use std::sync::Arc;

use bytes::{Buf, Bytes};
use h3::ext::Protocol;
use http::{header::HeaderValue, Method, Request, StatusCode, Version};
use maskman_protocol::{
    capsule::{self, Capsule, CapsuleLimits, DecodeEvent, Decoder},
    connect::{parse_ip_path, IpProtocolScope},
};
use tokio::sync::mpsc;

use crate::{
    auth::Authenticator,
    datagram, policy,
    proxy::ip,
    request::{self, RequestContext, RequestError},
    session::QuotaState,
};

const MAX_CAPSULE_VALUE_BYTES: usize = 65_535;

pub async fn handle(
    request: Request<()>,
    mut stream: h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    context: RequestContext,
) -> Result<(), RequestError> {
    if !is_connect_ip(&request) {
        return request::reject(stream, StatusCode::BAD_REQUEST, false).await;
    }
    if !context.config.ip.enabled {
        return request::reject(stream, StatusCode::NOT_IMPLEMENTED, false).await;
    }
    let scope = match parse_ip_path(request.uri().path(), &context.config.base_path) {
        Ok(scope) => scope,
        Err(_) => return request::reject(stream, StatusCode::BAD_REQUEST, false).await,
    };
    let authenticator = Authenticator::new(context.config.clone());
    let principal =
        match authenticator.authenticate(request.headers(), context.peer_certificate_sha256) {
            Ok(principal) => principal,
            Err(error) => return request::reject_auth(stream, error).await,
        };
    let policy = policy::compile(context.config.clone(), &principal);
    if let Err(error) = policy.authorize_capability("connect-ip") {
        return request::reject_policy(stream, error).await;
    }
    if let IpProtocolScope::Number(protocol) = scope.protocol {
        if policy.authorize_ip_protocol(protocol).is_err() {
            return request::reject(stream, StatusCode::FORBIDDEN, false).await;
        }
    }
    let Some(quota) = QuotaState::acquire(
        context.quotas.clone(),
        &principal.id,
        policy.limits.active_tunnels,
        policy.limits.new_tunnels_per_minute,
    ) else {
        return request::reject(stream, StatusCode::TOO_MANY_REQUESTS, false).await;
    };
    let policy = Arc::new(policy);
    let Some(mut session) = ip::IpSession::start(
        scope,
        &context.address_pools,
        policy,
        context.config.ip.mtu as usize,
        context.tun_sender.clone(),
    ) else {
        drop(quota);
        return request::reject(stream, StatusCode::SERVICE_UNAVAILABLE, false).await;
    };
    let stream_id = stream.id().into_inner();
    if !context.ip_registry.insert(context.connection_id, stream_id, session.handle.clone()) {
        drop(quota);
        return request::reject(stream, StatusCode::SERVICE_UNAVAILABLE, false).await;
    }
    let result = async {
        let assigned = session.handle.assignment_capsule([0])?;
        stream
            .send_response(request::response(StatusCode::OK, true))
            .await
            .map_err(RequestError::Response)?;
        send_capsule(&mut stream, capsule::ADDRESS_ASSIGN_CAPSULE, assigned).await?;
        if let Some(routes) = configured_route_capsule(&context.config.ip.advertise_routes) {
            send_capsule(&mut stream, capsule::ROUTE_ADVERTISEMENT_CAPSULE, routes).await?;
        }
        drive_stream(
            &mut stream,
            &session.handle,
            &mut session.to_client,
            context.connection.clone(),
            stream_id,
        )
        .await
    }
    .await;
    context.ip_registry.remove(context.connection_id, stream_id);
    drop(session);
    drop(quota);
    result
}

async fn drive_stream(
    stream: &mut h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    session: &ip::IpSessionHandle,
    to_client: &mut mpsc::Receiver<Bytes>,
    connection: quinn::Connection,
    stream_id: u64,
) -> Result<(), RequestError> {
    let mut decoder = Decoder::new(CapsuleLimits::uniform(MAX_CAPSULE_VALUE_BYTES));
    loop {
        tokio::select! {
            data = stream.recv_data() => match data.map_err(RequestError::Drain)? {
                Some(mut data) => while data.has_remaining() {
                    let chunk = data.chunk();
                    let length = chunk.len();
                    for event in decoder.push(chunk)? {
                        if let DecodeEvent::Capsule(value) = event {
                            handle_capsule(value, session, stream).await?;
                        }
                    }
                    data.advance(length);
                },
                None => {
                    decoder.finish()?;
                    stream.finish().await.map_err(RequestError::Response)?;
                    return Ok(());
                }
            },
            Some(payload) = to_client.recv() => {
                send_ip_packet(stream, &connection, stream_id, payload).await?;
            },
            else => return Ok(()),
        }
    }
}

async fn handle_capsule(
    capsule: Capsule,
    session: &ip::IpSessionHandle,
    stream: &mut h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
) -> Result<(), RequestError> {
    match capsule.capsule_type {
        capsule::DATAGRAM_CAPSULE => {
            if let Ok(datagram) = capsule::decode_datagram(&capsule.value) {
                if datagram.context_id == 0 {
                    let _ = session.try_send(Bytes::copy_from_slice(datagram.payload));
                }
            }
        }
        capsule::ADDRESS_REQUEST_CAPSULE => {
            let requests = capsule::decode_address_request(&capsule.value)?;
            let assignment =
                session.assignment_capsule(requests.iter().map(|request| request.request_id))?;
            send_capsule(stream, capsule::ADDRESS_ASSIGN_CAPSULE, assignment).await?;
        }
        capsule::ROUTE_ADVERTISEMENT_CAPSULE => {
            session.replace_routes(&capsule.value)?;
        }
        capsule::ADDRESS_ASSIGN_CAPSULE => {}
        _ => {}
    }
    Ok(())
}

async fn send_ip_packet(
    stream: &mut h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    connection: &quinn::Connection,
    stream_id: u64,
    payload: Bytes,
) -> Result<(), RequestError> {
    let mut http_payload = Vec::with_capacity(payload.len() + 2);
    capsule::encode_datagram(0, &payload, &mut http_payload)?;
    let encoded = datagram::encode(stream_id, Bytes::from(http_payload.clone()))
        .map_err(|error| RequestError::Datagram(error.to_string()))?;
    match connection.send_datagram(encoded) {
        Ok(()) | Err(quinn::SendDatagramError::TooLarge) => Ok(()),
        Err(quinn::SendDatagramError::UnsupportedByPeer | quinn::SendDatagramError::Disabled) => {
            send_capsule(stream, capsule::DATAGRAM_CAPSULE, http_payload).await
        }
        Err(quinn::SendDatagramError::ConnectionLost(error)) => {
            Err(RequestError::Datagram(error.to_string()))
        }
    }
}

async fn send_capsule(
    stream: &mut h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    capsule_type: u64,
    value: Vec<u8>,
) -> Result<(), RequestError> {
    let mut encoded = Vec::with_capacity(value.len() + 16);
    capsule::encode(&Capsule { capsule_type, value }, &mut encoded)?;
    stream.send_data(Bytes::from(encoded)).await.map_err(RequestError::Response)
}

fn configured_route_capsule(routes: &[ipnet::IpNet]) -> Option<Vec<u8>> {
    if routes.is_empty() {
        return None;
    }
    let ranges = routes
        .iter()
        .map(|route| maskman_protocol::capsule::AddressRange {
            start: route.network(),
            end: route.broadcast(),
            protocol: 0,
        })
        .collect::<Vec<_>>();
    let advertisement = maskman_protocol::capsule::RouteAdvertisement::new(ranges).ok()?;
    let mut encoded = Vec::new();
    capsule::encode_route_advertisement(&advertisement, &mut encoded).ok()?;
    Some(encoded)
}

fn is_connect_ip(request: &Request<()>) -> bool {
    request.method() == Method::CONNECT
        && request.version() == Version::HTTP_3
        && request.extensions().get::<Protocol>() == Some(&Protocol::CONNECT_IP)
        && request.uri().scheme_str() == Some("https")
        && request.uri().authority().is_some()
        && request.uri().path().starts_with('/')
        && request.uri().path().len() > 1
        && request.headers().get("capsule-protocol") == Some(&HeaderValue::from_static("?1"))
}
