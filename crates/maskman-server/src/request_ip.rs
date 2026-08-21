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
    proxy::{ip, resolver},
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
        return request::reject(
            stream,
            StatusCode::BAD_REQUEST,
            request::ProxyError::HttpRequestError,
        )
        .await;
    }
    if !context.config.ip.enabled {
        return request::reject(
            stream,
            StatusCode::NOT_IMPLEMENTED,
            request::ProxyError::ProxyConfigurationError,
        )
        .await;
    }
    let parsed_scope = match parse_ip_path(request.uri().path(), &context.config.base_path) {
        Ok(scope) => scope,
        Err(_) => {
            return request::reject(
                stream,
                StatusCode::BAD_REQUEST,
                request::ProxyError::HttpRequestError,
            )
            .await;
        }
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
    if let IpProtocolScope::Number(protocol) = parsed_scope.protocol {
        if policy.authorize_ip_protocol(protocol).is_err() {
            return request::reject(
                stream,
                StatusCode::FORBIDDEN,
                request::ProxyError::HttpRequestDenied,
            )
            .await;
        }
    }
    let scope = match resolver::resolve_ip_scope(parsed_scope, &policy).await {
        Ok(scope) => scope,
        Err(error) => return request::reject_resolver(stream, error).await,
    };
    let Some(quota) = QuotaState::acquire(
        context.quotas.clone(),
        &principal.id,
        policy.limits.active_tunnels,
        policy.limits.new_tunnels_per_minute,
    ) else {
        return request::reject(
            stream,
            StatusCode::TOO_MANY_REQUESTS,
            request::ProxyError::ConnectionLimitReached,
        )
        .await;
    };
    let policy = Arc::new(policy);
    let Some(mut session) = ip::IpSession::start_with_stats(
        scope,
        &context.address_pools,
        policy,
        context.config.ip.mtu as usize,
        context.tun_sender.clone(),
        Some(context.stats.clone()),
    ) else {
        drop(quota);
        return request::reject(
            stream,
            StatusCode::SERVICE_UNAVAILABLE,
            request::ProxyError::ConnectionLimitReached,
        )
        .await;
    };
    let stream_id = stream.id().into_inner();
    if !context.ip_registry.insert(context.connection_id, stream_id, session.handle.clone()) {
        drop(quota);
        return request::reject(
            stream,
            StatusCode::SERVICE_UNAVAILABLE,
            request::ProxyError::ProxyInternalError,
        )
        .await;
    }
    let _activity = context.stats.begin(crate::stats::ActivityKind::IpSession);
    let result = async {
        ensure_ipv6_capacity(&context.connection, stream_id, &session.handle)?;
        let assigned = session.handle.initial_assignment_capsule()?;
        stream
            .send_response(request::response(StatusCode::OK, true))
            .await
            .map_err(RequestError::Response)?;
        send_capsule(&mut stream, capsule::ADDRESS_ASSIGN_CAPSULE, assigned).await?;
        let routes = session
            .handle
            .route_advertisement(&context.config.ip.advertise_routes)
            .map_err(ip::IpControlError::from)?;
        if !routes.ranges().is_empty() {
            let mut encoded = Vec::new();
            capsule::encode_route_advertisement(&routes, &mut encoded)
                .map_err(ip::IpControlError::from)?;
            send_capsule(&mut stream, capsule::ROUTE_ADVERTISEMENT_CAPSULE, encoded).await?;
        }
        drive_stream(
            &mut stream,
            &session.handle,
            &mut session.to_client,
            &context.ip_registry,
            context.connection.clone(),
            context.connection_id,
            stream_id,
        )
        .await
    }
    .await;
    if result.is_err() {
        stream.stop_stream(h3::error::Code::H3_MESSAGE_ERROR);
    }
    context.ip_registry.remove(context.connection_id, stream_id);
    drop(session);
    drop(quota);
    result
}

async fn drive_stream(
    stream: &mut h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    session: &ip::IpSessionHandle,
    to_client: &mut mpsc::Receiver<Bytes>,
    registry: &ip::IpSessionRegistry,
    connection: quinn::Connection,
    connection_id: u64,
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
                            handle_capsule(
                                value,
                                session,
                                registry,
                                connection_id,
                                stream_id,
                                stream,
                            )
                            .await?;
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
    registry: &ip::IpSessionRegistry,
    connection_id: u64,
    stream_id: u64,
    stream: &mut h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
) -> Result<(), RequestError> {
    match capsule.capsule_type {
        capsule::DATAGRAM_CAPSULE => {
            let datagram = capsule::decode_datagram(&capsule.value)?;
            if datagram.context_id == 0 {
                let _ = session.try_send(Bytes::copy_from_slice(datagram.payload));
            }
        }
        capsule::ADDRESS_REQUEST_CAPSULE => {
            let requests = capsule::decode_address_request(&capsule.value)?;
            let assignment = session.address_request_capsule(&requests)?;
            send_capsule(stream, capsule::ADDRESS_ASSIGN_CAPSULE, assignment).await?;
        }
        capsule::ROUTE_ADVERTISEMENT_CAPSULE => {
            registry.replace_routes(connection_id, stream_id, &capsule.value)?;
        }
        capsule::ADDRESS_ASSIGN_CAPSULE => {
            session.replace_peer_assignments(&capsule.value)?;
        }
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
        Ok(()) => Ok(()),
        Err(quinn::SendDatagramError::TooLarge) => Err(RequestError::DatagramTooLarge),
        Err(quinn::SendDatagramError::UnsupportedByPeer | quinn::SendDatagramError::Disabled) => {
            send_capsule(stream, capsule::DATAGRAM_CAPSULE, http_payload).await
        }
        Err(quinn::SendDatagramError::ConnectionLost(error)) => {
            Err(RequestError::Datagram(error.to_string()))
        }
    }
}

fn ensure_ipv6_capacity(
    connection: &quinn::Connection,
    stream_id: u64,
    session: &ip::IpSessionHandle,
) -> Result<(), RequestError> {
    if !session.supports_ipv6() {
        return Ok(());
    }
    let Some(max_datagram_size) = connection.max_datagram_size() else {
        return Ok(());
    };
    let mut http_payload = Vec::with_capacity(1281);
    capsule::encode_datagram(0, &[0u8; 1_280], &mut http_payload)
        .map_err(RequestError::DatagramPayload)?;
    let encoded = datagram::encode(stream_id, Bytes::from(http_payload))
        .map_err(|error| RequestError::Datagram(error.to_string()))?;
    if encoded.len() > max_datagram_size {
        return Err(RequestError::DatagramTooSmall);
    }
    Ok(())
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
