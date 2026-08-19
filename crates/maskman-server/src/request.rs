use std::sync::Arc;

use bytes::{Buf, Bytes};
use h3::ext::Protocol;
use h3_quinn::Connection;
use http::{header::HeaderValue, HeaderMap, Method, Request, StatusCode, Version};
use maskman_config::CompiledConfig;
use maskman_protocol::{
    capsule::{self, CapsuleLimits, DecodeEvent, Decoder},
    connect::parse_udp_path,
};
use thiserror::Error;
use tokio::sync::mpsc;

use crate::{
    auth::{AuthError, Authenticator},
    policy::{self, PolicyError},
    proxy::{resolver, udp},
    session::{QuotaState, SessionRegistry},
};

const MAX_CAPSULE_VALUE_BYTES: usize = 65_535;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestMode {
    RejectUntilAuthentication,
    EchoDatagrams,
}

#[derive(Clone)]
pub struct RequestContext {
    pub config: Arc<CompiledConfig>,
    pub registry: Arc<SessionRegistry>,
    pub quotas: Arc<QuotaState>,
    pub connection: quinn::Connection,
    pub peer_certificate_sha256: Option<[u8; 32]>,
}

#[derive(Debug, Error)]
pub enum RequestError {
    #[error("failed to resolve HTTP/3 request: {0}")]
    Resolve(#[from] h3::error::StreamError),
    #[error("failed to send HTTP/3 response: {0}")]
    Response(#[source] h3::error::StreamError),
    #[error("failed while draining HTTP/3 request: {0}")]
    Drain(#[source] h3::error::StreamError),
    #[error("invalid capsule on HTTP/3 request stream: {0}")]
    Capsule(#[from] capsule::DecoderError),
    #[error("failed to encode capsule on HTTP/3 request stream: {0}")]
    CapsuleEncode(#[from] maskman_protocol::varint::VarIntError),
    #[error("failed to create connected UDP socket: {0}")]
    Udp(#[source] std::io::Error),
}

pub async fn handle(
    resolver: h3::server::RequestResolver<Connection, Bytes>,
    mode: RequestMode,
    context: Option<RequestContext>,
) -> Result<(), RequestError> {
    let (request, stream) = resolver.resolve_request().await?;
    if context.is_none() && mode == RequestMode::RejectUntilAuthentication {
        return reject(stream, StatusCode::SERVICE_UNAVAILABLE, false).await;
    }
    if let Some(context) = context {
        return handle_proxy(request, stream, context).await;
    }
    handle_echo(request, stream).await
}

async fn handle_echo(
    request: Request<()>,
    mut stream: h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
) -> Result<(), RequestError> {
    let valid_connect_udp = is_connect_udp(&request);
    let status = if valid_connect_udp { StatusCode::OK } else { StatusCode::BAD_REQUEST };
    let response = response(status, valid_connect_udp);
    stream.send_response(response).await.map_err(RequestError::Response)?;
    if !valid_connect_udp {
        return stream.finish().await.map_err(RequestError::Response);
    }
    let limits = CapsuleLimits::uniform(MAX_CAPSULE_VALUE_BYTES);
    let mut decoder = Decoder::new(limits);
    while let Some(mut data) = stream.recv_data().await.map_err(RequestError::Drain)? {
        while data.has_remaining() {
            let chunk = data.chunk();
            let chunk_length = chunk.len();
            let capsules = decoder.push(chunk)?;
            data.advance(chunk_length);
            for event in capsules {
                let DecodeEvent::Capsule(capsule) = event else { continue };
                if capsule.capsule_type != capsule::DATAGRAM_CAPSULE {
                    continue;
                }
                let mut encoded = Vec::with_capacity(capsule.value.len() + 16);
                capsule::encode(&capsule, &mut encoded)?;
                stream.send_data(Bytes::from(encoded)).await.map_err(RequestError::Response)?;
            }
        }
    }
    decoder.finish()?;
    stream.finish().await.map_err(RequestError::Response)
}

async fn handle_proxy(
    request: Request<()>,
    mut stream: h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    context: RequestContext,
) -> Result<(), RequestError> {
    if !is_connect_udp(&request) {
        return reject(stream, StatusCode::BAD_REQUEST, false).await;
    }
    let target = match parse_udp_path(request.uri().path(), &context.config.base_path) {
        Ok(target) => target,
        Err(_) => return reject(stream, StatusCode::BAD_REQUEST, false).await,
    };
    let authenticator = Authenticator::new(context.config.clone());
    let principal =
        match authenticator.authenticate(request.headers(), context.peer_certificate_sha256) {
            Ok(principal) => principal,
            Err(error) => return reject_auth(stream, error).await,
        };
    let policy = policy::compile(context.config.clone(), &principal);
    if let Err(error) = policy.authorize_capability("connect-udp") {
        return reject_policy(stream, error).await;
    }
    let target = match resolver::resolve_udp_target(
        &target,
        &policy,
        context.config.udp.prefer_ipv6,
    )
    .await
    {
        Ok(target) => target,
        Err(error) => return reject_resolver(stream, error).await,
    };
    let Some(quota) = QuotaState::acquire(
        context.quotas.clone(),
        &principal.id,
        policy.limits.active_tunnels,
        policy.limits.new_tunnels_per_minute,
    ) else {
        return reject(stream, StatusCode::TOO_MANY_REQUESTS, false).await;
    };
    let stream_id = stream.id().into_inner();
    let session = udp::start(
        target,
        stream_id,
        context.connection.clone(),
        context.config.udp.max_payload_bytes as usize,
        context.config.udp.idle_timeout,
        policy.limits.clone(),
    )
    .await
    .map_err(RequestError::Udp)?;
    let udp::UdpSession { handle, mut egress, task } = session;
    context.registry.insert(stream_id, handle.clone());
    stream.send_response(response(StatusCode::OK, true)).await.map_err(RequestError::Response)?;
    let result = drive_proxy_stream(
        &mut stream,
        &handle,
        &mut egress,
        context.config.udp.max_payload_bytes as usize,
    )
    .await;
    context.registry.remove(stream_id);
    task.abort();
    drop(quota);
    result
}

async fn drive_proxy_stream(
    stream: &mut h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    session: &udp::UdpSessionHandle,
    egress: &mut mpsc::Receiver<Bytes>,
    max_payload: usize,
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
                            forward_capsule(&value, session, max_payload)?;
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
            Some(payload) = egress.recv() => {
                let value = capsule::Capsule { capsule_type: capsule::DATAGRAM_CAPSULE, value: payload.to_vec() };
                let mut encoded = Vec::with_capacity(payload.len() + 16);
                capsule::encode(&value, &mut encoded)?;
                stream.send_data(Bytes::from(encoded)).await.map_err(RequestError::Response)?;
            },
            else => return Ok(()),
        }
    }
}

fn forward_capsule(
    capsule: &capsule::Capsule,
    session: &udp::UdpSessionHandle,
    max_payload: usize,
) -> Result<(), RequestError> {
    if capsule.capsule_type != capsule::DATAGRAM_CAPSULE {
        return Ok(());
    }
    let datagram =
        capsule::decode_datagram(&capsule.value).map_err(|_| capsule::DecoderError::Truncated)?;
    if datagram.context_id != 0 || datagram.payload.len() > max_payload {
        return Ok(());
    }
    let _ = session.try_send(Bytes::copy_from_slice(datagram.payload));
    Ok(())
}

fn is_connect_udp(request: &Request<()>) -> bool {
    request.method() == Method::CONNECT
        && request.version() == Version::HTTP_3
        && request.extensions().get::<Protocol>() == Some(&Protocol::CONNECT_UDP)
        && request.uri().scheme_str() == Some("https")
        && request.uri().authority().is_some()
        && request.uri().path().starts_with('/')
        && request.uri().path().len() > 1
        && request.headers().get("capsule-protocol") == Some(&HeaderValue::from_static("?1"))
}

async fn reject(
    mut stream: h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    status: StatusCode,
    capsule_protocol: bool,
) -> Result<(), RequestError> {
    stream
        .send_response(response(status, capsule_protocol))
        .await
        .map_err(RequestError::Response)?;
    stream.finish().await.map_err(RequestError::Response)
}

async fn reject_auth(
    mut stream: h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    _error: AuthError,
) -> Result<(), RequestError> {
    let mut response = response(StatusCode::UNAUTHORIZED, false);
    response
        .headers_mut()
        .insert("www-authenticate", HeaderValue::from_static("Bearer realm=\"maskman\""));
    stream.send_response(response).await.map_err(RequestError::Response)?;
    stream.finish().await.map_err(RequestError::Response)
}

async fn reject_policy(
    stream: h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    _error: PolicyError,
) -> Result<(), RequestError> {
    reject(stream, StatusCode::FORBIDDEN, false).await
}

async fn reject_resolver(
    stream: h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    _error: resolver::ResolveError,
) -> Result<(), RequestError> {
    reject(stream, StatusCode::BAD_GATEWAY, false).await
}

fn response(status: StatusCode, capsule_protocol: bool) -> http::Response<()> {
    let mut headers = HeaderMap::new();
    if capsule_protocol {
        headers.insert("capsule-protocol", HeaderValue::from_static("?1"));
    }
    let mut response = http::Response::new(());
    *response.status_mut() = status;
    *response.version_mut() = Version::HTTP_3;
    *response.headers_mut() = headers;
    response
}
