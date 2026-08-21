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
    proxy::{
        address_pool::AddressPoolSet,
        ip::{IpControlError, IpSessionRegistry},
        resolver, udp,
    },
    session::{QuotaState, SessionRegistry},
    stats::{ActivityKind, RuntimeStats},
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
    pub ip_registry: Arc<IpSessionRegistry>,
    pub address_pools: Arc<AddressPoolSet>,
    pub tun_sender: mpsc::Sender<Bytes>,
    pub connection: quinn::Connection,
    pub connection_id: u64,
    pub peer_certificate_sha256: Option<[u8; 32]>,
    pub(crate) stats: Arc<RuntimeStats>,
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
    #[error("invalid address capsule: {0}")]
    Address(#[from] capsule::AddressError),
    #[error("invalid HTTP datagram payload: {0}")]
    DatagramPayload(#[from] capsule::DatagramError),
    #[error("invalid CONNECT-IP control capsule: {0}")]
    IpControl(#[from] IpControlError),
    #[error("failed to send QUIC datagram: {0}")]
    Datagram(String),
    #[error("QUIC datagram is too small for the configured IP tunnel MTU")]
    DatagramTooSmall,
    #[error("QUIC datagram cannot carry the IP packet")]
    DatagramTooLarge,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProxyError {
    ConnectionLimitReached,
    DestinationIpProhibited,
    DestinationUnavailable,
    DnsError,
    HttpRequestDenied,
    HttpRequestError,
    ProxyConfigurationError,
    ProxyInternalError,
}

impl ProxyError {
    fn field_value(self) -> &'static str {
        match self {
            Self::ConnectionLimitReached => "maskman; error=connection_limit_reached",
            Self::DestinationIpProhibited => "maskman; error=destination_ip_prohibited",
            Self::DestinationUnavailable => "maskman; error=destination_unavailable",
            Self::DnsError => "maskman; error=dns_error",
            Self::HttpRequestDenied => "maskman; error=http_request_denied",
            Self::HttpRequestError => "maskman; error=http_request_error",
            Self::ProxyConfigurationError => "maskman; error=proxy_configuration_error",
            Self::ProxyInternalError => "maskman; error=proxy_internal_error",
        }
    }
}

pub async fn handle(
    resolver: h3::server::RequestResolver<Connection, Bytes>,
    mode: RequestMode,
    context: Option<RequestContext>,
) -> Result<(), RequestError> {
    let (request, stream) = resolver.resolve_request().await?;
    if context.is_none() && mode == RequestMode::RejectUntilAuthentication {
        return reject(
            stream,
            StatusCode::SERVICE_UNAVAILABLE,
            ProxyError::ProxyConfigurationError,
        )
        .await;
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
    stream: h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    context: RequestContext,
) -> Result<(), RequestError> {
    if is_connect_udp(&request) {
        return handle_udp(request, stream, context).await;
    }
    crate::request_ip::handle(request, stream, context).await
}

async fn handle_udp(
    request: Request<()>,
    mut stream: h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    context: RequestContext,
) -> Result<(), RequestError> {
    if !context.config.udp.enabled {
        return reject(stream, StatusCode::NOT_IMPLEMENTED, ProxyError::ProxyConfigurationError)
            .await;
    }
    let target = match parse_udp_path(request.uri().path(), &context.config.base_path) {
        Ok(target) => target,
        Err(_) => {
            return reject(stream, StatusCode::BAD_REQUEST, ProxyError::HttpRequestError).await;
        }
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
        return reject(stream, StatusCode::TOO_MANY_REQUESTS, ProxyError::ConnectionLimitReached)
            .await;
    };
    let stream_id = stream.id().into_inner();
    let session = match udp::start_with_stats(
        target,
        stream_id,
        context.connection.clone(),
        context.config.udp.max_payload_bytes as usize,
        context.config.udp.idle_timeout,
        policy.limits.clone(),
        Some(context.stats.clone()),
    )
    .await
    {
        Ok(session) => session,
        Err(_) => {
            drop(quota);
            return reject(stream, StatusCode::BAD_GATEWAY, ProxyError::DestinationUnavailable)
                .await;
        }
    };
    let udp::UdpSession { handle, mut egress, mut violations, task } = session;
    let _activity = context.stats.begin(ActivityKind::UdpSession);
    context.registry.insert(stream_id, handle.clone());
    stream.send_response(response(StatusCode::OK, true)).await.map_err(RequestError::Response)?;
    let result = drive_proxy_stream(
        &mut stream,
        &handle,
        &mut egress,
        &mut violations,
        context.config.udp.max_payload_bytes as usize,
        &context.stats,
    )
    .await;
    if result.is_err() {
        stream.stop_stream(h3::error::Code::H3_MESSAGE_ERROR);
    }
    context.registry.remove(stream_id);
    task.abort();
    drop(quota);
    result
}

async fn drive_proxy_stream(
    stream: &mut h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    session: &udp::UdpSessionHandle,
    egress: &mut mpsc::Receiver<Bytes>,
    violations: &mut mpsc::Receiver<usize>,
    max_payload: usize,
    stats: &RuntimeStats,
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
                            let forwarded = forward_capsule(&value, session, max_payload)?;
                            if value.capsule_type == capsule::DATAGRAM_CAPSULE {
                                stats.packet_result(forwarded);
                            }
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
            payload = egress.recv() => match payload {
                Some(payload) => {
                    let value = capsule::Capsule { capsule_type: capsule::DATAGRAM_CAPSULE, value: payload.to_vec() };
                    let mut encoded = Vec::with_capacity(payload.len() + 16);
                    capsule::encode(&value, &mut encoded)?;
                    stream.send_data(Bytes::from(encoded)).await.map_err(RequestError::Response)?;
                }
                None => {
                    stream.stop_sending(h3::error::Code::H3_NO_ERROR);
                    stream.finish().await.map_err(RequestError::Response)?;
                    return Ok(());
                }
            },
            Some(length) = violations.recv() => return Err(RequestError::DatagramPayload(
                capsule::DatagramError::UdpPayloadTooLarge { length }
            )),
            else => return Ok(()),
        }
    }
}

fn forward_capsule(
    capsule: &capsule::Capsule,
    session: &udp::UdpSessionHandle,
    max_payload: usize,
) -> Result<bool, RequestError> {
    if capsule.capsule_type != capsule::DATAGRAM_CAPSULE {
        return Ok(false);
    }
    let datagram =
        capsule::decode_datagram(&capsule.value).map_err(|_| capsule::DecoderError::Truncated)?;
    capsule::validate_udp_payload(&datagram)?;
    if datagram.context_id != 0 || datagram.payload.len() > max_payload {
        return Ok(false);
    }
    Ok(session.try_send(Bytes::copy_from_slice(datagram.payload)))
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

pub(crate) async fn reject(
    mut stream: h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    status: StatusCode,
    proxy_error: ProxyError,
) -> Result<(), RequestError> {
    stream
        .send_response(error_response(status, proxy_error))
        .await
        .map_err(RequestError::Response)?;
    stream.finish().await.map_err(RequestError::Response)
}

pub(crate) async fn reject_auth(
    mut stream: h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    _error: AuthError,
) -> Result<(), RequestError> {
    let mut response = error_response(StatusCode::UNAUTHORIZED, ProxyError::HttpRequestDenied);
    response
        .headers_mut()
        .insert("www-authenticate", HeaderValue::from_static("Bearer realm=\"maskman\""));
    stream.send_response(response).await.map_err(RequestError::Response)?;
    stream.finish().await.map_err(RequestError::Response)
}

pub(crate) async fn reject_policy(
    stream: h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    error: PolicyError,
) -> Result<(), RequestError> {
    let proxy_error = match error {
        PolicyError::Capability => ProxyError::HttpRequestDenied,
        PolicyError::Destination => ProxyError::DestinationIpProhibited,
    };
    reject(stream, StatusCode::FORBIDDEN, proxy_error).await
}

pub(crate) async fn reject_resolver(
    stream: h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    error: resolver::ResolveError,
) -> Result<(), RequestError> {
    let (status, proxy_error) = match error {
        resolver::ResolveError::Dns => (StatusCode::BAD_GATEWAY, ProxyError::DnsError),
        resolver::ResolveError::Policy => {
            (StatusCode::FORBIDDEN, ProxyError::DestinationIpProhibited)
        }
    };
    reject(stream, status, proxy_error).await
}

pub(crate) fn response(status: StatusCode, capsule_protocol: bool) -> http::Response<()> {
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

fn error_response(status: StatusCode, proxy_error: ProxyError) -> http::Response<()> {
    let mut response = response(status, false);
    response
        .headers_mut()
        .insert("proxy-status", HeaderValue::from_static(proxy_error.field_value()));
    response
}

#[cfg(test)]
mod tests {
    use http::StatusCode;

    use super::{error_response, ProxyError};

    #[test]
    fn proxy_status_uses_registered_rfc_9209_error_tokens() {
        let response = error_response(StatusCode::FORBIDDEN, ProxyError::DestinationIpProhibited);
        assert_eq!(
            response.headers().get("proxy-status").and_then(|value| value.to_str().ok()),
            Some("maskman; error=destination_ip_prohibited")
        );
        assert!(response.headers().get("capsule-protocol").is_none());
    }
}
