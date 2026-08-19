use bytes::{Buf, Bytes};
use h3::ext::Protocol;
use h3_quinn::Connection;
use http::{header::HeaderValue, HeaderMap, Method, Request, StatusCode, Version};
use thiserror::Error;

const MAX_SPIKE_CAPSULE_VALUE_BYTES: usize = 65_535;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestMode {
    RejectUntilAuthentication,
    EchoDatagrams,
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
    Capsule(#[from] maskman_protocol::capsule::DecoderError),
    #[error("failed to encode capsule on HTTP/3 request stream: {0}")]
    CapsuleEncode(#[from] maskman_protocol::varint::VarIntError),
}

pub async fn handle(
    resolver: h3::server::RequestResolver<Connection, Bytes>,
    mode: RequestMode,
) -> Result<(), RequestError> {
    let (request, mut stream) = resolver.resolve_request().await?;
    let valid_connect_udp = is_connect_udp(&request);
    let status = if !valid_connect_udp {
        StatusCode::BAD_REQUEST
    } else if mode == RequestMode::RejectUntilAuthentication {
        StatusCode::SERVICE_UNAVAILABLE
    } else {
        StatusCode::OK
    };
    let response = response(status, valid_connect_udp && status == StatusCode::OK);
    stream.send_response(response).await.map_err(RequestError::Response)?;
    if status != StatusCode::OK {
        stream.finish().await.map_err(RequestError::Response)?;
        return Ok(());
    }
    let limits = maskman_protocol::capsule::CapsuleLimits::uniform(MAX_SPIKE_CAPSULE_VALUE_BYTES);
    let mut decoder = maskman_protocol::capsule::Decoder::new(limits);
    while let Some(mut data) = stream.recv_data().await.map_err(RequestError::Drain)? {
        while data.has_remaining() {
            let chunk = data.chunk();
            let chunk_length = chunk.len();
            let capsules = decoder.push(chunk)?;
            data.advance(chunk_length);
            for event in capsules {
                let maskman_protocol::capsule::DecodeEvent::Capsule(capsule) = event else {
                    continue;
                };
                if capsule.capsule_type != maskman_protocol::capsule::DATAGRAM_CAPSULE {
                    continue;
                }
                let mut encoded = Vec::with_capacity(capsule.value.len() + 16);
                maskman_protocol::capsule::encode(&capsule, &mut encoded)?;
                stream.send_data(Bytes::from(encoded)).await.map_err(RequestError::Response)?;
            }
        }
    }
    decoder.finish()?;
    stream.finish().await.map_err(RequestError::Response)
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
