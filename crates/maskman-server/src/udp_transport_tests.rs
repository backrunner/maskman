use std::{net::SocketAddr, sync::Arc, time::Duration};

use bytes::Bytes;
use http::{Method, Request, StatusCode, Version};
use quinn::Endpoint;

use super::{
    h3_client, send_connect_udp, test_client_config, test_limits, test_server_config,
    RequestSender, TransportContext, TransportMode, TransportServer,
};

struct ProxyClient {
    endpoint: Endpoint,
    _driver: super::ClientDriver,
    sender: RequestSender,
    server_task: tokio::task::JoinHandle<Result<(), crate::TransportError>>,
}

#[tokio::test]
async fn disabled_connect_udp_returns_proxy_configuration_error() {
    let config = maskman_config::compile_document(
        &maskman_config::ConfigDocument::default(),
        std::path::Path::new("."),
    )
    .unwrap_or_else(|error| panic!("compile disabled UDP config: {error}"));
    let mut client = start_proxy(config).await;
    let mut stream =
        send_connect_udp(&mut client.sender, "/.well-known/masque/udp/192.0.2.1/53/").await;
    let response = stream
        .recv_response()
        .await
        .unwrap_or_else(|error| panic!("receive disabled response: {error}"));

    assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
    assert_eq!(
        response.headers().get("proxy-status").and_then(|value| value.to_str().ok()),
        Some("maskman; error=proxy_configuration_error")
    );
    client.endpoint.close(0u32.into(), b"test complete");
    client.server_task.abort();
}

#[tokio::test]
async fn udp_idle_timeout_closes_the_request_stream() {
    let target = tokio::net::UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .unwrap_or_else(|error| panic!("bind UDP target: {error}"));
    let mut config =
        udp_config(target.local_addr().unwrap_or_else(|error| panic!("target: {error}")));
    config.udp.idle_timeout = Duration::from_millis(25);
    let mut client = start_proxy(config).await;
    let path = format!(
        "/.well-known/masque/udp/127.0.0.1/{}/",
        target.local_addr().unwrap_or_else(|error| panic!("target: {error}")).port()
    );
    let mut stream = send_authenticated(&mut client.sender, &path).await;
    let response = stream
        .recv_response()
        .await
        .unwrap_or_else(|error| panic!("receive UDP response: {error}"));
    assert_eq!(response.status(), StatusCode::OK);

    let end = tokio::time::timeout(Duration::from_secs(1), stream.recv_data())
        .await
        .unwrap_or_else(|error| panic!("wait for idle stream close: {error}"))
        .unwrap_or_else(|error| panic!("receive idle stream close: {error}"));
    assert!(end.is_none());
    client.endpoint.close(0u32.into(), b"test complete");
    client.server_task.abort();
}

#[tokio::test]
async fn oversized_udp_capsule_aborts_the_request_stream() {
    let target = tokio::net::UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .unwrap_or_else(|error| panic!("bind UDP target: {error}"));
    let address = target.local_addr().unwrap_or_else(|error| panic!("target: {error}"));
    let mut client = start_proxy(udp_config(address)).await;
    let path = format!("/.well-known/masque/udp/127.0.0.1/{}/", address.port());
    let mut stream = send_authenticated(&mut client.sender, &path).await;
    let response = stream
        .recv_response()
        .await
        .unwrap_or_else(|error| panic!("receive UDP response: {error}"));
    assert_eq!(response.status(), StatusCode::OK);

    let mut value = Vec::with_capacity(65_529);
    maskman_protocol::capsule::encode_datagram(0, &vec![0; 65_528], &mut value)
        .unwrap_or_else(|error| panic!("encode oversized datagram: {error}"));
    let capsule = maskman_protocol::capsule::Capsule {
        capsule_type: maskman_protocol::capsule::DATAGRAM_CAPSULE,
        value,
    };
    let mut encoded = Vec::new();
    maskman_protocol::capsule::encode(&capsule, &mut encoded)
        .unwrap_or_else(|error| panic!("encode DATAGRAM capsule: {error}"));
    stream
        .send_data(Bytes::from(encoded))
        .await
        .unwrap_or_else(|error| panic!("send oversized DATAGRAM capsule: {error}"));

    let result = tokio::time::timeout(Duration::from_secs(2), stream.recv_data())
        .await
        .unwrap_or_else(|error| panic!("wait for stream reset: {error}"));
    assert!(result.is_err(), "oversized UDP payload must reset the request stream");
    client.endpoint.close(0u32.into(), b"test complete");
    client.server_task.abort();
}

async fn start_proxy(config: maskman_config::CompiledConfig) -> ProxyClient {
    let context = Arc::new(TransportContext::new(Arc::new(config)));
    let (server_config, certificate) = test_server_config();
    let server = TransportServer::bind_with_context(
        SocketAddr::from(([127, 0, 0, 1], 0)),
        server_config,
        test_limits(),
        TransportMode::RejectUntilAuthentication,
        context,
    )
    .unwrap_or_else(|error| panic!("bind proxy server: {error}"));
    let address = server.local_addr().unwrap_or_else(|error| panic!("server address: {error}"));
    let server_task = tokio::spawn(server.run());
    let mut endpoint = Endpoint::client(SocketAddr::from(([127, 0, 0, 1], 0)))
        .unwrap_or_else(|error| panic!("bind client: {error}"));
    endpoint.set_default_client_config(test_client_config(certificate));
    let connection = endpoint
        .connect(address, "localhost")
        .unwrap_or_else(|error| panic!("connect client: {error}"))
        .await
        .unwrap_or_else(|error| panic!("complete client connection: {error}"));
    let (driver, sender) = h3_client(connection).await;
    ProxyClient { endpoint, _driver: driver, sender, server_task }
}

async fn send_authenticated(sender: &mut RequestSender, path: &str) -> super::RequestStream {
    let mut request = Request::builder()
        .method(Method::CONNECT)
        .uri(format!("https://proxy.example{path}"))
        .version(Version::HTTP_3)
        .header("capsule-protocol", "?1")
        .header("authorization", "Bearer mm_token_secret")
        .body(())
        .unwrap_or_else(|error| panic!("build authenticated request: {error}"));
    request.extensions_mut().insert(h3::ext::Protocol::CONNECT_UDP);
    sender
        .send_request(request)
        .await
        .unwrap_or_else(|error| panic!("send authenticated request: {error}"))
}

fn udp_config(target: SocketAddr) -> maskman_config::CompiledConfig {
    let mut document = maskman_config::ConfigDocument::default();
    document.proxy.udp.enabled = true;
    document.auth.principals.push(maskman_config::model::PrincipalConfig {
        id: "client".into(),
        roles: vec!["udp".into()],
        certificate_sha256: Vec::new(),
    });
    document.auth.bearer_tokens.push(maskman_config::model::BearerTokenConfig {
        id: "token".into(),
        principal: "client".into(),
        secret_sha256: super::hex_sha256("secret"),
        expires_at: None,
        enabled: true,
    });
    document.policy.roles.push(maskman_config::model::RoleConfig {
        name: "udp".into(),
        capabilities: vec!["connect-udp".into()],
        allow_destinations: vec![format!("{}/32", target.ip())],
        deny_destinations: Vec::new(),
        deny_private: false,
        allowed_ip_protocols: Vec::new(),
        limits: Default::default(),
    });
    maskman_config::compile_document(&document, std::path::Path::new("."))
        .unwrap_or_else(|error| panic!("compile UDP config: {error}"))
}
