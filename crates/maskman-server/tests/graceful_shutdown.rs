use std::{net::SocketAddr, sync::Arc, time::Duration};

use bytes::Bytes;
use http::{Method, Request, StatusCode, Version};
use maskman_server::{TransportLimits, TransportMode, TransportServer};
use quinn::{ClientConfig, Endpoint};
use rcgen::generate_simple_self_signed;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};

#[tokio::test]
async fn shutdown_sends_an_h3_no_error_close() {
    let (server_config, certificate) = test_server_config();
    let server = TransportServer::bind(
        SocketAddr::from(([127, 0, 0, 1], 0)),
        server_config,
        test_limits(),
        TransportMode::RejectUntilAuthentication,
    )
    .unwrap_or_else(|error| panic!("bind test server: {error}"));
    let address =
        server.local_addr().unwrap_or_else(|error| panic!("read test server address: {error}"));
    let shutdown = server.shutdown_handle();
    let server_task = tokio::spawn(server.run());

    let mut endpoint = Endpoint::client(SocketAddr::from(([127, 0, 0, 1], 0)))
        .unwrap_or_else(|error| panic!("bind test client: {error}"));
    endpoint.set_default_client_config(test_client_config(certificate));
    let connection = endpoint
        .connect(address, "localhost")
        .unwrap_or_else(|error| panic!("start test connection: {error}"))
        .await
        .unwrap_or_else(|error| panic!("complete test connection: {error}"));
    let mut builder = h3::client::builder();
    builder.enable_extended_connect(true).enable_datagram(true);
    let (mut driver, mut sender) = builder
        .build::<_, _, Bytes>(h3_quinn::Connection::new(connection))
        .await
        .unwrap_or_else(|error| panic!("build HTTP/3 client: {error}"));

    let mut stream = sender
        .send_request(connect_udp_request())
        .await
        .unwrap_or_else(|error| panic!("send CONNECT request: {error}"));
    stream.finish().await.unwrap_or_else(|error| panic!("finish CONNECT request: {error}"));
    let response =
        stream.recv_response().await.unwrap_or_else(|error| panic!("receive rejection: {error}"));
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    drop(stream);

    let close_task = tokio::spawn(async move { driver.wait_idle().await });
    shutdown.shutdown();
    let close = tokio::time::timeout(Duration::from_secs(2), close_task)
        .await
        .unwrap_or_else(|error| panic!("wait for graceful close: {error}"))
        .unwrap_or_else(|error| panic!("join client driver: {error}"));
    assert!(close.is_h3_no_error(), "unexpected HTTP/3 close: {close}");
    tokio::time::timeout(Duration::from_secs(2), server_task)
        .await
        .unwrap_or_else(|error| panic!("wait for server shutdown: {error}"))
        .unwrap_or_else(|error| panic!("join server task: {error}"))
        .unwrap_or_else(|error| panic!("run server: {error}"));
}

fn connect_udp_request() -> Request<()> {
    let mut request = Request::builder()
        .method(Method::CONNECT)
        .uri("https://proxy.example/.well-known/masque/udp/example.com/443/")
        .version(Version::HTTP_3)
        .header("capsule-protocol", "?1")
        .body(())
        .unwrap_or_else(|error| panic!("build CONNECT request: {error}"));
    request.extensions_mut().insert(h3::ext::Protocol::CONNECT_UDP);
    request
}

fn test_server_config() -> (quinn::ServerConfig, CertificateDer<'static>) {
    let certificate = generate_simple_self_signed(vec!["localhost".to_owned()])
        .unwrap_or_else(|error| panic!("generate test certificate: {error}"));
    let certificate_der = CertificateDer::from(certificate.cert.der().to_vec());
    let private_key = PrivatePkcs8KeyDer::from(certificate.key_pair.serialize_der());
    let mut crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![certificate_der.clone()], private_key.into())
        .unwrap_or_else(|error| panic!("build test TLS config: {error}"));
    crypto.alpn_protocols = vec![b"h3".to_vec()];
    let quic_crypto = quinn::crypto::rustls::QuicServerConfig::try_from(crypto)
        .unwrap_or_else(|error| panic!("build test QUIC config: {error}"));
    (quinn::ServerConfig::with_crypto(Arc::new(quic_crypto)), certificate_der)
}

fn test_client_config(certificate: CertificateDer<'static>) -> ClientConfig {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(certificate).unwrap_or_else(|error| panic!("add test root: {error}"));
    let mut crypto =
        rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
    crypto.alpn_protocols = vec![b"h3".to_vec()];
    let quic_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
        .unwrap_or_else(|error| panic!("build test client QUIC config: {error}"));
    ClientConfig::new(Arc::new(quic_crypto))
}

fn test_limits() -> TransportLimits {
    TransportLimits {
        max_connections: 8,
        max_requests_per_connection: 8,
        max_header_bytes: 16_384,
        idle_timeout: Duration::from_secs(5),
        drain_timeout: Duration::from_secs(1),
    }
}
