use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Duration};

use bytes::{Buf, Bytes};
use http::{Method, Request, StatusCode, Version};
use quinn::{ClientConfig, Endpoint};
use rcgen::generate_simple_self_signed;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};

use crate::datagram;

use super::{TransportLimits, TransportMode, TransportServer};

type ClientDriver = h3::client::Connection<h3_quinn::Connection, Bytes>;
type RequestSender = h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>;
type RequestStream = h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;

struct TestClient {
    endpoint: Endpoint,
    connection: quinn::Connection,
    _driver: ClientDriver,
    sender: RequestSender,
    server_task: tokio::task::JoinHandle<Result<(), super::TransportError>>,
}

#[tokio::test]
async fn connect_udp_supports_both_datagram_paths_and_migration() {
    let mut client = start(TransportMode::EchoDatagrams).await;
    let mut first = open_connect_udp(&mut client.sender, "/udp/first/1").await;
    let mut second = open_connect_udp(&mut client.sender, "/udp/second/2").await;
    let first_id = first.id().into_inner();
    let second_id = second.id().into_inner();

    assert_stream_scoping(&client.connection, first_id, second_id).await;
    assert_migration(&client.endpoint, &client.connection, first_id).await;
    assert_capsule_round_trip(&mut first).await;
    assert_oversized_datagram_is_rejected(&client.connection, first_id);

    first.stop_sending(h3::error::Code::H3_NO_ERROR);
    second.stop_sending(h3::error::Code::H3_NO_ERROR);
    client.endpoint.close(0u32.into(), b"test complete");
    client.server_task.abort();
}

#[tokio::test]
async fn production_mode_rejects_before_authentication() {
    let mut client = start(TransportMode::RejectUntilAuthentication).await;
    let mut stream = send_connect_udp(&mut client.sender, "/udp/rejected/1").await;
    let response =
        stream.recv_response().await.unwrap_or_else(|error| panic!("receive rejection: {error}"));
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(response.version(), Version::HTTP_3);
    client.endpoint.close(0u32.into(), b"test complete");
    client.server_task.abort();
}

async fn assert_stream_scoping(connection: &quinn::Connection, first_id: u64, second_id: u64) {
    send_datagram(connection, first_id, Bytes::from_static(b"first"));
    send_datagram(connection, second_id, Bytes::from_static(b"second"));
    let mut received = HashMap::new();
    for _ in 0..2 {
        let encoded = tokio::time::timeout(Duration::from_secs(2), connection.read_datagram())
            .await
            .unwrap_or_else(|error| panic!("wait for datagram: {error}"))
            .unwrap_or_else(|error| panic!("read datagram: {error}"));
        let datagram =
            datagram::decode(encoded).unwrap_or_else(|error| panic!("decode datagram: {error}"));
        received.insert(datagram.stream_id, datagram.payload);
    }
    assert_eq!(received.get(&first_id), Some(&Bytes::from_static(b"first")));
    assert_eq!(received.get(&second_id), Some(&Bytes::from_static(b"second")));
}

async fn assert_migration(endpoint: &Endpoint, connection: &quinn::Connection, stream_id: u64) {
    let old_address = endpoint
        .local_addr()
        .unwrap_or_else(|error| panic!("read original client address: {error}"));
    let socket = std::net::UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .unwrap_or_else(|error| panic!("bind replacement client socket: {error}"));
    let new_address =
        socket.local_addr().unwrap_or_else(|error| panic!("read replacement address: {error}"));
    endpoint.rebind(socket).unwrap_or_else(|error| panic!("migrate client endpoint: {error}"));
    assert_ne!(old_address, new_address);

    send_datagram(connection, stream_id, Bytes::from_static(b"migrated"));
    let encoded = tokio::time::timeout(Duration::from_secs(2), connection.read_datagram())
        .await
        .unwrap_or_else(|error| panic!("wait after migration: {error}"))
        .unwrap_or_else(|error| panic!("read after migration: {error}"));
    let echoed =
        datagram::decode(encoded).unwrap_or_else(|error| panic!("decode after migration: {error}"));
    assert_eq!(echoed.stream_id, stream_id);
    assert_eq!(echoed.payload, Bytes::from_static(b"migrated"));
}

async fn assert_capsule_round_trip(stream: &mut RequestStream) {
    let capsule = maskman_protocol::capsule::Capsule {
        capsule_type: maskman_protocol::capsule::DATAGRAM_CAPSULE,
        value: b"\0capsule".to_vec(),
    };
    let mut encoded = Vec::new();
    maskman_protocol::capsule::encode(&capsule, &mut encoded)
        .unwrap_or_else(|error| panic!("encode DATAGRAM capsule: {error}"));
    stream
        .send_data(Bytes::from(encoded))
        .await
        .unwrap_or_else(|error| panic!("send DATAGRAM capsule: {error}"));
    let mut echoed = tokio::time::timeout(Duration::from_secs(2), stream.recv_data())
        .await
        .unwrap_or_else(|error| panic!("wait for DATAGRAM capsule: {error}"))
        .unwrap_or_else(|error| panic!("receive DATAGRAM capsule: {error}"))
        .unwrap_or_else(|| panic!("DATAGRAM capsule stream ended"));
    let limits = maskman_protocol::capsule::CapsuleLimits::uniform(65_535);
    let mut decoder = maskman_protocol::capsule::Decoder::new(limits);
    let mut decoded = Vec::new();
    while echoed.has_remaining() {
        let chunk = echoed.chunk();
        let chunk_length = chunk.len();
        decoded.extend(
            decoder
                .push(chunk)
                .unwrap_or_else(|error| panic!("decode echoed DATAGRAM capsule: {error}")),
        );
        echoed.advance(chunk_length);
    }
    decoder.finish().unwrap_or_else(|error| panic!("finish echoed DATAGRAM capsule: {error}"));
    assert_eq!(decoded, vec![maskman_protocol::capsule::DecodeEvent::Capsule(capsule)]);
}

fn assert_oversized_datagram_is_rejected(connection: &quinn::Connection, stream_id: u64) {
    if let Some(max_datagram_size) = connection.max_datagram_size() {
        let oversized = Bytes::from(vec![0u8; max_datagram_size]);
        let encoded = datagram::encode(stream_id, oversized)
            .unwrap_or_else(|error| panic!("encode oversized datagram: {error}"));
        assert!(connection.send_datagram(encoded).is_err());
    }
}

async fn start(mode: TransportMode) -> TestClient {
    let (server_config, certificate) = test_server_config();
    let server = TransportServer::bind(
        SocketAddr::from(([127, 0, 0, 1], 0)),
        server_config,
        test_limits(),
        mode,
    )
    .unwrap_or_else(|error| panic!("bind test server: {error}"));
    let address =
        server.local_addr().unwrap_or_else(|error| panic!("read test server address: {error}"));
    let server_task = tokio::spawn(server.run());
    let mut endpoint = Endpoint::client(SocketAddr::from(([127, 0, 0, 1], 0)))
        .unwrap_or_else(|error| panic!("bind test client: {error}"));
    endpoint.set_default_client_config(test_client_config(certificate));
    let connection = endpoint
        .connect(address, "localhost")
        .unwrap_or_else(|error| panic!("start test connection: {error}"))
        .await
        .unwrap_or_else(|error| panic!("complete test connection: {error}"));
    let (driver, sender) = h3_client(connection.clone()).await;
    TestClient { endpoint, connection, _driver: driver, sender, server_task }
}

async fn h3_client(connection: quinn::Connection) -> (ClientDriver, RequestSender) {
    let mut builder = h3::client::builder();
    builder.enable_extended_connect(true).enable_datagram(true);
    builder
        .build(h3_quinn::Connection::new(connection))
        .await
        .unwrap_or_else(|error| panic!("build HTTP/3 client: {error}"))
}

async fn open_connect_udp(sender: &mut RequestSender, path: &str) -> RequestStream {
    let mut stream = send_connect_udp(sender, path).await;
    let response = stream
        .recv_response()
        .await
        .unwrap_or_else(|error| panic!("receive CONNECT response: {error}"));
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.version(), Version::HTTP_3);
    assert_eq!(
        response.headers().get("capsule-protocol").and_then(|value| value.to_str().ok()),
        Some("?1")
    );
    stream
}

async fn send_connect_udp(sender: &mut RequestSender, path: &str) -> RequestStream {
    let mut request = Request::builder()
        .method(Method::CONNECT)
        .uri(format!("https://proxy.example{path}"))
        .version(Version::HTTP_3)
        .header("capsule-protocol", "?1")
        .body(())
        .unwrap_or_else(|error| panic!("build CONNECT request: {error}"));
    request.extensions_mut().insert(h3::ext::Protocol::CONNECT_UDP);
    sender
        .send_request(request)
        .await
        .unwrap_or_else(|error| panic!("send CONNECT request: {error}"))
}

fn send_datagram(connection: &quinn::Connection, stream_id: u64, payload: Bytes) {
    let encoded = datagram::encode(stream_id, payload)
        .unwrap_or_else(|error| panic!("encode test datagram: {error}"));
    connection.send_datagram(encoded).unwrap_or_else(|error| panic!("send test datagram: {error}"));
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
        drain_timeout: Duration::from_secs(2),
    }
}
