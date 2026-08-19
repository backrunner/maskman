use std::{net::SocketAddr, sync::Arc, time::Duration};

use bytes::{Buf, Bytes};
use http::{Method, Request, StatusCode, Version};
use quinn::Endpoint;

use super::{
    h3_client, test_client_config, test_limits, test_server_config, TransportContext,
    TransportMode, TransportServer,
};
use crate::datagram;

#[tokio::test]
async fn authenticated_connect_ip_assigns_and_forwards_through_tun_boundary() {
    let mut document = maskman_config::ConfigDocument::default();
    document.proxy.ip.enabled = true;
    document.proxy.ip.client_ipv4_pool = Some("100.96.0.0/30".into());
    document.proxy.ip.mtu = 1500;
    document.auth.principals.push(maskman_config::model::PrincipalConfig {
        id: "client".into(),
        roles: vec!["ip".into()],
        certificate_sha256: Vec::new(),
    });
    document.auth.bearer_tokens.push(maskman_config::model::BearerTokenConfig {
        id: "token".into(),
        principal: "client".into(),
        secret_sha256: hex_sha256("secret"),
        expires_at: None,
        enabled: true,
    });
    document.policy.roles.push(maskman_config::model::RoleConfig {
        name: "ip".into(),
        capabilities: vec!["connect-ip".into()],
        allow_destinations: vec!["8.8.8.0/24".into()],
        deny_destinations: Vec::new(),
        deny_private: true,
        allowed_ip_protocols: vec!["17".into()],
        limits: Default::default(),
    });
    let compiled = maskman_config::compile_document(&document, std::path::Path::new("."))
        .unwrap_or_else(|error| panic!("compile IP config: {error}"));
    let context = Arc::new(TransportContext::new(Arc::new(compiled)));
    let mut tun_rx = context.take_tun_receiver().unwrap_or_else(|| panic!("take TUN receiver"));
    let (server_config, certificate) = test_server_config();
    let server = TransportServer::bind_with_context(
        SocketAddr::from(([127, 0, 0, 1], 0)),
        server_config,
        test_limits(),
        TransportMode::RejectUntilAuthentication,
        context.clone(),
    )
    .unwrap_or_else(|error| panic!("bind IP server: {error}"));
    let address =
        server.local_addr().unwrap_or_else(|error| panic!("read IP server address: {error}"));
    let server_task = tokio::spawn(server.run());
    let mut endpoint = Endpoint::client(SocketAddr::from(([127, 0, 0, 1], 0)))
        .unwrap_or_else(|error| panic!("bind IP client: {error}"));
    endpoint.set_default_client_config(test_client_config(certificate));
    let connection = endpoint
        .connect(address, "localhost")
        .unwrap_or_else(|error| panic!("connect IP client: {error}"))
        .await
        .unwrap_or_else(|error| panic!("complete IP client: {error}"));
    let (_driver, mut sender) = h3_client(connection.clone()).await;
    let mut request = Request::builder()
        .method(Method::CONNECT)
        .uri("https://proxy.example/.well-known/masque/ip/%2A/17/")
        .version(Version::HTTP_3)
        .header("capsule-protocol", "?1")
        .header("authorization", "Bearer mm_token_secret")
        .body(())
        .unwrap_or_else(|error| panic!("build IP request: {error}"));
    request.extensions_mut().insert(h3::ext::Protocol::CONNECT_IP);
    let mut stream = sender
        .send_request(request)
        .await
        .unwrap_or_else(|error| panic!("send IP request: {error}"));
    let response =
        stream.recv_response().await.unwrap_or_else(|error| panic!("receive IP response: {error}"));
    assert_eq!(response.status(), StatusCode::OK);
    let mut assignment_data = tokio::time::timeout(Duration::from_secs(2), stream.recv_data())
        .await
        .unwrap_or_else(|error| panic!("wait for ADDRESS_ASSIGN: {error}"))
        .unwrap_or_else(|error| panic!("read ADDRESS_ASSIGN: {error}"))
        .unwrap_or_else(|| panic!("ADDRESS_ASSIGN stream ended"));
    let mut decoder = maskman_protocol::capsule::Decoder::new(
        maskman_protocol::capsule::CapsuleLimits::uniform(65_535),
    );
    let mut assignments = Vec::new();
    while assignment_data.has_remaining() {
        let chunk = assignment_data.chunk();
        let length = chunk.len();
        for event in
            decoder.push(chunk).unwrap_or_else(|error| panic!("decode ADDRESS_ASSIGN: {error}"))
        {
            if let maskman_protocol::capsule::DecodeEvent::Capsule(capsule) = event {
                if capsule.capsule_type == maskman_protocol::capsule::ADDRESS_ASSIGN_CAPSULE {
                    assignments = maskman_protocol::capsule::decode_address_assign(&capsule.value)
                        .unwrap_or_else(|error| panic!("parse ADDRESS_ASSIGN: {error}"));
                }
            }
        }
        assignment_data.advance(length);
    }
    assert_eq!(assignments.len(), 1);
    let assigned = match assignments[0].prefix.network() {
        std::net::IpAddr::V4(address) => address,
        std::net::IpAddr::V6(_) => panic!("expected IPv4 assignment"),
    };
    let outbound = ipv4_packet(assigned.octets(), [8, 8, 8, 8], 64, b"ping");
    let stream_id = stream.id().into_inner();
    let mut http_payload = Vec::new();
    maskman_protocol::capsule::encode_datagram(0, &outbound, &mut http_payload)
        .unwrap_or_else(|error| panic!("encode outbound IP datagram: {error}"));
    connection
        .send_datagram(
            datagram::encode(stream_id, Bytes::from(http_payload))
                .unwrap_or_else(|error| panic!("encode HTTP datagram: {error}")),
        )
        .unwrap_or_else(|error| panic!("send outbound IP datagram: {error}"));
    let forwarded = tokio::time::timeout(Duration::from_secs(2), tun_rx.recv())
        .await
        .unwrap_or_else(|error| panic!("wait for TUN packet: {error}"))
        .unwrap_or_else(|| panic!("TUN queue closed"));
    assert_eq!(forwarded[8], 63);
    assert_eq!(&forwarded[12..16], &assigned.octets());
    assert_eq!(&forwarded[16..20], &[8, 8, 8, 8]);
    let inbound = ipv4_packet([8, 8, 8, 8], assigned.octets(), 64, b"pong");
    assert!(context.dispatch_tun_packet(Bytes::from(inbound.clone())));
    let response_datagram =
        tokio::time::timeout(Duration::from_secs(2), connection.read_datagram())
            .await
            .unwrap_or_else(|error| panic!("wait for inbound IP datagram: {error}"))
            .unwrap_or_else(|error| panic!("read inbound IP datagram: {error}"));
    let response_datagram = datagram::decode(response_datagram)
        .unwrap_or_else(|error| panic!("decode HTTP datagram: {error}"));
    let response_datagram = maskman_protocol::capsule::decode_datagram(&response_datagram.payload)
        .unwrap_or_else(|error| panic!("decode IP datagram: {error}"));
    assert_eq!(response_datagram.context_id, 0);
    assert_eq!(response_datagram.payload, inbound.as_slice());
    stream.stop_sending(h3::error::Code::H3_NO_ERROR);
    endpoint.close(0u32.into(), b"test complete");
    server_task.abort();
}

fn hex_sha256(value: &str) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(value.as_bytes()).iter().map(|byte| format!("{byte:02x}")).collect()
}

fn ipv4_packet(source: [u8; 4], destination: [u8; 4], ttl: u8, payload: &[u8]) -> Vec<u8> {
    let total = 20 + payload.len();
    let mut packet = vec![0u8; total];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    packet[8] = ttl;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&source);
    packet[16..20].copy_from_slice(&destination);
    packet[20..].copy_from_slice(payload);
    let mut sum = 0u32;
    for pair in packet[..20].chunks_exact(2) {
        sum += u32::from(u16::from_be_bytes([pair[0], pair[1]]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    packet[10..12].copy_from_slice(&(!(sum as u16)).to_be_bytes());
    packet
}
