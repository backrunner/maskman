use std::sync::Arc;

use bytes::Bytes;
use maskman_config::model::ConfigDocument;
use maskman_protocol::connect::{IpProtocolScope, IpScope, IpTarget};

use super::{AddressPoolSet, IpDropReason, IpSession, IpSessionRegistry};
use crate::{auth::Principal, policy};

fn session() -> (super::IpSession, tokio::sync::mpsc::Receiver<Bytes>) {
    let mut document = ConfigDocument::default();
    document.auth.principals.push(maskman_config::model::PrincipalConfig {
        id: "client".into(),
        roles: vec!["ip".into()],
        certificate_sha256: Vec::new(),
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
    document.proxy.ip.client_ipv4_pool = Some("100.96.0.0/30".into());
    let config = maskman_config::compile_document(&document, std::path::Path::new("."))
        .unwrap_or_else(|error| panic!("compile IP config: {error}"));
    let pools = AddressPoolSet::from_config(&config.ip);
    let policy = Arc::new(policy::compile(
        Arc::new(config),
        &Principal { id: "client".into(), roles: vec!["ip".into()] },
    ));
    let (tun_tx, _tun_rx) = tokio::sync::mpsc::channel(8);
    let session = IpSession::start(
        IpScope { target: IpTarget::Any, protocol: IpProtocolScope::Number(17) },
        &pools,
        policy,
        1500,
        tun_tx,
    )
    .unwrap_or_else(|| panic!("start IP session"));
    (session, _tun_rx)
}

#[test]
fn source_and_protocol_are_enforced() {
    let (session, _tun_rx) = session();
    let assigned = session.handle.assigned()[0].network();
    let mut packet = vec![
        0x45, 0, 0, 28, 0, 0, 0, 0, 64, 17, 0, 0, 0, 0, 0, 0, 8, 8, 8, 8, 1, 2, 3, 4, 0, 0, 0, 0,
    ];
    packet[12..16].copy_from_slice(&match assigned {
        std::net::IpAddr::V4(address) => address.octets(),
        std::net::IpAddr::V6(_) => [0, 0, 0, 0],
    });
    let packet_checksum = checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&packet_checksum.to_be_bytes());
    assert_eq!(session.handle.try_send(Bytes::from(packet.clone())), Ok(()));
    let mut wrong = packet;
    wrong[9] = 6;
    wrong[10] = 0;
    wrong[11] = 0;
    let wrong_checksum = checksum(&wrong[..20]);
    wrong[10..12].copy_from_slice(&wrong_checksum.to_be_bytes());
    assert_eq!(session.handle.try_send(Bytes::from(wrong)), Err(IpDropReason::Protocol));
}

#[test]
fn address_requests_match_family_and_preserve_complete_assignment_set() {
    let (session, _tun_rx) = session();
    let requests = vec![
        maskman_protocol::capsule::RequestedAddress {
            request_id: 7,
            prefix: "0.0.0.0/32"
                .parse()
                .unwrap_or_else(|error| panic!("parse IPv4 request: {error}")),
        },
        maskman_protocol::capsule::RequestedAddress {
            request_id: 8,
            prefix: "::/128".parse().unwrap_or_else(|error| panic!("parse IPv6 request: {error}")),
        },
    ];
    let encoded = session
        .handle
        .address_request_capsule(&requests)
        .unwrap_or_else(|error| panic!("encode address response: {error}"));
    let assignments = maskman_protocol::capsule::decode_address_assign(&encoded)
        .unwrap_or_else(|error| panic!("decode address response: {error}"));

    assert_eq!(assignments.len(), 2);
    assert_eq!(assignments[0].request_id, 7);
    assert_eq!(assignments[0].prefix, session.handle.assigned()[0]);
    assert_eq!(assignments[1].request_id, 8);
    assert_eq!(assignments[1].prefix.to_string(), "::/128");
}

#[test]
fn initial_assignment_uses_unprompted_request_id_zero() {
    let (session, _tun_rx) = session();
    let encoded = session
        .handle
        .initial_assignment_capsule()
        .unwrap_or_else(|error| panic!("encode initial assignment: {error}"));
    let assignments = maskman_protocol::capsule::decode_address_assign(&encoded)
        .unwrap_or_else(|error| panic!("decode initial assignment: {error}"));
    assert_eq!(assignments.len(), session.handle.assigned().len());
    assert!(assignments.iter().all(|assignment| assignment.request_id == 0));
}

#[test]
fn registry_dispatches_only_to_assigned_destination() {
    let (session, _tun_rx) = session();
    let destination = session.handle.assigned()[0].network();
    let registry = IpSessionRegistry::default();
    assert!(registry.insert(1, 4, session.handle.clone()));
    let mut packet = vec![0x45, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0, 8, 8, 8, 8, 0, 0, 0, 0];
    packet[16..20].copy_from_slice(&match destination {
        std::net::IpAddr::V4(address) => address.octets(),
        std::net::IpAddr::V6(_) => [0, 0, 0, 0],
    });
    let checksum = checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());
    assert!(registry.dispatch_tun(Bytes::from(packet)).is_ok());
}

#[test]
fn reverse_packets_use_route_and_principal_scope() {
    let (session, _tun_rx) = session();
    let route = maskman_protocol::capsule::RouteAdvertisement::new(vec![
        maskman_protocol::capsule::AddressRange {
            start: "8.8.8.0".parse().unwrap_or_else(|error| panic!("parse route start: {error}")),
            end: "8.8.8.255".parse().unwrap_or_else(|error| panic!("parse route end: {error}")),
            protocol: 17,
        },
    ])
    .unwrap_or_else(|error| panic!("build route: {error}"));
    let mut encoded = Vec::new();
    maskman_protocol::capsule::encode_route_advertisement(&route, &mut encoded)
        .unwrap_or_else(|error| panic!("encode route: {error}"));
    session
        .handle
        .replace_routes(&encoded)
        .unwrap_or_else(|error| panic!("install route: {error}"));

    let assigned = match session.handle.assigned()[0].network() {
        std::net::IpAddr::V4(address) => address.octets(),
        std::net::IpAddr::V6(_) => panic!("expected IPv4 assignment"),
    };
    let allowed = ipv4_packet([8, 8, 8, 8], assigned, 64);
    assert_eq!(session.handle.try_send_from_tun(Bytes::from(allowed)), Ok(()));
    let denied = ipv4_packet([1, 1, 1, 1], assigned, 64);
    assert_eq!(session.handle.try_send_from_tun(Bytes::from(denied)), Err(IpDropReason::Source));
}

fn ipv4_packet(source: [u8; 4], destination: [u8; 4], ttl: u8) -> Vec<u8> {
    let total = 20;
    let mut packet = vec![0u8; total];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    packet[8] = ttl;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&source);
    packet[16..20].copy_from_slice(&destination);
    let checksum = checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());
    packet
}

fn checksum(header: &[u8]) -> u16 {
    let mut sum = 0u32;
    for pair in header.chunks_exact(2) {
        sum += u32::from(u16::from_be_bytes([pair[0], pair[1]]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}
