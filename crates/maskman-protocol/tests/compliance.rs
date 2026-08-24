use std::net::IpAddr;

use ipnet::IpNet;
use maskman_protocol::{
    capsule::{
        decode_address_assign, decode_address_request, decode_route_advertisement,
        encode_address_assign, encode_route_advertisement, validate_udp_payload,
        AddressAssignments, AddressRange, AssignedAddress, Capsule, CapsuleLimits, DecodeEvent,
        Decoder, DecoderError, RouteAdvertisement, SkipReason, DATAGRAM_CAPSULE,
    },
    connect::{parse_ip_path, parse_udp_path, IpProtocolScope, IpTarget, TargetHost},
    packet::{classify_address, decrement_hop_limit, AddressClass, PacketError, PacketView},
};

#[test]
fn rfc9297_capsule_golden_vectors() {
    let wire = [0x00, 0x04, 0x00, 0x01, 0x02, 0x03];
    let mut decoder = Decoder::default();
    assert_eq!(
        decoder.push(&wire),
        Ok(vec![DecodeEvent::Capsule(Capsule {
            capsule_type: DATAGRAM_CAPSULE,
            value: vec![0x00, 0x01, 0x02, 0x03],
        })])
    );
    assert_eq!(decoder.finish(), Ok(()));

    let non_minimal = [0x40, 0x00, 0x40, 0x01, 0x00];
    assert_eq!(
        Decoder::default().push(&non_minimal),
        Ok(vec![DecodeEvent::Capsule(Capsule { capsule_type: DATAGRAM_CAPSULE, value: vec![0] })])
    );
}

#[test]
fn rfc9297_unknown_and_oversized_capsules_are_streamed() {
    let limits = CapsuleLimits::uniform(4);
    let mut decoder = Decoder::new(limits);
    let wire = [0x21, 0x03, 1, 2, 3, 0x00, 0x05, 0, 1, 2, 3, 4, 0, 0];
    let events =
        decoder.push(&wire).unwrap_or_else(|error| panic!("decode bounded capsules: {error}"));
    assert_eq!(events.len(), 3);
    assert!(matches!(
        events.first(),
        Some(DecodeEvent::Skipped(value)) if value.reason == SkipReason::UnknownType
    ));
    assert!(matches!(
        events.get(1),
        Some(DecodeEvent::Skipped(value)) if value.reason == SkipReason::Oversized
    ));
    assert!(matches!(events.get(2), Some(DecodeEvent::Capsule(value)) if value.value.is_empty()));
    assert_eq!(decoder.buffered_len(), 0);
}

#[test]
fn rfc9297_truncated_capsule_is_malformed() {
    let mut decoder = Decoder::default();
    assert!(decoder.push(&[0, 3, 1]).is_ok());
    assert_eq!(decoder.finish(), Err(DecoderError::Truncated));
}

#[test]
fn rfc9298_udp_path_golden_vectors() {
    let base = "/.well-known/masque";
    let dns = parse_udp_path("/.well-known/masque/udp/example.com/443/", base)
        .unwrap_or_else(|error| panic!("parse DNS target: {error}"));
    assert_eq!(dns.host, TargetHost::Name("example.com".to_owned()));
    let ipv6 = parse_udp_path("/.well-known/masque/udp/2001%3Adb8%3A%3A1/53/", base)
        .unwrap_or_else(|error| panic!("parse IPv6 target: {error}"));
    assert_eq!(ipv6.host, TargetHost::Ip(ip("2001:db8::1")));
    assert!(parse_udp_path("/.well-known/masque/udp/2001:db8::1/53/", base).is_err());
    assert!(parse_udp_path("/.well-known/masque/udp/example.com/0/", base).is_err());
    assert!(parse_udp_path("/.well-known/masque/udp/example.com/65536/", base).is_err());
}

#[test]
fn rfc9298_context_zero_payload_limit() {
    let accepted =
        maskman_protocol::capsule::DatagramPayload { context_id: 0, payload: &vec![0; 65_527] };
    assert_eq!(validate_udp_payload(&accepted), Ok(()));
    let rejected =
        maskman_protocol::capsule::DatagramPayload { context_id: 0, payload: &vec![0; 65_528] };
    assert!(validate_udp_payload(&rejected).is_err());
}

#[test]
fn rfc9484_ip_path_errata_8444() {
    let base = "/.well-known/masque";
    let scope = parse_ip_path("/.well-known/masque/ip/%2A/%2A/", base)
        .unwrap_or_else(|error| panic!("parse wildcard IP path: {error}"));
    assert_eq!(scope.target, IpTarget::Any);
    assert_eq!(scope.protocol, IpProtocolScope::Any);
    assert!(parse_ip_path("/.well-known/masque/ip/*/%2A/", base).is_err());
    assert!(parse_ip_path("/.well-known/masque/ip/%2A/*/", base).is_err());
    assert!(parse_ip_path("/.well-known/masque/ip/192.0.2.1%2F24/17/", base).is_err());
}

#[test]
fn rfc9484_address_capsule_golden_vectors() {
    let assignment = [0x00, 0x04, 192, 0, 2, 0, 24];
    assert_eq!(
        decode_address_assign(&assignment),
        Ok(vec![AssignedAddress { request_id: 0, prefix: net("192.0.2.0/24") }])
    );
    let mut encoded = Vec::new();
    encode_address_assign(
        &[AssignedAddress { request_id: 0, prefix: net("192.0.2.0/24") }],
        &mut encoded,
    )
    .unwrap_or_else(|error| panic!("encode assignment: {error}"));
    assert_eq!(encoded, assignment);

    let mut request = vec![1, 6];
    request.extend_from_slice(&[0; 16]);
    request.push(128);
    assert_eq!(decode_address_request(&request).map(|value| value.len()), Ok(1));
    assert!(decode_address_request(&[]).is_err());
    assert!(decode_address_request(&[0, 4, 0, 0, 0, 0, 32]).is_err());
}

#[test]
fn rfc9484_address_replacement_is_atomic() {
    let valid = [0, 4, 192, 0, 2, 0, 24];
    let mut state = AddressAssignments::default();
    assert_eq!(state.replace(&valid), Ok(()));
    assert!(state.replace(&[0, 6, 0]).is_err());
    assert_eq!(state.entries()[0].prefix, net("192.0.2.0/24"));
    assert_eq!(state.replace(&[]), Ok(()));
    assert!(state.entries().is_empty());
}

#[test]
fn rfc9484_route_capsule_golden_vectors() {
    let wire = [4, 192, 0, 2, 0, 192, 0, 2, 255, 17];
    let advertisement =
        decode_route_advertisement(&wire).unwrap_or_else(|error| panic!("decode route: {error}"));
    assert_eq!(advertisement.ranges().len(), 1);
    let mut encoded = Vec::new();
    encode_route_advertisement(&advertisement, &mut encoded)
        .unwrap_or_else(|error| panic!("encode route: {error}"));
    assert_eq!(encoded, wire);
}

#[test]
fn rfc9484_route_order_overlap_and_replacement() {
    let first = AddressRange { start: ip("192.0.2.0"), end: ip("192.0.2.10"), protocol: 0 };
    let conflicting = AddressRange { start: ip("192.0.2.5"), end: ip("192.0.2.20"), protocol: 17 };
    assert!(RouteAdvertisement::new(vec![first.clone(), conflicting]).is_err());
    let mut state = RouteAdvertisement::default();
    let mut encoded = Vec::new();
    let valid = RouteAdvertisement::new(vec![first])
        .unwrap_or_else(|error| panic!("validate route: {error}"));
    encode_route_advertisement(&valid, &mut encoded)
        .unwrap_or_else(|error| panic!("encode route: {error}"));
    assert_eq!(state.replace(&encoded), Ok(()));
    assert!(state.replace(&[4, 192]).is_err());
    assert_eq!(state.ranges(), valid.ranges());
}

#[test]
fn rfc9484_ip_packet_validation_and_hop_limit() {
    let mut ipv4 = ipv4_packet(64);
    let view = PacketView::parse(&ipv4).unwrap_or_else(|error| panic!("parse IPv4: {error}"));
    assert_eq!(view.protocol(), 17);
    assert_eq!(decrement_hop_limit(&mut ipv4), Ok(()));
    assert_eq!(PacketView::parse(&ipv4).map(PacketView::hop_limit), Ok(63));

    let mut ipv6 = vec![0x60, 0, 0, 0, 0, 0, 59, 2];
    ipv6.resize(40, 0);
    assert_eq!(decrement_hop_limit(&mut ipv6), Ok(()));
    assert_eq!(PacketView::parse(&ipv6).map(PacketView::hop_limit), Ok(1));
    assert_eq!(decrement_hop_limit(&mut ipv6), Err(PacketError::HopLimitExpired));
}

#[test]
fn rfc9484_ipv6_extension_chain_is_bounded() {
    let mut packet = ipv6_extensions(2);
    packet[40] = 60;
    packet[48] = 17;
    assert_eq!(PacketView::parse(&packet).map(PacketView::protocol), Ok(17));
    assert!(PacketView::parse(&ipv6_extensions(9)).is_err());
}

#[test]
fn rfc9484_special_address_scope_is_default_denied() {
    for address in [
        "127.0.0.1",
        "10.0.0.1",
        "169.254.1.1",
        "224.0.0.1",
        "::1",
        "fc00::1",
        "fe80::1",
        "ff02::1",
        "4000::1",
    ] {
        assert!(classify_address(ip(address)).is_default_denied(), "{address}");
    }
    assert_eq!(classify_address(ip("2001:4860:4860::8888")), AddressClass::Global);
}

fn ip(value: &str) -> IpAddr {
    value.parse().unwrap_or_else(|error| panic!("parse IP {value}: {error}"))
}

fn net(value: &str) -> IpNet {
    value.parse().unwrap_or_else(|error| panic!("parse network {value}: {error}"))
}

fn ipv4_packet(ttl: u8) -> Vec<u8> {
    let mut packet =
        vec![0x45, 0, 0, 24, 0, 1, 0, 0, ttl, 17, 0, 0, 192, 0, 2, 1, 198, 51, 100, 1, 1, 2, 3, 4];
    let checksum = checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());
    packet
}

fn checksum(header: &[u8]) -> u16 {
    let mut sum = header
        .chunks(2)
        .map(|chunk| u32::from(u16::from_be_bytes([chunk[0], chunk[1]])))
        .sum::<u32>();
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn ipv6_extensions(count: usize) -> Vec<u8> {
    let payload_length = count * 8;
    let mut packet = vec![0x60, 0, 0, 0, (payload_length >> 8) as u8, payload_length as u8, 60, 64];
    packet.resize(40 + payload_length, 0);
    for offset in (40..40 + payload_length).step_by(8) {
        packet[offset] = 60;
    }
    packet
}
