use std::net::{IpAddr, Ipv4Addr};

use ipnet::IpNet;
use maskman_protocol::{
    capsule::{
        decode_address_assign, decode_route_advertisement, encode_address_assign,
        encode_route_advertisement, AddressRange, AssignedAddress, CapsuleLimits, DecodeEvent,
        Decoder, RouteAdvertisement,
    },
    connect::{parse_ip_path, parse_udp_path},
    packet::PacketView,
    varint,
};
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn arbitrary_capsule_chunking_is_equivalent(
        input in prop::collection::vec(any::<u8>(), 0..2048),
        chunk_sizes in prop::collection::vec(1usize..64, 0..64),
    ) {
        let limits = CapsuleLimits::uniform(128);
        let (whole_events, whole_finish, whole_peak) = decode_chunks(&input, &[], limits);
        let (chunked_events, chunked_finish, chunked_peak) =
            decode_chunks(&input, &chunk_sizes, limits);
        prop_assert_eq!(chunked_events, whole_events);
        prop_assert_eq!(chunked_finish, whole_finish);
        prop_assert!(whole_peak <= 128);
        prop_assert!(chunked_peak <= 128);
    }

    #[test]
    fn varint_round_trip(value in 0u64..=varint::MAX_VARINT) {
        let mut encoded = [0; 8];
        let length = varint::encode(value, &mut encoded)
            .unwrap_or_else(|error| panic!("encode generated varint: {error}"));
        prop_assert_eq!(varint::decode(&encoded[..length]), Ok((value, length)));
    }

    #[test]
    fn address_assignment_round_trip(request_id in 0u64..=varint::MAX_VARINT, address in any::<u32>()) {
        let prefix = IpNet::new(IpAddr::V4(Ipv4Addr::from(address)), 32)
            .unwrap_or_else(|error| panic!("construct generated prefix: {error}"));
        let expected = vec![AssignedAddress { request_id, prefix }];
        let mut encoded = Vec::new();
        encode_address_assign(&expected, &mut encoded)
            .unwrap_or_else(|error| panic!("encode generated assignment: {error}"));
        prop_assert_eq!(decode_address_assign(&encoded), Ok(expected));
    }

    #[test]
    fn route_advertisement_round_trip(start in any::<u32>(), span in 0u16..1024, protocol in any::<u8>()) {
        let end = start.saturating_add(u32::from(span));
        let range = AddressRange {
            start: IpAddr::V4(Ipv4Addr::from(start)),
            end: IpAddr::V4(Ipv4Addr::from(end)),
            protocol,
        };
        let expected = RouteAdvertisement::new(vec![range])
            .unwrap_or_else(|error| panic!("validate generated route: {error}"));
        let mut encoded = Vec::new();
        encode_route_advertisement(&expected, &mut encoded)
            .unwrap_or_else(|error| panic!("encode generated route: {error}"));
        prop_assert_eq!(decode_route_advertisement(&encoded), Ok(expected));
    }

    #[test]
    fn overlapping_routes_are_rejected(start in 0u32..=u32::MAX - 2, protocol in any::<u8>()) {
        let first = AddressRange {
            start: IpAddr::V4(Ipv4Addr::from(start)),
            end: IpAddr::V4(Ipv4Addr::from(start + 1)),
            protocol,
        };
        let second = AddressRange {
            start: IpAddr::V4(Ipv4Addr::from(start + 1)),
            end: IpAddr::V4(Ipv4Addr::from(start + 2)),
            protocol,
        };
        prop_assert!(RouteAdvertisement::new(vec![first, second]).is_err());
    }

    #[test]
    fn arbitrary_protocol_inputs_do_not_panic(input in prop::collection::vec(any::<u8>(), 0..512)) {
        let text = String::from_utf8_lossy(&input);
        let _ = parse_udp_path(&text, "/.well-known/masque");
        let _ = parse_ip_path(&text, "/.well-known/masque");
        let _ = PacketView::parse(&input);
        let _ = decode_route_advertisement(&input);
    }
}

fn decode_chunks(
    input: &[u8],
    chunk_sizes: &[usize],
    limits: CapsuleLimits,
) -> (Vec<DecodeEvent>, Result<(), maskman_protocol::capsule::DecoderError>, usize) {
    let mut decoder = Decoder::new(limits);
    let mut events = Vec::new();
    let mut offset = 0;
    let mut index = 0;
    let mut peak = 0;
    while offset < input.len() {
        let requested = chunk_sizes.get(index).copied().unwrap_or(input.len() - offset);
        let end = offset.saturating_add(requested).min(input.len());
        let decoded = decoder
            .push(&input[offset..end])
            .unwrap_or_else(|error| panic!("arbitrary capsule input returned push error: {error}"));
        events.extend(decoded);
        peak = peak.max(decoder.buffered_len());
        offset = end;
        index += 1;
    }
    (events, decoder.finish(), peak)
}
