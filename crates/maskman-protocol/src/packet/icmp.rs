use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use thiserror::Error;

use super::{Ipv4Packet, PacketError, PacketView};

const IPV4_QUOTE_LIMIT: usize = 548;
const IPV6_QUOTE_LIMIT: usize = 1_232;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IcmpErrorKind {
    SourcePolicy,
    NoRoute,
    HopLimit,
    PacketTooBig { mtu: u32 },
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum IcmpBuildError {
    #[error("invoking packet is invalid: {0}")]
    Packet(#[from] PacketError),
    #[error("ICMP source and invoking packet use different address families")]
    FamilyMismatch,
    #[error("ICMP packet would exceed the IP length field")]
    LengthOverflow,
}

pub fn build_error(
    invoking: &[u8],
    source: IpAddr,
    kind: IcmpErrorKind,
) -> Result<Vec<u8>, IcmpBuildError> {
    let view = PacketView::parse_prefix(invoking)?;
    let quote_len = invoking.len().min(view.total_len());
    match (view, source) {
        (PacketView::V4(packet), IpAddr::V4(source)) => {
            build_v4(invoking, quote_len, packet, source, kind)
        }
        (PacketView::V6(packet), IpAddr::V6(source)) => {
            build_v6(invoking, quote_len, packet, source, kind)
        }
        _ => Err(IcmpBuildError::FamilyMismatch),
    }
}

fn build_v4(
    invoking: &[u8],
    quote_len: usize,
    packet: Ipv4Packet<'_>,
    source: Ipv4Addr,
    kind: IcmpErrorKind,
) -> Result<Vec<u8>, IcmpBuildError> {
    let quote_len = quote_len.min(IPV4_QUOTE_LIMIT);
    let payload_len = 8usize.checked_add(quote_len).ok_or(IcmpBuildError::LengthOverflow)?;
    let total_len = 20usize.checked_add(payload_len).ok_or(IcmpBuildError::LengthOverflow)?;
    if total_len > usize::from(u16::MAX) {
        return Err(IcmpBuildError::LengthOverflow);
    }
    let mut output = vec![0u8; total_len];
    output[0] = 0x45;
    output[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    output[8] = 64;
    output[9] = 1;
    output[12..16].copy_from_slice(&source.octets());
    output[16..20].copy_from_slice(&packet.source().octets());
    let (message_type, code, field) = v4_fields(kind);
    output[20] = message_type;
    output[21] = code;
    if let Some(mtu) = field {
        output[26..28].copy_from_slice(&(mtu.min(u32::from(u16::MAX)) as u16).to_be_bytes());
    }
    output[28..].copy_from_slice(&invoking[..quote_len]);
    let message_checksum = checksum(&output[20..]);
    output[22..24].copy_from_slice(&message_checksum.to_be_bytes());
    let header_checksum = checksum(&output[..20]);
    output[10..12].copy_from_slice(&header_checksum.to_be_bytes());
    Ok(output)
}

fn build_v6(
    invoking: &[u8],
    quote_len: usize,
    packet: super::Ipv6Packet<'_>,
    source: Ipv6Addr,
    kind: IcmpErrorKind,
) -> Result<Vec<u8>, IcmpBuildError> {
    let quote_len = quote_len.min(IPV6_QUOTE_LIMIT);
    let payload_len = 8usize.checked_add(quote_len).ok_or(IcmpBuildError::LengthOverflow)?;
    if payload_len > usize::from(u16::MAX) {
        return Err(IcmpBuildError::LengthOverflow);
    }
    let mut output = vec![0u8; 40 + payload_len];
    output[0] = 0x60;
    output[4..6].copy_from_slice(&(payload_len as u16).to_be_bytes());
    output[6] = 58;
    output[7] = 64;
    output[8..24].copy_from_slice(&source.octets());
    output[24..40].copy_from_slice(&packet.source().octets());
    let (message_type, code, field) = v6_fields(kind);
    output[40] = message_type;
    output[41] = code;
    if let Some(mtu) = field {
        output[44..48].copy_from_slice(&mtu.to_be_bytes());
    }
    output[48..].copy_from_slice(&invoking[..quote_len]);
    let checksum = ipv6_checksum(source, packet.source(), &output[40..]);
    output[42..44].copy_from_slice(&checksum.to_be_bytes());
    Ok(output)
}

fn v4_fields(kind: IcmpErrorKind) -> (u8, u8, Option<u32>) {
    match kind {
        IcmpErrorKind::SourcePolicy => (3, 13, None),
        IcmpErrorKind::NoRoute => (3, 0, None),
        IcmpErrorKind::HopLimit => (11, 0, None),
        IcmpErrorKind::PacketTooBig { mtu } => (3, 4, Some(mtu)),
    }
}

fn v6_fields(kind: IcmpErrorKind) -> (u8, u8, Option<u32>) {
    match kind {
        IcmpErrorKind::SourcePolicy => (1, 5, None),
        IcmpErrorKind::NoRoute => (1, 0, None),
        IcmpErrorKind::HopLimit => (3, 0, None),
        IcmpErrorKind::PacketTooBig { mtu } => (2, 0, Some(mtu)),
    }
}

fn checksum(input: &[u8]) -> u16 {
    let mut sum = 0u32;
    for pair in input.chunks(2) {
        let value = if pair.len() == 2 {
            u16::from_be_bytes([pair[0], pair[1]])
        } else {
            u16::from(pair[0]) << 8
        };
        sum = sum.saturating_add(u32::from(value));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn ipv6_checksum(source: Ipv6Addr, destination: Ipv6Addr, payload: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(40 + payload.len());
    pseudo.extend_from_slice(&source.octets());
    pseudo.extend_from_slice(&destination.octets());
    pseudo.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    pseudo.extend_from_slice(&[0, 0, 0, 58]);
    pseudo.extend_from_slice(payload);
    checksum(&pseudo)
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use super::{build_error, IcmpErrorKind};

    fn v4_packet() -> Vec<u8> {
        let mut packet = vec![0u8; 28];
        packet[0] = 0x45;
        let packet_len = packet.len() as u16;
        packet[2..4].copy_from_slice(&packet_len.to_be_bytes());
        packet[8] = 32;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&[100, 96, 0, 1]);
        packet[16..20].copy_from_slice(&[8, 8, 8, 8]);
        packet[20..].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        let checksum = super::checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&checksum.to_be_bytes());
        packet
    }

    #[test]
    fn builds_ipv4_no_route_with_quoted_header() {
        let output =
            build_error(&v4_packet(), IpAddr::from([100, 96, 0, 1]), IcmpErrorKind::NoRoute)
                .unwrap_or_else(|error| panic!("build ICMPv4: {error}"));
        assert_eq!(&output[12..16], &[100, 96, 0, 1]);
        assert_eq!(&output[16..20], &[100, 96, 0, 1]);
        assert_eq!(&output[20..22], &[3, 0]);
        assert_eq!(&output[28..48], &v4_packet()[..20]);
        assert_eq!(super::checksum(&output[20..]), 0);
        assert_eq!(super::checksum(&output[..20]), 0);
    }

    #[test]
    fn builds_ipv6_packet_too_big_and_checks_pseudo_header() {
        let mut packet = vec![0u8; 40];
        packet[0] = 0x60;
        packet[6] = 17;
        packet[7] = 64;
        packet[8..24].copy_from_slice(&[0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        packet[24..40].copy_from_slice(&[0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        let output = build_error(
            &packet,
            "2001:db8::1".parse().unwrap_or_else(|error| panic!("parse source: {error}")),
            IcmpErrorKind::PacketTooBig { mtu: 1280 },
        )
        .unwrap_or_else(|error| panic!("build ICMPv6: {error}"));
        assert_eq!(output[40], 2);
        assert_eq!(&output[44..48], &1280u32.to_be_bytes());
        let mut payload = output[40..].to_vec();
        payload[2] = 0;
        payload[3] = 0;
        let expected = super::ipv6_checksum(
            "2001:db8::1".parse().unwrap_or_else(|error| panic!("parse source: {error}")),
            "2001:db8::1".parse().unwrap_or_else(|error| panic!("parse destination: {error}")),
            &payload,
        );
        assert_eq!(expected, u16::from_be_bytes([output[42], output[43]]));
    }
}
