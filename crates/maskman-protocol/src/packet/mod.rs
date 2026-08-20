mod icmp;
mod ipv4;
mod ipv6;
mod scope;

pub use icmp::{build_error as build_icmp_error, IcmpBuildError, IcmpErrorKind};
pub use ipv4::Ipv4Packet;
pub use ipv6::{Ipv6Packet, MAX_EXTENSION_HEADERS};
pub use scope::{classify_address, AddressClass};

use std::net::IpAddr;

use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum PacketError {
    #[error("IP packet is truncated: need {needed} bytes, have {available}")]
    Truncated { needed: usize, available: usize },
    #[error("unsupported IP version {0}")]
    Version(u8),
    #[error("IP packet length field {declared} does not match {actual} bytes")]
    LengthMismatch { declared: usize, actual: usize },
    #[error("IPv4 header length is invalid")]
    InvalidHeaderLength,
    #[error("IPv4 header checksum is invalid")]
    InvalidChecksum,
    #[error("IPv6 extension header is malformed")]
    InvalidExtensionLength,
    #[error("IPv6 extension header order is invalid")]
    InvalidExtensionOrder,
    #[error("IPv6 extension header appears more than once")]
    DuplicateExtension,
    #[error("IPv6 extension header chain exceeds the configured limit")]
    TooManyExtensions,
    #[error("IP hop limit or TTL is already exhausted")]
    HopLimitExpired,
    #[error("ICMP error does not contain a complete invoking IP header")]
    InvalidIcmpInvocation,
}

#[derive(Debug, Clone, Copy)]
pub enum PacketView<'a> {
    V4(Ipv4Packet<'a>),
    V6(Ipv6Packet<'a>),
}

impl<'a> PacketView<'a> {
    pub fn parse(input: &'a [u8]) -> Result<Self, PacketError> {
        let view = Self::parse_prefix(input)?;
        if view.total_len() != input.len() {
            return Err(PacketError::LengthMismatch {
                declared: view.total_len(),
                actual: input.len(),
            });
        }
        Ok(view)
    }

    pub fn parse_prefix(input: &'a [u8]) -> Result<Self, PacketError> {
        let first = input.first().ok_or(PacketError::Truncated { needed: 1, available: 0 })?;
        let version = first >> 4;
        match version {
            4 => Ok(Self::V4(Ipv4Packet::parse_prefix(input)?)),
            6 => Ok(Self::V6(Ipv6Packet::parse_prefix(input)?)),
            other => Err(PacketError::Version(other)),
        }
    }

    pub fn source(self) -> IpAddr {
        match self {
            Self::V4(packet) => packet.source().into(),
            Self::V6(packet) => packet.source().into(),
        }
    }

    pub fn destination(self) -> IpAddr {
        match self {
            Self::V4(packet) => packet.destination().into(),
            Self::V6(packet) => packet.destination().into(),
        }
    }

    pub fn protocol(self) -> u8 {
        match self {
            Self::V4(packet) => packet.protocol(),
            Self::V6(packet) => packet.protocol(),
        }
    }

    pub fn hop_limit(self) -> u8 {
        match self {
            Self::V4(packet) => packet.ttl(),
            Self::V6(packet) => packet.hop_limit(),
        }
    }

    pub fn header_len(self) -> usize {
        match self {
            Self::V4(packet) => packet.header_len(),
            Self::V6(packet) => packet.header_len(),
        }
    }

    pub fn total_len(self) -> usize {
        match self {
            Self::V4(packet) => packet.total_len(),
            Self::V6(packet) => packet.total_len(),
        }
    }

    pub fn payload(self) -> &'a [u8] {
        match self {
            Self::V4(packet) => packet.payload(),
            Self::V6(packet) => packet.payload(),
        }
    }

    pub fn icmp_invoking_packet(self) -> Result<Option<Self>, PacketError> {
        let protocol = self.protocol();
        if !is_icmp_protocol(protocol) {
            return Ok(None);
        }
        let payload = self.payload();
        let message_type = *payload.first().ok_or(PacketError::InvalidIcmpInvocation)?;
        let is_error = match protocol {
            1 => matches!(message_type, 3 | 4 | 5 | 11 | 12),
            58 => message_type < 128,
            _ => false,
        };
        if !is_error {
            return Ok(None);
        }
        let invoking = payload.get(8..).ok_or(PacketError::InvalidIcmpInvocation)?;
        Self::parse_prefix(invoking).map(Some).map_err(|_| PacketError::InvalidIcmpInvocation)
    }
}

pub fn is_icmp_protocol(protocol: u8) -> bool {
    matches!(protocol, 1 | 58)
}

pub fn decrement_hop_limit(packet: &mut [u8]) -> Result<(), PacketError> {
    let (version, header_len, hop_limit) = match PacketView::parse(packet)? {
        PacketView::V4(view) => (4, view.header_len(), view.ttl()),
        PacketView::V6(view) => (6, view.header_len(), view.hop_limit()),
    };
    if hop_limit <= 1 {
        return Err(PacketError::HopLimitExpired);
    }
    match version {
        4 => {
            packet[8] -= 1;
            packet[10] = 0;
            packet[11] = 0;
            let checksum = ipv4::header_checksum(&packet[..header_len]);
            packet[10..12].copy_from_slice(&checksum.to_be_bytes());
        }
        6 => packet[7] -= 1,
        _ => return Err(PacketError::Version(version)),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{decrement_hop_limit, PacketError, PacketView};

    #[test]
    fn rejects_short_and_unknown_versions() {
        assert!(matches!(PacketView::parse(&[]), Err(PacketError::Truncated { .. })));
        assert!(matches!(PacketView::parse(&[0x70]), Err(PacketError::Version(7))));
    }

    #[test]
    fn decrements_ipv6_hop_limit_once() {
        let mut packet = vec![0x60, 0, 0, 0, 0, 0, 59, 64];
        packet.resize(40, 0);
        packet[24] = 1;
        assert!(decrement_hop_limit(&mut packet).is_ok());
        assert_eq!(packet[7], 63);
        assert!(decrement_hop_limit(&mut [
            0x60, 0, 0, 0, 0, 0, 59, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        ])
        .is_err());
    }

    #[test]
    fn parses_truncated_invoking_packet_from_icmp_error() {
        let inner = ipv4_packet([192, 0, 2, 1], [198, 51, 100, 1], 17, 60, 8);
        let mut outer = ipv4_packet([203, 0, 113, 1], [192, 0, 2, 1], 1, 28, 0);
        outer.extend_from_slice(&[3, 0, 0, 0, 0, 0, 0, 0]);
        outer.extend_from_slice(&inner);
        let total = outer.len() as u16;
        outer[2..4].copy_from_slice(&total.to_be_bytes());
        update_ipv4_checksum(&mut outer);

        let invoking = PacketView::parse(&outer)
            .and_then(|view| view.icmp_invoking_packet())
            .unwrap_or_else(|error| panic!("parse ICMP invocation: {error}"))
            .unwrap_or_else(|| panic!("expected ICMP error invocation"));
        assert_eq!(
            invoking.source(),
            "192.0.2.1"
                .parse::<std::net::IpAddr>()
                .unwrap_or_else(|error| panic!("parse source: {error}"))
        );
        assert_eq!(
            invoking.destination(),
            "198.51.100.1"
                .parse::<std::net::IpAddr>()
                .unwrap_or_else(|error| panic!("parse destination: {error}"))
        );
        assert_eq!(invoking.protocol(), 17);
        assert_eq!(invoking.total_len(), 60);
    }

    fn ipv4_packet(
        source: [u8; 4],
        destination: [u8; 4],
        protocol: u8,
        declared_len: u16,
        included_payload: usize,
    ) -> Vec<u8> {
        let mut packet = vec![0u8; 20 + included_payload];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&declared_len.to_be_bytes());
        packet[8] = 64;
        packet[9] = protocol;
        packet[12..16].copy_from_slice(&source);
        packet[16..20].copy_from_slice(&destination);
        update_ipv4_checksum(&mut packet);
        packet
    }

    fn update_ipv4_checksum(packet: &mut [u8]) {
        packet[10] = 0;
        packet[11] = 0;
        let checksum = super::ipv4::header_checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&checksum.to_be_bytes());
    }
}
