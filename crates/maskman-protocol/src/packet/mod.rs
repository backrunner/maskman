mod ipv4;
mod ipv6;
mod scope;

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
}

#[derive(Debug, Clone, Copy)]
pub enum PacketView<'a> {
    V4(Ipv4Packet<'a>),
    V6(Ipv6Packet<'a>),
}

impl<'a> PacketView<'a> {
    pub fn parse(input: &'a [u8]) -> Result<Self, PacketError> {
        let first = input.first().ok_or(PacketError::Truncated { needed: 1, available: 0 })?;
        let version = first >> 4;
        match version {
            4 => Ok(Self::V4(Ipv4Packet::parse(input)?)),
            6 => Ok(Self::V6(Ipv6Packet::parse(input)?)),
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
}
