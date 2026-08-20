use std::net::Ipv4Addr;

use super::PacketError;

#[derive(Debug, Clone, Copy)]
pub struct Ipv4Packet<'a> {
    bytes: &'a [u8],
    header_len: usize,
    total_len: usize,
}

impl<'a> Ipv4Packet<'a> {
    pub fn parse(input: &'a [u8]) -> Result<Self, PacketError> {
        let packet = Self::parse_prefix(input)?;
        if packet.total_len != input.len() {
            return Err(PacketError::LengthMismatch {
                declared: packet.total_len,
                actual: input.len(),
            });
        }
        Ok(packet)
    }

    pub fn parse_prefix(input: &'a [u8]) -> Result<Self, PacketError> {
        if input.len() < 20 {
            return Err(PacketError::Truncated { needed: 20, available: input.len() });
        }
        if input[0] >> 4 != 4 {
            return Err(PacketError::Version(input[0] >> 4));
        }
        let header_len = usize::from(input[0] & 0x0f) * 4;
        if !(20..=60).contains(&header_len) || header_len > input.len() {
            return Err(PacketError::InvalidHeaderLength);
        }
        let total_len = usize::from(u16::from_be_bytes([input[2], input[3]]));
        if total_len < header_len {
            return Err(PacketError::LengthMismatch { declared: total_len, actual: input.len() });
        }
        if header_checksum(&input[..header_len]) != 0 {
            return Err(PacketError::InvalidChecksum);
        }
        Ok(Self { bytes: &input[..input.len().min(total_len)], header_len, total_len })
    }

    pub fn source(self) -> Ipv4Addr {
        Ipv4Addr::new(self.bytes[12], self.bytes[13], self.bytes[14], self.bytes[15])
    }

    pub fn destination(self) -> Ipv4Addr {
        Ipv4Addr::new(self.bytes[16], self.bytes[17], self.bytes[18], self.bytes[19])
    }

    pub fn protocol(self) -> u8 {
        self.bytes[9]
    }

    pub fn ttl(self) -> u8 {
        self.bytes[8]
    }

    pub fn header_len(self) -> usize {
        self.header_len
    }

    pub fn total_len(self) -> usize {
        self.total_len
    }

    pub fn payload(self) -> &'a [u8] {
        &self.bytes[self.header_len..]
    }

    pub fn fragment_offset(self) -> u16 {
        let flags_offset = u16::from_be_bytes([self.bytes[6], self.bytes[7]]);
        (flags_offset & 0x1fff) * 8
    }

    pub fn more_fragments(self) -> bool {
        (self.bytes[6] & 0x20) != 0
    }
}

pub(crate) fn header_checksum(header: &[u8]) -> u16 {
    let mut sum = 0u32;
    for chunk in header.chunks_exact(2) {
        sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
    }
    if header.len() & 1 == 1 {
        sum += u32::from(header[header.len() - 1]) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::{header_checksum, Ipv4Packet};

    fn packet() -> Vec<u8> {
        let mut packet = vec![
            0x45, 0, 0, 24, 0, 1, 0, 0, 64, 17, 0, 0, 192, 0, 2, 1, 198, 51, 100, 1, 1, 2, 3, 4,
        ];
        let checksum = header_checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&checksum.to_be_bytes());
        packet
    }

    #[test]
    fn parses_header_and_fragment_fields() {
        let packet = packet();
        let view = Ipv4Packet::parse(&packet).unwrap_or_else(|error| panic!("parse IPv4: {error}"));
        assert_eq!(view.protocol(), 17);
        assert_eq!(view.payload(), &[1, 2, 3, 4]);
        assert_eq!(view.fragment_offset(), 0);
    }

    #[test]
    fn rejects_bad_checksum_and_length() {
        let mut invalid_checksum = packet();
        invalid_checksum[10] ^= 1;
        assert!(Ipv4Packet::parse(&invalid_checksum).is_err());

        let mut invalid_length = packet();
        invalid_length[3] = 20;
        assert!(Ipv4Packet::parse(&invalid_length).is_err());
    }
}
