use std::net::Ipv6Addr;

use super::PacketError;

pub const MAX_EXTENSION_HEADERS: usize = 8;

#[derive(Debug, Clone, Copy)]
pub struct Ipv6Packet<'a> {
    bytes: &'a [u8],
    header_len: usize,
    total_len: usize,
    protocol: u8,
    fragment_seen: bool,
}

impl<'a> Ipv6Packet<'a> {
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
        if input.len() < 40 {
            return Err(PacketError::Truncated { needed: 40, available: input.len() });
        }
        if input[0] >> 4 != 6 {
            return Err(PacketError::Version(input[0] >> 4));
        }
        let payload_length = usize::from(u16::from_be_bytes([input[4], input[5]]));
        let total_len = 40usize
            .checked_add(payload_length)
            .ok_or(PacketError::LengthMismatch { declared: usize::MAX, actual: input.len() })?;
        let available = input.len().min(total_len);
        let mut offset = 40;
        let mut next_header = input[6];
        let mut extension_count = 0;
        let mut fragment_seen = false;
        while is_extension_header(next_header) {
            if extension_count == MAX_EXTENSION_HEADERS {
                return Err(PacketError::TooManyExtensions);
            }
            if next_header == 0 && offset != 40 {
                return Err(PacketError::InvalidExtensionOrder);
            }
            let length = extension_length(next_header, input, offset)?;
            let end = offset.checked_add(length).ok_or(PacketError::InvalidExtensionLength)?;
            if end > available || length == 0 {
                return Err(PacketError::InvalidExtensionLength);
            }
            if next_header == 44 {
                if fragment_seen {
                    return Err(PacketError::DuplicateExtension);
                }
                fragment_seen = true;
            }
            next_header = input[offset];
            offset = end;
            extension_count += 1;
        }
        Ok(Self {
            bytes: &input[..available],
            header_len: offset,
            total_len,
            protocol: next_header,
            fragment_seen,
        })
    }

    pub fn source(self) -> Ipv6Addr {
        let mut bytes = [0; 16];
        bytes.copy_from_slice(&self.bytes[8..24]);
        Ipv6Addr::from(bytes)
    }

    pub fn destination(self) -> Ipv6Addr {
        let mut bytes = [0; 16];
        bytes.copy_from_slice(&self.bytes[24..40]);
        Ipv6Addr::from(bytes)
    }

    pub fn protocol(self) -> u8 {
        self.protocol
    }

    pub fn hop_limit(self) -> u8 {
        self.bytes[7]
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

    pub fn has_fragment_header(self) -> bool {
        self.fragment_seen
    }
}

fn is_extension_header(next_header: u8) -> bool {
    matches!(next_header, 0 | 43 | 44 | 60 | 51 | 135 | 139 | 140)
}

fn extension_length(next_header: u8, input: &[u8], offset: usize) -> Result<usize, PacketError> {
    match next_header {
        44 => Ok(8),
        51 => {
            let length = *input
                .get(offset + 1)
                .ok_or(PacketError::Truncated { needed: offset + 2, available: input.len() })?;
            Ok((usize::from(length) + 2) * 4)
        }
        _ => {
            let length = *input
                .get(offset + 1)
                .ok_or(PacketError::Truncated { needed: offset + 2, available: input.len() })?;
            Ok((usize::from(length) + 1) * 8)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Ipv6Packet;

    fn base(next_header: u8, payload_length: usize) -> Vec<u8> {
        let mut packet =
            vec![0x60, 0, 0, 0, (payload_length >> 8) as u8, payload_length as u8, next_header, 64];
        packet.resize(40 + payload_length, 0);
        packet
    }

    #[test]
    fn walks_hop_by_hop_and_destination_headers() {
        let mut packet = base(0, 16);
        packet[40] = 60;
        packet[41] = 0;
        packet[48] = 17;
        packet[49] = 0;
        let view = Ipv6Packet::parse(&packet).unwrap_or_else(|error| panic!("parse IPv6: {error}"));
        assert_eq!(view.protocol(), 17);
        assert_eq!(view.header_len(), 56);
    }

    #[test]
    fn rejects_extension_chain_overflow_and_bad_order() {
        let mut packet = base(0, 8);
        packet[40] = 0;
        packet[41] = 0;
        assert!(Ipv6Packet::parse(&packet).is_err());
        let mut packet = base(17, 0);
        let protocol = Ipv6Packet::parse(&packet)
            .unwrap_or_else(|error| panic!("parse test packet: {error}"))
            .protocol();
        assert_eq!(protocol, 17);
        packet[6] = 0;
        assert!(Ipv6Packet::parse(&packet).is_err());
    }
}
