use std::{
    collections::HashSet,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use ipnet::IpNet;
use thiserror::Error;

use crate::varint::{self, VarIntError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssignedAddress {
    pub request_id: u64,
    pub prefix: IpNet,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestedAddress {
    pub request_id: u64,
    pub prefix: IpNet,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum AddressError {
    #[error("address capsule varint is invalid: {0}")]
    VarInt(#[from] VarIntError),
    #[error("address capsule is truncated")]
    Truncated,
    #[error("address capsule has unsupported IP version {0}")]
    IpVersion(u8),
    #[error("address capsule prefix length {prefix} exceeds {bits} bits")]
    PrefixLength { prefix: u8, bits: u8 },
    #[error("address capsule has host bits set outside its prefix")]
    HostBitsSet,
    #[error("ADDRESS_REQUEST request ID must not be zero")]
    ZeroRequestId,
    #[error("ADDRESS_REQUEST request ID {0} is repeated")]
    DuplicateRequestId(u64),
    #[error("address capsule contains too many entries")]
    TooManyEntries,
    #[error("ADDRESS_REQUEST capsule must contain at least one address")]
    EmptyRequest,
    #[error("address capsule contains trailing bytes")]
    TrailingBytes,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AddressAssignments {
    entries: Vec<AssignedAddress>,
}

impl AddressAssignments {
    pub fn entries(&self) -> &[AssignedAddress] {
        &self.entries
    }

    pub fn replace(&mut self, value: &[u8]) -> Result<(), AddressError> {
        let next = decode_address_assign(value)?;
        self.entries = next;
        Ok(())
    }
}

pub fn decode_address_assign(value: &[u8]) -> Result<Vec<AssignedAddress>, AddressError> {
    let mut offset = 0;
    let mut entries = Vec::new();
    while offset < value.len() {
        let (request_id, consumed) = decode_varint_at(value, offset)?;
        offset += consumed;
        let (prefix, consumed) = decode_prefix(value, offset)?;
        offset += consumed;
        entries.push(AssignedAddress { request_id, prefix });
        if entries.len() > 256 {
            return Err(AddressError::TooManyEntries);
        }
    }
    Ok(entries)
}

pub fn decode_address_request(value: &[u8]) -> Result<Vec<RequestedAddress>, AddressError> {
    let mut offset = 0;
    let mut entries = Vec::new();
    let mut request_ids = HashSet::new();
    while offset < value.len() {
        let (request_id, consumed) = decode_varint_at(value, offset)?;
        offset += consumed;
        if request_id == 0 {
            return Err(AddressError::ZeroRequestId);
        }
        if !request_ids.insert(request_id) {
            return Err(AddressError::DuplicateRequestId(request_id));
        }
        let (prefix, consumed) = decode_prefix(value, offset)?;
        offset += consumed;
        entries.push(RequestedAddress { request_id, prefix });
        if entries.len() > 256 {
            return Err(AddressError::TooManyEntries);
        }
    }
    if entries.is_empty() {
        return Err(AddressError::EmptyRequest);
    }
    Ok(entries)
}

pub fn encode_address_assign(
    entries: &[AssignedAddress],
    output: &mut Vec<u8>,
) -> Result<(), AddressError> {
    encode_entries(entries.iter().map(|entry| (entry.request_id, &entry.prefix)), output)
}

pub fn encode_address_request(
    entries: &[RequestedAddress],
    output: &mut Vec<u8>,
) -> Result<(), AddressError> {
    if entries.is_empty() {
        return Err(AddressError::EmptyRequest);
    }
    let mut ids = HashSet::new();
    for entry in entries {
        if entry.request_id == 0 {
            return Err(AddressError::ZeroRequestId);
        }
        if !ids.insert(entry.request_id) {
            return Err(AddressError::DuplicateRequestId(entry.request_id));
        }
    }
    encode_entries(entries.iter().map(|entry| (entry.request_id, &entry.prefix)), output)
}

fn encode_entries<'a, I>(entries: I, output: &mut Vec<u8>) -> Result<(), AddressError>
where
    I: IntoIterator<Item = (u64, &'a IpNet)>,
{
    let mut encoded = [0; 8];
    let mut count = 0;
    for (request_id, prefix) in entries {
        count += 1;
        if count > 256 {
            return Err(AddressError::TooManyEntries);
        }
        let length = varint::encode(request_id, &mut encoded)?;
        output.extend_from_slice(&encoded[..length]);
        encode_prefix(prefix, output)?;
    }
    Ok(())
}

fn decode_varint_at(input: &[u8], offset: usize) -> Result<(u64, usize), AddressError> {
    varint::decode(input.get(offset..).ok_or(AddressError::Truncated)?).map_err(Into::into)
}

fn decode_prefix(input: &[u8], offset: usize) -> Result<(IpNet, usize), AddressError> {
    let version = *input.get(offset).ok_or(AddressError::Truncated)?;
    let bits = match version {
        4 => 32,
        6 => 128,
        value => return Err(AddressError::IpVersion(value)),
    };
    let address_start = offset + 1;
    let address_end = address_start + bits as usize / 8;
    let address_bytes = input.get(address_start..address_end).ok_or(AddressError::Truncated)?;
    let prefix = *input.get(address_end).ok_or(AddressError::Truncated)?;
    if prefix > bits {
        return Err(AddressError::PrefixLength { prefix, bits });
    }
    let address = if version == 4 {
        IpAddr::V4(Ipv4Addr::new(
            address_bytes[0],
            address_bytes[1],
            address_bytes[2],
            address_bytes[3],
        ))
    } else {
        let mut bytes = [0; 16];
        bytes.copy_from_slice(address_bytes);
        IpAddr::V6(Ipv6Addr::from(bytes))
    };
    let network =
        IpNet::new(address, prefix).map_err(|_| AddressError::PrefixLength { prefix, bits })?;
    if network.network() != address {
        return Err(AddressError::HostBitsSet);
    }
    Ok((network, 1 + address_bytes.len() + 1))
}

fn encode_prefix(prefix: &IpNet, output: &mut Vec<u8>) -> Result<(), AddressError> {
    match prefix {
        IpNet::V4(network) => {
            output.push(4);
            output.extend_from_slice(&network.addr().octets());
            output.push(network.prefix_len());
        }
        IpNet::V6(network) => {
            output.push(6);
            output.extend_from_slice(&network.addr().octets());
            output.push(network.prefix_len());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use ipnet::IpNet;

    use super::{
        decode_address_assign, decode_address_request, encode_address_assign,
        encode_address_request, AddressAssignments, AssignedAddress, RequestedAddress,
    };

    fn net(value: &str) -> IpNet {
        value.parse().unwrap_or_else(|error| panic!("parse test network {value}: {error}"))
    }

    #[test]
    fn assignment_round_trip_and_replace_is_atomic() {
        let entry = AssignedAddress { request_id: 0, prefix: net("192.0.2.0/24") };
        let mut encoded = Vec::new();
        encode_address_assign(std::slice::from_ref(&entry), &mut encoded)
            .unwrap_or_else(|error| panic!("encode assignment: {error}"));
        assert_eq!(decode_address_assign(&encoded), Ok(vec![entry.clone()]));
        let mut state = AddressAssignments::default();
        state.replace(&encoded).unwrap_or_else(|error| panic!("replace: {error}"));
        assert_eq!(state.entries(), &[entry]);
        assert!(state.replace(&[4, 192, 0]).is_err());
        assert_eq!(
            state.entries(),
            &[AssignedAddress { request_id: 0, prefix: net("192.0.2.0/24") }]
        );
    }

    #[test]
    fn request_requires_nonzero_unique_ids_and_aligned_prefixes() {
        let entries = vec![RequestedAddress { request_id: 1, prefix: net("2001:db8::/32") }];
        let mut encoded = Vec::new();
        encode_address_request(&entries, &mut encoded)
            .unwrap_or_else(|error| panic!("encode request: {error}"));
        assert_eq!(decode_address_request(&encoded), Ok(entries));
        assert!(decode_address_request(&[]).is_err());
        assert!(decode_address_request(&[0]).is_err());
        assert!(decode_address_request(&[1, 4, 192, 0, 2, 1, 24]).is_err());
    }

    #[test]
    fn supports_empty_assignment_and_exact_ip_widths() {
        assert_eq!(decode_address_assign(&[]), Ok(Vec::new()));
        let v4 = net("198.51.100.1/32");
        let mut encoded = Vec::new();
        encode_address_assign(&[AssignedAddress { request_id: 2, prefix: v4 }], &mut encoded)
            .unwrap_or_else(|error| panic!("encode v4: {error}"));
        assert_eq!(encoded.len(), 1 + 1 + 4 + 1);
    }
}
