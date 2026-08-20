use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use thiserror::Error;

use crate::packet::is_icmp_protocol;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressRange {
    pub start: IpAddr,
    pub end: IpAddr,
    pub protocol: u8,
}

impl AddressRange {
    pub fn contains(&self, address: IpAddr) -> bool {
        same_family(self.start, address) && self.start <= address && address <= self.end
    }

    pub fn permits(&self, address: IpAddr, protocol: u8) -> bool {
        self.contains(address)
            && (self.protocol == 0 || self.protocol == protocol || is_icmp_protocol(protocol))
    }

    pub fn overlaps(&self, other: &Self) -> bool {
        same_family(self.start, other.start) && self.start <= other.end && other.start <= self.end
    }

    pub fn conflicts_with(&self, other: &Self) -> bool {
        self.overlaps(other)
            && (self.protocol == 0 || other.protocol == 0 || self.protocol == other.protocol)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RouteAdvertisement {
    ranges: Vec<AddressRange>,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum RouteError {
    #[error("route capsule is truncated")]
    Truncated,
    #[error("route capsule has unsupported IP version {0}")]
    IpVersion(u8),
    #[error("route range has mixed IP address families")]
    MixedFamilies,
    #[error("route range start is greater than its end")]
    ReversedRange,
    #[error("route ranges are not ordered according to RFC 9484")]
    Unordered,
    #[error("route ranges overlap for the same protocol")]
    Overlap,
    #[error("route wildcard protocol overlaps another range")]
    WildcardOverlap,
    #[error("route capsule contains trailing bytes")]
    TrailingBytes,
}

impl RouteAdvertisement {
    pub fn new(ranges: Vec<AddressRange>) -> Result<Self, RouteError> {
        validate_ranges(&ranges)?;
        Ok(Self { ranges })
    }

    pub fn ranges(&self) -> &[AddressRange] {
        &self.ranges
    }

    pub fn replace(&mut self, value: &[u8]) -> Result<(), RouteError> {
        let next = decode_route_advertisement(value)?;
        self.ranges = next.ranges;
        Ok(())
    }
}

pub fn decode_route_advertisement(value: &[u8]) -> Result<RouteAdvertisement, RouteError> {
    let mut offset = 0;
    let mut ranges = Vec::new();
    while offset < value.len() {
        let version = *value.get(offset).ok_or(RouteError::Truncated)?;
        let width = match version {
            4 => 4,
            6 => 16,
            other => return Err(RouteError::IpVersion(other)),
        };
        let start_begin = offset + 1;
        let start_end = start_begin + width;
        let end_end = start_end + width;
        let protocol_offset = end_end;
        let protocol = *value.get(protocol_offset).ok_or(RouteError::Truncated)?;
        let start = decode_address(
            version,
            value.get(start_begin..start_end).ok_or(RouteError::Truncated)?,
        )?;
        let end =
            decode_address(version, value.get(start_end..end_end).ok_or(RouteError::Truncated)?)?;
        if start > end {
            return Err(RouteError::ReversedRange);
        }
        ranges.push(AddressRange { start, end, protocol });
        offset = protocol_offset + 1;
    }
    validate_ranges(&ranges)?;
    RouteAdvertisement::new(ranges)
}

pub fn encode_route_advertisement(
    advertisement: &RouteAdvertisement,
    output: &mut Vec<u8>,
) -> Result<(), RouteError> {
    validate_ranges(&advertisement.ranges)?;
    for range in &advertisement.ranges {
        match (range.start, range.end) {
            (IpAddr::V4(start), IpAddr::V4(end)) => {
                output.push(4);
                output.extend_from_slice(&start.octets());
                output.extend_from_slice(&end.octets());
            }
            (IpAddr::V6(start), IpAddr::V6(end)) => {
                output.push(6);
                output.extend_from_slice(&start.octets());
                output.extend_from_slice(&end.octets());
            }
            _ => return Err(RouteError::MixedFamilies),
        }
        output.push(range.protocol);
    }
    Ok(())
}

fn decode_address(version: u8, bytes: &[u8]) -> Result<IpAddr, RouteError> {
    match version {
        4 => Ok(IpAddr::V4(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]))),
        6 => {
            let mut address = [0; 16];
            address.copy_from_slice(bytes);
            Ok(IpAddr::V6(Ipv6Addr::from(address)))
        }
        other => Err(RouteError::IpVersion(other)),
    }
}

fn validate_ranges(ranges: &[AddressRange]) -> Result<(), RouteError> {
    for range in ranges {
        if !same_family(range.start, range.end) {
            return Err(RouteError::MixedFamilies);
        }
        if range.start > range.end {
            return Err(RouteError::ReversedRange);
        }
    }
    for pair in ranges.windows(2) {
        let previous = &pair[0];
        let current = &pair[1];
        if version(previous.start) > version(current.start)
            || (version(previous.start) == version(current.start)
                && previous.protocol > current.protocol)
        {
            return Err(RouteError::Unordered);
        }
        if same_family(previous.start, current.start)
            && previous.protocol == current.protocol
            && previous.end >= current.start
        {
            return Err(RouteError::Overlap);
        }
    }
    for family in [4u8, 6u8] {
        let wildcard: Vec<_> = ranges
            .iter()
            .filter(|range| version(range.start) == family && range.protocol == 0)
            .collect();
        for range in
            ranges.iter().filter(|range| version(range.start) == family && range.protocol != 0)
        {
            let candidate = wildcard.partition_point(|candidate| candidate.end < range.start);
            if wildcard.get(candidate).is_some_and(|candidate| candidate.start <= range.end) {
                return Err(RouteError::WildcardOverlap);
            }
        }
    }
    Ok(())
}

fn version(address: IpAddr) -> u8 {
    match address {
        IpAddr::V4(_) => 4,
        IpAddr::V6(_) => 6,
    }
}

fn same_family(start: IpAddr, end: IpAddr) -> bool {
    version(start) == version(end)
}

#[cfg(test)]
mod tests {
    use super::{
        decode_route_advertisement, encode_route_advertisement, AddressRange, RouteAdvertisement,
    };

    fn range(start: &str, end: &str, protocol: u8) -> AddressRange {
        let start =
            start.parse().unwrap_or_else(|error| panic!("parse test range start {start}: {error}"));
        let end = end.parse().unwrap_or_else(|error| panic!("parse test range end {end}: {error}"));
        AddressRange { start, end, protocol }
    }

    #[test]
    fn round_trips_ordered_ranges() {
        let advertisement = RouteAdvertisement::new(vec![
            range("192.0.2.0", "192.0.2.10", 6),
            range("192.0.2.20", "192.0.2.30", 17),
            range("2001:db8::", "2001:db8::ff", 0),
        ])
        .unwrap_or_else(|error| panic!("validate routes: {error}"));
        let mut encoded = Vec::new();
        encode_route_advertisement(&advertisement, &mut encoded)
            .unwrap_or_else(|error| panic!("encode routes: {error}"));
        assert_eq!(decode_route_advertisement(&encoded), Ok(advertisement));
    }

    #[test]
    fn rejects_overlap_order_and_wildcard_overlap() {
        assert!(RouteAdvertisement::new(vec![
            range("192.0.2.0", "192.0.2.10", 17),
            range("192.0.2.10", "192.0.2.20", 17),
        ])
        .is_err());
        assert!(RouteAdvertisement::new(vec![
            range("192.0.2.0", "192.0.2.20", 0),
            range("192.0.2.10", "192.0.2.30", 17),
        ])
        .is_err());
        assert!(RouteAdvertisement::new(vec![
            range("2001:db8::", "2001:db8::1", 6),
            range("192.0.2.0", "192.0.2.1", 6),
        ])
        .is_err());
    }

    #[test]
    fn empty_advertisement_withdraws_all_routes() {
        let empty =
            decode_route_advertisement(&[]).unwrap_or_else(|error| panic!("decode empty: {error}"));
        assert!(empty.ranges().is_empty());
    }

    #[test]
    fn scoped_routes_always_permit_icmp() {
        let route = range("192.0.2.0", "192.0.2.255", 17);
        let destination = "192.0.2.42".parse().unwrap_or_else(|error| panic!("parse IP: {error}"));
        assert!(route.permits(destination, 17));
        assert!(route.permits(destination, 1));
        assert!(route.permits(destination, 58));
        assert!(!route.permits(destination, 6));
    }

    #[test]
    fn different_protocol_routes_can_share_an_address_range() {
        let first = range("192.0.2.0", "192.0.2.255", 6);
        let second = range("192.0.2.0", "192.0.2.255", 17);
        assert!(first.overlaps(&second));
        assert!(!first.conflicts_with(&second));
    }
}
