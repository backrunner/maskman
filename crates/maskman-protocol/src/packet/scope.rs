use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressClass {
    Global,
    Unspecified,
    Loopback,
    Private,
    Shared,
    LinkLocal,
    Multicast,
    Documentation,
    Reserved,
    Broadcast,
}

pub fn classify_address(address: IpAddr) -> AddressClass {
    match address {
        IpAddr::V4(address) => classify_v4(address),
        IpAddr::V6(address) => classify_v6(address),
    }
}

impl AddressClass {
    pub fn is_default_denied(self) -> bool {
        !matches!(self, Self::Global)
    }
}

fn classify_v4(address: Ipv4Addr) -> AddressClass {
    let value = u32::from(address);
    if value == u32::from(Ipv4Addr::BROADCAST) {
        return AddressClass::Broadcast;
    }
    if address.is_unspecified() {
        return AddressClass::Unspecified;
    }
    if address.is_loopback() {
        return AddressClass::Loopback;
    }
    if address.is_private() || in_range(value, 0xC0A8_0000, 0xFFFF_0000) {
        return AddressClass::Private;
    }
    if in_range(value, 0x6440_0000, 0xFFC0_0000) {
        return AddressClass::Shared;
    }
    if address.is_link_local() {
        return AddressClass::LinkLocal;
    }
    if address.is_multicast() {
        return AddressClass::Multicast;
    }
    if in_range(value, 0xC000_0000, 0xFFFF_FF00)
        || in_range(value, 0xC000_0200, 0xFFFF_FF00)
        || in_range(value, 0xC633_6400, 0xFFFF_FF00)
        || in_range(value, 0xCB00_7100, 0xFFFF_FF00)
    {
        return AddressClass::Documentation;
    }
    if in_range(value, 0x0000_0000, 0xFF00_0000)
        || in_range(value, 0xC612_0000, 0xFFFE_0000)
        || value >= 0xF000_0000
    {
        return AddressClass::Reserved;
    }
    AddressClass::Global
}

fn classify_v6(address: Ipv6Addr) -> AddressClass {
    let value = u128::from(address);
    if value == 0 {
        return AddressClass::Unspecified;
    }
    if value == 1 {
        return AddressClass::Loopback;
    }
    if prefix(value, 0x7e, 7) || prefix(value, 0x3fa, 10) {
        return if prefix(value, 0x3fa, 10) {
            AddressClass::LinkLocal
        } else {
            AddressClass::Private
        };
    }
    if prefix(value, 0xff, 8) {
        return AddressClass::Multicast;
    }
    if prefix(value, 0x2001_0db8, 32) {
        return AddressClass::Documentation;
    }
    if prefix(value, 0, 96) || prefix(value, 0xffff, 96) {
        return AddressClass::Reserved;
    }
    if prefix(value, 0x10_0080, 23) || prefix(value, 0x2002, 16) {
        return AddressClass::Reserved;
    }
    if prefix(value, 0x1, 3) {
        return AddressClass::Global;
    }
    AddressClass::Reserved
}

fn in_range(value: u32, base: u32, mask: u32) -> bool {
    value & mask == base & mask
}

fn prefix(value: u128, base: u128, bits: u8) -> bool {
    if bits == 0 {
        return true;
    }
    let shift = 128 - u32::from(bits);
    (value >> shift) == base
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use super::{classify_address, AddressClass};

    fn ip(value: &str) -> IpAddr {
        value.parse().unwrap_or_else(|error| panic!("parse test address {value}: {error}"))
    }

    #[test]
    fn denies_special_v4_and_v6_ranges_by_default() {
        for address in ["127.0.0.1", "10.0.0.1", "169.254.1.1", "224.0.0.1", "255.255.255.255"] {
            assert!(classify_address(ip(address)).is_default_denied());
        }
        assert_eq!(classify_address(ip("8.8.8.8")), AddressClass::Global);
        assert!(classify_address(ip("fc00::1")).is_default_denied());
        assert!(classify_address(ip("fe80::1")).is_default_denied());
        assert!(classify_address(ip("ff02::1")).is_default_denied());
        assert!(classify_address(ip("2001:db8::1")).is_default_denied());
        assert!(classify_address(ip("2002::1")).is_default_denied());
        assert!(classify_address(ip("4000::1")).is_default_denied());
    }

    #[test]
    fn accepts_global_addresses() {
        assert_eq!(classify_address(IpAddr::from([200, 1, 1, 1])), AddressClass::Global);
        assert_eq!(classify_address(ip("2001:4860:4860::8888")), AddressClass::Global);
        assert_eq!(classify_address(ip("2606:4700:4700::1111")), AddressClass::Global);
    }
}
