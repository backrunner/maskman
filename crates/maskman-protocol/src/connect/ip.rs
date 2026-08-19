use std::net::IpAddr;

use ipnet::IpNet;

use super::{
    decode_segment, decode_wildcard, endpoint_segments, parse_decimal, reject_literal,
    require_segment_count, validate_name, PathError,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpTarget {
    Any,
    Prefix(IpNet),
    Name(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpProtocolScope {
    Any,
    Number(u8),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpScope {
    pub target: IpTarget,
    pub protocol: IpProtocolScope,
}

pub fn parse_ip_path(path: &str, base_path: &str) -> Result<IpScope, PathError> {
    let segments = require_segment_count(endpoint_segments(path, base_path, "ip")?, 2, "ip")?;
    let target = parse_target(segments[0])?;
    let protocol = parse_protocol(segments[1])?;
    Ok(IpScope { target, protocol })
}

fn parse_target(raw: &str) -> Result<IpTarget, PathError> {
    reject_literal(raw, ':', "target")?;
    let decoded = decode_wildcard(raw, decode_segment(raw, "target")?, "target")?;
    if decoded == "*" {
        return Ok(IpTarget::Any);
    }
    if decoded.contains('/') {
        let pieces: Vec<_> = decoded.split('/').collect();
        if pieces.len() != 2 {
            return Err(PathError::InvalidValue { field: "target", value: decoded });
        }
        let address = parse_address(pieces[0])?;
        let prefix =
            parse_decimal(pieces[1], "target prefix", 0, address_bits(address) as u64)? as u8;
        return Ok(IpTarget::Prefix(prefix_from_address(address, prefix)?));
    }
    if let Ok(address) = decoded.parse::<IpAddr>() {
        return Ok(IpTarget::Prefix(prefix_from_address(address, address_bits(address))?));
    }
    validate_name(&decoded, "target")?;
    Ok(IpTarget::Name(decoded))
}

fn parse_protocol(raw: &str) -> Result<IpProtocolScope, PathError> {
    let decoded = decode_wildcard(raw, decode_segment(raw, "ipproto")?, "ipproto")?;
    if decoded == "*" {
        return Ok(IpProtocolScope::Any);
    }
    Ok(IpProtocolScope::Number(parse_decimal(&decoded, "ipproto", 0, u8::MAX as u64)? as u8))
}

fn parse_address(value: &str) -> Result<IpAddr, PathError> {
    value
        .parse()
        .map_err(|_| PathError::InvalidValue { field: "target address", value: value.to_owned() })
}

fn address_bits(address: IpAddr) -> u8 {
    match address {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    }
}

fn prefix_from_address(address: IpAddr, prefix: u8) -> Result<IpNet, PathError> {
    let network = IpNet::new(address, prefix).map_err(|_| PathError::InvalidValue {
        field: "target prefix",
        value: prefix.to_string(),
    })?;
    if network.network() != address {
        return Err(PathError::InvalidValue { field: "target prefix", value: address.to_string() });
    }
    Ok(network)
}

#[cfg(test)]
mod tests {
    use ipnet::IpNet;

    use super::{parse_ip_path, IpProtocolScope, IpScope, IpTarget};

    #[test]
    fn parses_wildcards_only_when_percent_encoded() {
        let scope = parse_ip_path("/.well-known/masque/ip/%2A/%2A/", "/.well-known/masque")
            .unwrap_or_else(|error| panic!("parse wildcard scope: {error}"));
        assert_eq!(scope, IpScope { target: IpTarget::Any, protocol: IpProtocolScope::Any });
        assert!(parse_ip_path("/.well-known/masque/ip/*/%2A/", "/.well-known/masque",).is_err());
    }

    #[test]
    fn parses_ipv6_prefix_and_protocol() {
        let scope = parse_ip_path(
            "/.well-known/masque/ip/2001%3Adb8%3A%3A%2F32/17/",
            "/.well-known/masque",
        )
        .unwrap_or_else(|error| panic!("parse IPv6 scope: {error}"));
        let expected = "2001:db8::/32"
            .parse::<IpNet>()
            .unwrap_or_else(|error| panic!("parse test prefix: {error}"));
        assert_eq!(scope.target, IpTarget::Prefix(expected));
        assert_eq!(scope.protocol, IpProtocolScope::Number(17));
    }

    #[test]
    fn rejects_nonzero_host_bits_and_bad_protocol() {
        assert!(
            parse_ip_path("/.well-known/masque/ip/192.0.2.1%2F24/%2A/", "/.well-known/masque",)
                .is_err()
        );
        assert!(parse_ip_path("/.well-known/masque/ip/%2A/256/", "/.well-known/masque",).is_err());
    }
}
