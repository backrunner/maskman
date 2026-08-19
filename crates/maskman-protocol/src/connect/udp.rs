use std::net::IpAddr;

use super::{
    decode_segment, endpoint_segments, reject_literal, require_segment_count, validate_name,
    PathError,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetHost {
    Ip(IpAddr),
    Name(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpTarget {
    pub host: TargetHost,
    pub port: u16,
}

pub fn parse_udp_path(path: &str, base_path: &str) -> Result<UdpTarget, PathError> {
    let segments = require_segment_count(endpoint_segments(path, base_path, "udp")?, 2, "udp")?;
    reject_literal(segments[0], ':', "target_host")?;
    let host = decode_host(segments[0])?;
    let port = decode_segment(segments[1], "target_port")?;
    let port = super::parse_decimal(&port, "target_port", 1, u16::MAX as u64)? as u16;
    Ok(UdpTarget { host, port })
}

fn decode_host(raw: &str) -> Result<TargetHost, PathError> {
    let decoded = decode_segment(raw, "target_host")?;
    if decoded.is_empty() || decoded.contains('/') {
        return Err(PathError::InvalidValue { field: "target_host", value: decoded });
    }
    if let Ok(address) = decoded.parse::<IpAddr>() {
        return Ok(TargetHost::Ip(address));
    }
    validate_name(&decoded, "target_host")?;
    Ok(TargetHost::Name(decoded))
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv6Addr};

    use super::{parse_udp_path, TargetHost};

    #[test]
    fn parses_dns_and_port() {
        let target =
            parse_udp_path("/.well-known/masque/udp/example.com/443/", "/.well-known/masque")
                .unwrap_or_else(|error| panic!("parse UDP target: {error}"));
        assert_eq!(target.host, TargetHost::Name("example.com".into()));
        assert_eq!(target.port, 443);
    }

    #[test]
    fn decodes_percent_encoded_ipv6_and_rejects_literal_colon() {
        let target =
            parse_udp_path("/.well-known/masque/udp/2001%3Adb8%3A%3A1/53/", "/.well-known/masque")
                .unwrap_or_else(|error| panic!("parse IPv6 target: {error}"));
        assert_eq!(
            target.host,
            TargetHost::Ip(IpAddr::V6(Ipv6Addr::from([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1])))
        );
        assert!(parse_udp_path("/.well-known/masque/udp/2001:db8::1/53/", "/.well-known/masque",)
            .is_err());
    }

    #[test]
    fn rejects_empty_and_invalid_ports() {
        assert!(parse_udp_path("/.well-known/masque/udp//53/", "/.well-known/masque").is_err());
        assert!(parse_udp_path(
            "/.well-known/masque/udp/example.com/65536/",
            "/.well-known/masque",
        )
        .is_err());
    }
}
