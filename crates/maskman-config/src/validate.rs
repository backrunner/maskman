use std::{collections::HashSet, net::SocketAddr, path::Path};

use ipnet::IpNet;
use thiserror::Error;

use crate::model::{AuthMode, ConfigDocument, NatMode};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DurationError {
    InvalidFormat,
    InvalidNumber,
    Overflow,
}

impl std::fmt::Display for DurationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidFormat => "expected a number followed by ms, s, m, or h",
            Self::InvalidNumber => "duration number is invalid",
            Self::Overflow => "duration is too large",
        })
    }
}

impl std::error::Error for DurationError {}

#[derive(Debug, Error)]
pub enum ValidationError {
    #[error("schema_version must be 1, got {0}")]
    SchemaVersion(u32),
    #[error("server.listen must contain at least one address")]
    EmptyListen,
    #[error("server.listen[{index}] is invalid: {value}")]
    Listen { index: usize, value: String },
    #[error("server.listen[{index}] must use a non-zero port")]
    ZeroPort { index: usize },
    #[error("server.base_path must be an absolute path without query or fragment: {0}")]
    BasePath(String),
    #[error("{0} must not be empty")]
    EmptyField(&'static str),
    #[error("{field} is invalid: {value}")]
    InvalidDuration { field: &'static str, value: String },
    #[error("{0} must be greater than zero")]
    ZeroLimit(&'static str),
    #[error("server.max_header_bytes is too large")]
    HeaderLimit,
    #[error("duplicate {kind} id: {id}")]
    DuplicateId { kind: &'static str, id: String },
    #[error("principal {principal} references missing role {role}")]
    MissingRole { principal: String, role: String },
    #[error("bearer token {token} references missing principal {principal}")]
    MissingPrincipal { token: String, principal: String },
    #[error("bearer token {token} has an invalid SHA-256 value")]
    TokenHash { token: String },
    #[error("principal {principal} has an invalid certificate SHA-256 value")]
    CertificateHash { principal: String },
    #[error("mTLS authentication requires tls.client_ca_file")]
    MissingClientCa,
    #[error("mTLS authentication requires at least one principal certificate SHA-256 mapping")]
    MissingCertificatePrincipal,
    #[error("bearer token {token} has an invalid expiry: {value}")]
    TokenExpiry { token: String, value: String },
    #[error("role {role} contains unsupported capability {capability}")]
    Capability { role: String, capability: String },
    #[error("role {role} has no destination allow rule")]
    EmptyAllowDestinations { role: String },
    #[error("role {role} has invalid destination prefix {value}")]
    Destination { role: String, value: String },
    #[error("role {role} has invalid IP protocol {value}")]
    IpProtocol { role: String, value: String },
    #[error("proxy.udp.max_payload_bytes must be between 1 and 65527")]
    UdpPayload,
    #[error("proxy.udp.socket_idle_timeout must be at least 2m when CONNECT-UDP is enabled")]
    UdpIdleTimeout,
    #[error("proxy.ip.mtu must be at least 1280 for IPv6-capable IP proxying")]
    IpMtu,
    #[error("proxy.ip pool {field} is invalid: {value}")]
    IpPool { field: &'static str, value: String },
    #[error("proxy.ip requires at least one client address pool when enabled")]
    IpPoolRequired,
    #[error("proxy.ip pools overlap: {left} and {right}")]
    OverlappingPools { left: String, right: String },
    #[error("proxy.ip advertise routes are unordered or overlapping")]
    AdvertiseRoutes,
    #[error("proxy.ip.nat managed mode requires a non-empty egress_interface")]
    NatInterface,
    #[error("observability.metrics_listen is invalid: {0}")]
    MetricsListen(String),
}

pub fn validate(document: &ConfigDocument) -> Result<(), ValidationError> {
    if document.schema_version != 1 {
        return Err(ValidationError::SchemaVersion(document.schema_version));
    }
    if document.server.listen.is_empty() {
        return Err(ValidationError::EmptyListen);
    }
    for (index, value) in document.server.listen.iter().enumerate() {
        let address = value
            .parse::<SocketAddr>()
            .map_err(|_| ValidationError::Listen { index, value: value.clone() })?;
        if address.port() == 0 {
            return Err(ValidationError::ZeroPort { index });
        }
    }
    if !document.server.base_path.starts_with('/')
        || document.server.base_path.contains(['?', '#'])
        || document.server.base_path.contains("//")
        || document.server.base_path.contains("%2f")
        || document.server.base_path.contains("%2F")
    {
        return Err(ValidationError::BasePath(document.server.base_path.clone()));
    }
    check_non_empty("tls.certificate_file", &document.tls.certificate_file)?;
    check_non_empty("tls.private_key_file", &document.tls.private_key_file)?;
    check_non_empty("server.state_dir", &document.server.state_dir)?;
    check_duration("server.idle_timeout", &document.server.idle_timeout)?;
    check_duration("server.drain_timeout", &document.server.drain_timeout)?;
    check_duration("proxy.udp.socket_idle_timeout", &document.proxy.udp.socket_idle_timeout)?;
    check_duration("update.check_interval", &document.update.check_interval)?;
    if document.server.max_connections == 0 {
        return Err(ValidationError::ZeroLimit("server.max_connections"));
    }
    if document.server.max_requests_per_connection == 0 {
        return Err(ValidationError::ZeroLimit("server.max_requests_per_connection"));
    }
    if document.server.max_header_bytes == 0 {
        return Err(ValidationError::ZeroLimit("server.max_header_bytes"));
    }
    if document.server.max_header_bytes > 1024 * 1024 {
        return Err(ValidationError::HeaderLimit);
    }
    validate_auth(document)?;
    validate_policy(document)?;
    validate_udp(document)?;
    validate_ip(document)?;
    document.observability.metrics_listen.parse::<SocketAddr>().map_err(|_| {
        ValidationError::MetricsListen(document.observability.metrics_listen.clone())
    })?;
    Ok(())
}

pub fn resolve_path(base: &Path, value: &str) -> std::path::PathBuf {
    let path = Path::new(value);
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    }
}

fn validate_auth(document: &ConfigDocument) -> Result<(), ValidationError> {
    let mut principals = HashSet::new();
    for principal in &document.auth.principals {
        if !principals.insert(&principal.id) {
            return Err(ValidationError::DuplicateId {
                kind: "principal",
                id: principal.id.clone(),
            });
        }
        for digest in &principal.certificate_sha256 {
            if digest.len() != 64 || !digest.chars().all(|character| character.is_ascii_hexdigit())
            {
                return Err(ValidationError::CertificateHash { principal: principal.id.clone() });
            }
        }
    }
    let mut roles = HashSet::new();
    for role in &document.policy.roles {
        if !roles.insert(&role.name) {
            return Err(ValidationError::DuplicateId { kind: "role", id: role.name.clone() });
        }
    }
    for principal in &document.auth.principals {
        for role in &principal.roles {
            if !roles.contains(role) {
                return Err(ValidationError::MissingRole {
                    principal: principal.id.clone(),
                    role: role.clone(),
                });
            }
        }
    }
    let mut tokens = HashSet::new();
    for token in &document.auth.bearer_tokens {
        if !tokens.insert(&token.id) {
            return Err(ValidationError::DuplicateId {
                kind: "bearer token",
                id: token.id.clone(),
            });
        }
        if !principals.contains(&token.principal) {
            return Err(ValidationError::MissingPrincipal {
                token: token.id.clone(),
                principal: token.principal.clone(),
            });
        }
        if token.secret_sha256.len() != 64
            || !token.secret_sha256.chars().all(|character| character.is_ascii_hexdigit())
        {
            return Err(ValidationError::TokenHash { token: token.id.clone() });
        }
        if let Some(expiry) = &token.expires_at {
            time::OffsetDateTime::parse(expiry, &time::format_description::well_known::Rfc3339)
                .map_err(|_| ValidationError::TokenExpiry {
                    token: token.id.clone(),
                    value: expiry.clone(),
                })?;
        }
    }
    if document.auth.required && matches!(document.auth.mode, AuthMode::None) {
        return Err(ValidationError::EmptyField("auth.mode when auth.required is true"));
    }
    validate_mtls(document)
}

fn validate_mtls(document: &ConfigDocument) -> Result<(), ValidationError> {
    let uses_mtls = matches!(document.auth.mode, AuthMode::Mtls | AuthMode::BearerOrMtls);
    if uses_mtls
        && document.tls.client_ca_file.as_deref().is_none_or(|value| value.trim().is_empty())
    {
        return Err(ValidationError::MissingClientCa);
    }
    if uses_mtls
        && document.auth.principals.iter().all(|principal| principal.certificate_sha256.is_empty())
    {
        return Err(ValidationError::MissingCertificatePrincipal);
    }
    Ok(())
}

fn validate_udp(document: &ConfigDocument) -> Result<(), ValidationError> {
    if !document.proxy.udp.enabled {
        return Ok(());
    }
    if parse_duration(&document.proxy.udp.socket_idle_timeout)
        .is_ok_and(|duration| duration < std::time::Duration::from_secs(120))
    {
        return Err(ValidationError::UdpIdleTimeout);
    }
    if document.proxy.udp.max_payload_bytes == 0 || document.proxy.udp.max_payload_bytes > 65_527 {
        return Err(ValidationError::UdpPayload);
    }
    Ok(())
}

fn validate_policy(document: &ConfigDocument) -> Result<(), ValidationError> {
    for role in &document.policy.roles {
        if role.allow_destinations.is_empty() {
            return Err(ValidationError::EmptyAllowDestinations { role: role.name.clone() });
        }
        for capability in &role.capabilities {
            if capability != "connect-ip" && capability != "connect-udp" {
                return Err(ValidationError::Capability {
                    role: role.name.clone(),
                    capability: capability.clone(),
                });
            }
        }
        for value in role.allow_destinations.iter().chain(&role.deny_destinations) {
            value.parse::<IpNet>().map_err(|_| ValidationError::Destination {
                role: role.name.clone(),
                value: value.clone(),
            })?;
        }
        for value in &role.allowed_ip_protocols {
            if value != "*" && value.parse::<u8>().is_err() {
                return Err(ValidationError::IpProtocol {
                    role: role.name.clone(),
                    value: value.clone(),
                });
            }
        }
        if role.limits.active_tunnels == 0
            || role.limits.new_tunnels_per_minute == 0
            || role.limits.ingress_bytes_per_second == 0
            || role.limits.egress_bytes_per_second == 0
            || role.limits.burst_bytes == 0
        {
            return Err(ValidationError::ZeroLimit("policy role limits"));
        }
    }
    Ok(())
}

fn validate_ip(document: &ConfigDocument) -> Result<(), ValidationError> {
    if !document.proxy.ip.enabled {
        return Ok(());
    }
    if document.proxy.ip.mtu < 1_280 {
        return Err(ValidationError::IpMtu);
    }
    let mut pools = Vec::new();
    for (field, value) in [
        ("proxy.ip.client_ipv4_pool", document.proxy.ip.client_ipv4_pool.as_deref()),
        ("proxy.ip.client_ipv6_pool", document.proxy.ip.client_ipv6_pool.as_deref()),
    ] {
        if let Some(value) = value {
            let network = value
                .parse::<IpNet>()
                .map_err(|_| ValidationError::IpPool { field, value: value.to_owned() })?;
            pools.push((field, network));
        }
    }
    if pools.is_empty() {
        return Err(ValidationError::IpPoolRequired);
    }
    for (index, (_, left)) in pools.iter().enumerate() {
        for (_, right) in pools.iter().skip(index + 1) {
            if left.contains(&right.network()) || right.contains(&left.network()) {
                return Err(ValidationError::OverlappingPools {
                    left: left.to_string(),
                    right: right.to_string(),
                });
            }
        }
    }
    if matches!(document.proxy.ip.nat.mode, NatMode::Managed)
        && document.proxy.ip.nat.egress_interface.trim().is_empty()
    {
        return Err(ValidationError::NatInterface);
    }
    let routes = document
        .proxy
        .ip
        .advertise_routes
        .iter()
        .map(|route| {
            route.parse::<IpNet>().map_err(|_| ValidationError::IpPool {
                field: "proxy.ip.advertise_routes",
                value: route.clone(),
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    for pair in routes.windows(2) {
        let left = pair[0];
        let right = pair[1];
        if ip_version(left.network()) > ip_version(right.network())
            || (ip_version(left.network()) == ip_version(right.network())
                && left.network() > right.network())
            || (same_ip_version(left.network(), right.network())
                && left.broadcast() >= right.network())
        {
            return Err(ValidationError::AdvertiseRoutes);
        }
    }
    Ok(())
}

fn ip_version(address: std::net::IpAddr) -> u8 {
    match address {
        std::net::IpAddr::V4(_) => 4,
        std::net::IpAddr::V6(_) => 6,
    }
}

fn same_ip_version(left: std::net::IpAddr, right: std::net::IpAddr) -> bool {
    ip_version(left) == ip_version(right)
}

fn check_non_empty(field: &'static str, value: &str) -> Result<(), ValidationError> {
    if value.trim().is_empty() {
        Err(ValidationError::EmptyField(field))
    } else {
        Ok(())
    }
}

fn check_duration(field: &'static str, value: &str) -> Result<(), ValidationError> {
    parse_duration(value)
        .map(|_| ())
        .map_err(|_| ValidationError::InvalidDuration { field, value: value.to_owned() })
}

pub fn parse_duration(value: &str) -> Result<std::time::Duration, DurationError> {
    let value = value.trim();
    if value.len() < 2 {
        return Err(DurationError::InvalidFormat);
    }
    let (number, unit) = value.split_at(value.len() - 1);
    let multiplier = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 60 * 60,
        _ if value.ends_with("ms") => {
            let number = &value[..value.len() - 2];
            let milliseconds = number.parse::<u64>().map_err(|_| DurationError::InvalidNumber)?;
            return Ok(std::time::Duration::from_millis(milliseconds));
        }
        _ => return Err(DurationError::InvalidFormat),
    };
    let seconds = number.parse::<u64>().map_err(|_| DurationError::InvalidNumber)?;
    let total = seconds.checked_mul(multiplier).ok_or(DurationError::Overflow)?;
    Ok(std::time::Duration::from_secs(total))
}
