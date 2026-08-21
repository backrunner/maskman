use std::{collections::HashMap, net::SocketAddr, path::PathBuf, time::Duration};

use ipnet::IpNet;
use time::OffsetDateTime;

use crate::{
    model::{AuthMode, ConfigDocument, NatMode},
    validate::{parse_duration, resolve_path},
    ConfigError,
};

#[derive(Debug, Clone)]
pub struct CompiledConfig {
    pub listen: Vec<SocketAddr>,
    pub base_path: String,
    pub idle_timeout: Duration,
    pub drain_timeout: Duration,
    pub max_connections: u32,
    pub max_requests_per_connection: u32,
    pub max_header_bytes: u32,
    pub state_dir: PathBuf,
    pub certificate_file: PathBuf,
    pub private_key_file: PathBuf,
    pub client_ca_file: Option<PathBuf>,
    pub auth_required: bool,
    pub auth_mode: AuthMode,
    pub principals: HashMap<String, Vec<String>>,
    pub token_principals: HashMap<String, CompiledToken>,
    pub certificate_principals: HashMap<String, String>,
    pub roles: HashMap<String, CompiledRole>,
    pub udp: CompiledUdp,
    pub ip: CompiledIp,
    pub metrics_listen: SocketAddr,
}

#[derive(Debug, Clone)]
pub struct CompiledRole {
    pub capabilities: Vec<String>,
    pub allow_destinations: Vec<IpNet>,
    pub deny_destinations: Vec<IpNet>,
    pub deny_private: bool,
    pub allowed_ip_protocols: Vec<String>,
    pub limits: CompiledLimits,
}

#[derive(Debug, Clone)]
pub struct CompiledLimits {
    pub active_tunnels: u32,
    pub new_tunnels_per_minute: u32,
    pub ingress_bytes_per_second: u64,
    pub egress_bytes_per_second: u64,
    pub burst_bytes: u64,
}

#[derive(Debug, Clone)]
pub struct CompiledToken {
    pub principal: String,
    pub secret_sha256: [u8; 32],
    pub expires_at: Option<OffsetDateTime>,
}

#[derive(Debug, Clone)]
pub struct CompiledUdp {
    pub enabled: bool,
    pub idle_timeout: Duration,
    pub max_payload_bytes: u32,
    pub prefer_ipv6: bool,
}

#[derive(Debug, Clone)]
pub struct CompiledIp {
    pub enabled: bool,
    pub interface_name: String,
    pub mtu: u32,
    pub ipv4_pool: Option<IpNet>,
    pub ipv6_pool: Option<IpNet>,
    pub advertise_routes: Vec<IpNet>,
    pub nat_managed: bool,
    pub nat_egress_interface: String,
}

pub fn compile(
    document: &ConfigDocument,
    base_dir: &std::path::Path,
) -> Result<CompiledConfig, ConfigError> {
    crate::validate::validate(document)?;
    let listen = document
        .server
        .listen
        .iter()
        .map(|value| parse_socket_addr(value, "server.listen"))
        .collect::<Result<Vec<_>, _>>()?;
    let mut principals = HashMap::new();
    for principal in &document.auth.principals {
        principals.insert(principal.id.clone(), principal.roles.clone());
    }
    let mut roles = HashMap::new();
    for role in &document.policy.roles {
        roles.insert(
            role.name.clone(),
            CompiledRole {
                capabilities: role.capabilities.clone(),
                allow_destinations: parse_networks(&role.allow_destinations)?,
                deny_destinations: parse_networks(&role.deny_destinations)?,
                deny_private: role.deny_private,
                allowed_ip_protocols: role.allowed_ip_protocols.clone(),
                limits: CompiledLimits {
                    active_tunnels: role.limits.active_tunnels,
                    new_tunnels_per_minute: role.limits.new_tunnels_per_minute,
                    ingress_bytes_per_second: role.limits.ingress_bytes_per_second,
                    egress_bytes_per_second: role.limits.egress_bytes_per_second,
                    burst_bytes: role.limits.burst_bytes,
                },
            },
        );
    }
    let mut token_principals = HashMap::new();
    for token in &document.auth.bearer_tokens {
        if token.enabled {
            token_principals.insert(
                token.id.clone(),
                CompiledToken {
                    principal: token.principal.clone(),
                    secret_sha256: decode_hash(&token.secret_sha256, &token.id)?,
                    expires_at: token.expires_at.as_deref().map(parse_expiry).transpose().map_err(
                        |error| {
                            ConfigError::Invariant(format!("token {} expiry: {error}", token.id))
                        },
                    )?,
                },
            );
        }
    }
    let mut certificate_principals = HashMap::new();
    for principal in &document.auth.principals {
        for digest in &principal.certificate_sha256 {
            certificate_principals.insert(digest.to_ascii_lowercase(), principal.id.clone());
        }
    }
    let metrics_listen =
        parse_socket_addr(&document.observability.metrics_listen, "observability.metrics_listen")?;
    Ok(CompiledConfig {
        listen,
        base_path: document.server.base_path.clone(),
        idle_timeout: parse_duration_checked(&document.server.idle_timeout, "server.idle_timeout")?,
        drain_timeout: parse_duration_checked(
            &document.server.drain_timeout,
            "server.drain_timeout",
        )?,
        max_connections: document.server.max_connections,
        max_requests_per_connection: document.server.max_requests_per_connection,
        max_header_bytes: document.server.max_header_bytes,
        state_dir: resolve_path(base_dir, &document.server.state_dir),
        certificate_file: resolve_path(base_dir, &document.tls.certificate_file),
        private_key_file: resolve_path(base_dir, &document.tls.private_key_file),
        client_ca_file: document
            .tls
            .client_ca_file
            .as_deref()
            .map(|value| resolve_path(base_dir, value)),
        auth_required: document.auth.required,
        auth_mode: document.auth.mode.clone(),
        principals,
        token_principals,
        certificate_principals,
        roles,
        udp: CompiledUdp {
            enabled: document.proxy.udp.enabled,
            idle_timeout: parse_duration_checked(
                &document.proxy.udp.socket_idle_timeout,
                "proxy.udp.socket_idle_timeout",
            )?,
            max_payload_bytes: document.proxy.udp.max_payload_bytes,
            prefer_ipv6: document.proxy.udp.prefer_ipv6,
        },
        ip: CompiledIp {
            enabled: document.proxy.ip.enabled,
            interface_name: document.proxy.ip.interface_name.clone(),
            mtu: document.proxy.ip.mtu,
            ipv4_pool: parse_optional_network(
                document.proxy.ip.client_ipv4_pool.as_deref(),
                "proxy.ip.client_ipv4_pool",
            )?,
            ipv6_pool: parse_optional_network(
                document.proxy.ip.client_ipv6_pool.as_deref(),
                "proxy.ip.client_ipv6_pool",
            )?,
            advertise_routes: parse_networks(&document.proxy.ip.advertise_routes)?,
            nat_managed: matches!(document.proxy.ip.nat.mode, NatMode::Managed),
            nat_egress_interface: document.proxy.ip.nat.egress_interface.clone(),
        },
        metrics_listen,
    })
}

fn parse_socket_addr(value: &str, field: &str) -> Result<SocketAddr, ConfigError> {
    value.parse().map_err(|error| ConfigError::Invariant(format!("{field} `{value}`: {error}")))
}

fn parse_duration_checked(value: &str, field: &str) -> Result<Duration, ConfigError> {
    parse_duration(value)
        .map_err(|_| ConfigError::Invariant(format!("{field} `{value}` is invalid")))
}

fn parse_networks(values: &[String]) -> Result<Vec<IpNet>, ConfigError> {
    values
        .iter()
        .map(|value| {
            value
                .parse()
                .map_err(|error| ConfigError::Invariant(format!("network `{value}`: {error}")))
        })
        .collect()
}

fn parse_optional_network(value: Option<&str>, field: &str) -> Result<Option<IpNet>, ConfigError> {
    value
        .map(|value| {
            value
                .parse()
                .map_err(|error| ConfigError::Invariant(format!("{field} `{value}`: {error}")))
        })
        .transpose()
}

fn decode_hash(value: &str, token: &str) -> Result<[u8; 32], ConfigError> {
    if value.len() != 64 {
        return Err(ConfigError::Invariant(format!(
            "token {token} contains an invalid SHA-256 value"
        )));
    }
    let mut output = [0u8; 32];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_digit(chunk[0]).ok_or_else(|| {
            ConfigError::Invariant(format!("token {token} contains an invalid SHA-256 value"))
        })?;
        let low = hex_digit(chunk[1]).ok_or_else(|| {
            ConfigError::Invariant(format!("token {token} contains an invalid SHA-256 value"))
        })?;
        output[index] = (high << 4) | low;
    }
    Ok(output)
}

fn hex_digit(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn parse_expiry(value: &str) -> Result<OffsetDateTime, time::error::Parse> {
    OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339)
}
