use std::{net::IpAddr, sync::Arc};

use ipnet::IpNet;
use maskman_config::{CompiledConfig, CompiledLimits, CompiledRole};
use maskman_protocol::{
    capsule::AddressRange,
    packet::{classify_address, is_icmp_protocol, AddressClass},
};
use thiserror::Error;

use crate::auth::Principal;

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum PolicyError {
    #[error("principal is not authorized for this proxy capability")]
    Capability,
    #[error("target is not allowed by the principal policy")]
    Destination,
}

#[derive(Debug, Clone)]
pub struct EffectivePolicy {
    roles: Vec<CompiledRole>,
    pub limits: CompiledLimits,
    allowed_ip_protocols: Vec<String>,
}

impl EffectivePolicy {
    pub fn authorize_capability(&self, capability: &str) -> Result<(), PolicyError> {
        if self.roles.iter().any(|role| role.capabilities.iter().any(|value| value == capability)) {
            Ok(())
        } else {
            Err(PolicyError::Capability)
        }
    }

    pub fn authorize_destination(&self, address: IpAddr) -> Result<(), PolicyError> {
        if self.roles.iter().any(|role| destination_allowed(role, address)) {
            Ok(())
        } else {
            Err(PolicyError::Destination)
        }
    }

    /// Perform the cheap, pre-provisioning part of a literal prefix check.
    ///
    /// Packet authorization remains authoritative, but a request for a prefix
    /// that has no policy intersection must never acquire a socket, lease, or
    /// other session resource first.
    pub fn authorize_prefix(&self, prefix: IpNet) -> Result<(), PolicyError> {
        if self.roles.iter().any(|role| {
            role.allow_destinations.iter().any(|allowed| networks_overlap(*allowed, prefix))
                && !role.deny_destinations.iter().any(|denied| contains_network(*denied, prefix))
                && !(role.deny_private && entirely_non_global(prefix))
        }) {
            Ok(())
        } else {
            Err(PolicyError::Destination)
        }
    }

    pub fn authorize_destination_range(
        &self,
        start: IpAddr,
        end: IpAddr,
    ) -> Result<(), PolicyError> {
        let range = AddressRange { start, end, protocol: 0 };
        if self.roles.iter().any(|role| {
            role.allow_destinations.iter().any(|allowed| {
                network_contains_address(*allowed, start) && network_contains_address(*allowed, end)
            }) && !role
                .deny_destinations
                .iter()
                .any(|denied| network_overlaps_range(*denied, &range))
                && !(role.deny_private && default_denied_overlaps(&range))
        }) {
            Ok(())
        } else {
            Err(PolicyError::Destination)
        }
    }

    pub fn authorize_ip_protocol(&self, protocol: u8) -> Result<(), PolicyError> {
        if is_icmp_protocol(protocol)
            || self.allowed_ip_protocols.iter().any(|value| value == "*")
            || self
                .allowed_ip_protocols
                .iter()
                .any(|value| value.parse::<u8>().ok() == Some(protocol))
        {
            Ok(())
        } else {
            Err(PolicyError::Capability)
        }
    }
}

pub fn compile(config: Arc<CompiledConfig>, principal: &Principal) -> EffectivePolicy {
    let roles = principal
        .roles
        .iter()
        .filter_map(|name| config.roles.get(name).cloned())
        .collect::<Vec<_>>();
    let limits =
        roles.iter().map(|role| role.limits.clone()).reduce(min_limits).unwrap_or(CompiledLimits {
            active_tunnels: 0,
            new_tunnels_per_minute: 0,
            ingress_bytes_per_second: 0,
            egress_bytes_per_second: 0,
            burst_bytes: 0,
        });
    let allowed_ip_protocols =
        roles.iter().flat_map(|role| role.allowed_ip_protocols.iter().cloned()).collect();
    EffectivePolicy { roles, limits, allowed_ip_protocols }
}

fn destination_allowed(role: &CompiledRole, address: IpAddr) -> bool {
    if role.deny_private && classify_address(address) != AddressClass::Global {
        return false;
    }
    role.allow_destinations.iter().any(|network| network.contains(&address))
        && !role.deny_destinations.iter().any(|network| network.contains(&address))
}

fn networks_overlap(left: IpNet, right: IpNet) -> bool {
    match (left, right) {
        (IpNet::V4(left), IpNet::V4(right)) => {
            left.contains(&right.network()) || right.contains(&left.network())
        }
        (IpNet::V6(left), IpNet::V6(right)) => {
            left.contains(&right.network()) || right.contains(&left.network())
        }
        _ => false,
    }
}

fn network_contains_address(network: IpNet, address: IpAddr) -> bool {
    network.contains(&address)
}

fn network_overlaps_range(network: IpNet, range: &AddressRange) -> bool {
    match (network, range.start, range.end) {
        (IpNet::V4(network), IpAddr::V4(start), IpAddr::V4(end)) => {
            network.contains(&start)
                || network.contains(&end)
                || (start <= network.network() && network.broadcast() <= end)
        }
        (IpNet::V6(network), IpAddr::V6(start), IpAddr::V6(end)) => {
            network.contains(&start)
                || network.contains(&end)
                || (start <= network.network() && network.broadcast() <= end)
        }
        _ => false,
    }
}

fn default_denied_overlaps(range: &AddressRange) -> bool {
    default_denied_networks().iter().any(|network| network_overlaps_range(*network, range))
}

fn default_denied_networks() -> &'static [IpNet] {
    use std::sync::OnceLock;
    static NETWORKS: OnceLock<Vec<IpNet>> = OnceLock::new();
    NETWORKS.get_or_init(|| {
        [
            "0.0.0.0/8",
            "10.0.0.0/8",
            "100.64.0.0/10",
            "127.0.0.0/8",
            "169.254.0.0/16",
            "172.16.0.0/12",
            "192.0.0.0/24",
            "192.0.2.0/24",
            "192.168.0.0/16",
            "198.18.0.0/15",
            "198.51.100.0/24",
            "203.0.113.0/24",
            "224.0.0.0/4",
            "240.0.0.0/4",
            "::/128",
            "::1/128",
            "fc00::/7",
            "fe80::/10",
            "ff00::/8",
            "2001:db8::/32",
            "2002::/16",
        ]
        .into_iter()
        .filter_map(|value| value.parse().ok())
        .collect()
    })
}

fn contains_network(container: IpNet, candidate: IpNet) -> bool {
    match (container, candidate) {
        (IpNet::V4(container), IpNet::V4(candidate)) => {
            container.contains(&candidate.network()) && container.contains(&candidate.broadcast())
        }
        (IpNet::V6(container), IpNet::V6(candidate)) => {
            container.contains(&candidate.network()) && container.contains(&candidate.broadcast())
        }
        _ => false,
    }
}

fn entirely_non_global(prefix: IpNet) -> bool {
    let length = prefix.prefix_len();
    if length == 0 {
        return false;
    }
    let (first, last) = (prefix.network(), prefix.broadcast());
    let samples = [first, last];
    length >= if first.is_ipv4() { 8 } else { 7 }
        && samples.into_iter().all(|address| classify_address(address) != AddressClass::Global)
}

fn min_limits(left: CompiledLimits, right: CompiledLimits) -> CompiledLimits {
    CompiledLimits {
        active_tunnels: left.active_tunnels.min(right.active_tunnels),
        new_tunnels_per_minute: left.new_tunnels_per_minute.min(right.new_tunnels_per_minute),
        ingress_bytes_per_second: left.ingress_bytes_per_second.min(right.ingress_bytes_per_second),
        egress_bytes_per_second: left.egress_bytes_per_second.min(right.egress_bytes_per_second),
        burst_bytes: left.burst_bytes.min(right.burst_bytes),
    }
}

#[cfg(test)]
mod tests {
    use std::{net::IpAddr, sync::Arc};

    use maskman_config::{model::ConfigDocument, CompiledConfig};

    use super::{compile, PolicyError};
    use crate::auth::Principal;

    fn config() -> Arc<CompiledConfig> {
        let mut document = ConfigDocument::default();
        document.auth.principals.push(maskman_config::model::PrincipalConfig {
            id: "client".into(),
            roles: vec!["role".into()],
            certificate_sha256: Vec::new(),
        });
        document.policy.roles.push(maskman_config::model::RoleConfig {
            name: "role".into(),
            capabilities: vec!["connect-udp".into()],
            allow_destinations: vec!["8.8.8.8/32".into()],
            deny_destinations: Vec::new(),
            deny_private: true,
            allowed_ip_protocols: Vec::new(),
            limits: Default::default(),
        });
        Arc::new(
            maskman_config::compile_document(&document, std::path::Path::new("."))
                .unwrap_or_else(|error| panic!("compile policy test config: {error}")),
        )
    }

    #[test]
    fn denies_private_and_missing_capabilities() {
        let policy =
            compile(config(), &Principal { id: "client".into(), roles: vec!["role".into()] });
        assert_eq!(policy.authorize_capability("connect-udp"), Ok(()));
        assert_eq!(policy.authorize_capability("connect-ip"), Err(PolicyError::Capability));
        assert_eq!(policy.authorize_destination(IpAddr::from([8, 8, 8, 8])), Ok(()));
        assert_eq!(
            policy.authorize_destination(IpAddr::from([10, 0, 0, 1])),
            Err(PolicyError::Destination)
        );
        assert_eq!(policy.authorize_ip_protocol(1), Ok(()));
        assert_eq!(policy.authorize_ip_protocol(58), Ok(()));
    }
}
