use std::{net::IpAddr, sync::Arc};

use maskman_config::{CompiledConfig, CompiledLimits, CompiledRole};
use maskman_protocol::packet::{classify_address, AddressClass};
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

    pub fn authorize_ip_protocol(&self, protocol: u8) -> Result<(), PolicyError> {
        if self.allowed_ip_protocols.iter().any(|value| value == "*")
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
    }
}
