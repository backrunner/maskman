use std::{net::SocketAddr, time::Duration};

use maskman_protocol::connect::{TargetHost, UdpTarget};
use thiserror::Error;
use tokio::{net::lookup_host, time::timeout};

use crate::policy::{EffectivePolicy, PolicyError};

#[derive(Debug, Error)]
pub enum ResolveError {
    #[error("DNS resolution failed")]
    Dns,
    #[error("resolved target is not allowed by policy")]
    Policy,
}

pub async fn resolve_udp_target(
    target: &UdpTarget,
    policy: &EffectivePolicy,
    prefer_ipv6: bool,
) -> Result<SocketAddr, ResolveError> {
    match &target.host {
        TargetHost::Ip(address) => {
            policy
                .authorize_destination(*address)
                .map_err(|_: PolicyError| ResolveError::Policy)?;
            Ok(SocketAddr::new(*address, target.port))
        }
        TargetHost::Name(name) => {
            let lookup = timeout(Duration::from_secs(5), lookup_host((name.as_str(), target.port)))
                .await
                .map_err(|_| ResolveError::Dns)?
                .map_err(|_| ResolveError::Dns)?;
            let mut allowed = lookup
                .take(32)
                .filter(|address| policy.authorize_destination(address.ip()).is_ok())
                .collect::<Vec<_>>();
            allowed.sort_by_key(|address| address.is_ipv6() != prefer_ipv6);
            allowed.into_iter().next().ok_or(ResolveError::Policy)
        }
    }
}
