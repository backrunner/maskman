use std::{collections::BTreeSet, net::SocketAddr, time::Duration};

use maskman_protocol::connect::{IpScope, IpTarget, TargetHost, UdpTarget};
use thiserror::Error;
use tokio::{net::lookup_host, time::timeout};

use crate::{
    policy::{EffectivePolicy, PolicyError},
    proxy::ip_scope::AuthorizedIpScope,
};

const DNS_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_DNS_ADDRESSES: usize = 32;

#[derive(Debug, Error)]
pub enum ResolveError {
    #[error("DNS resolution failed")]
    Dns,
    #[error("resolved target is not allowed by policy")]
    Policy,
}

pub async fn resolve_ip_scope(
    scope: IpScope,
    policy: &EffectivePolicy,
) -> Result<AuthorizedIpScope, ResolveError> {
    let protocol = scope.protocol;
    match scope.target {
        IpTarget::Any => Ok(AuthorizedIpScope::any(protocol)),
        IpTarget::Prefix(prefix) => {
            policy.authorize_prefix(prefix).map_err(|_: PolicyError| ResolveError::Policy)?;
            Ok(AuthorizedIpScope::prefix(prefix, protocol))
        }
        IpTarget::Name(name) => {
            let addresses = lookup_addresses(&name, 0).await?;
            let mut allowed = addresses
                .into_iter()
                .map(|address| address.ip())
                .filter(|address| policy.authorize_destination(*address).is_ok())
                .collect::<Vec<_>>();
            allowed.sort_unstable();
            allowed.dedup();
            AuthorizedIpScope::resolved(allowed, protocol).ok_or(ResolveError::Policy)
        }
    }
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
            let mut allowed = lookup_addresses(name, target.port)
                .await?
                .into_iter()
                .filter(|address| policy.authorize_destination(address.ip()).is_ok())
                .collect::<Vec<_>>();
            allowed.sort_by_key(|address| address.is_ipv6() != prefer_ipv6);
            allowed.into_iter().next().ok_or(ResolveError::Policy)
        }
    }
}

async fn lookup_addresses(name: &str, port: u16) -> Result<Vec<SocketAddr>, ResolveError> {
    let lookup = timeout(DNS_TIMEOUT, lookup_host((name, port)))
        .await
        .map_err(|_| ResolveError::Dns)?
        .map_err(|_| ResolveError::Dns)?;
    let mut addresses = BTreeSet::new();
    for address in lookup {
        addresses.insert(address);
        if addresses.len() > MAX_DNS_ADDRESSES {
            return Err(ResolveError::Dns);
        }
    }
    if addresses.is_empty() {
        return Err(ResolveError::Dns);
    }
    Ok(addresses.into_iter().collect())
}
