use std::net::IpAddr;

use ipnet::IpNet;
use maskman_protocol::{
    capsule::{AddressRange, RouteAdvertisement, RouteError},
    connect::IpProtocolScope,
    packet::is_icmp_protocol,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorizedIpTarget {
    Any,
    Prefix(IpNet),
    Resolved(Vec<IpAddr>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizedIpScope {
    target: AuthorizedIpTarget,
    protocol: IpProtocolScope,
}

impl AuthorizedIpScope {
    pub fn any(protocol: IpProtocolScope) -> Self {
        Self { target: AuthorizedIpTarget::Any, protocol }
    }

    pub fn prefix(prefix: IpNet, protocol: IpProtocolScope) -> Self {
        Self { target: AuthorizedIpTarget::Prefix(prefix), protocol }
    }

    pub fn resolved(addresses: Vec<IpAddr>, protocol: IpProtocolScope) -> Option<Self> {
        (!addresses.is_empty())
            .then_some(Self { target: AuthorizedIpTarget::Resolved(addresses), protocol })
    }

    pub fn destination_matches(&self, address: IpAddr) -> bool {
        match &self.target {
            AuthorizedIpTarget::Any => true,
            AuthorizedIpTarget::Prefix(prefix) => prefix.contains(&address),
            AuthorizedIpTarget::Resolved(addresses) => addresses.binary_search(&address).is_ok(),
        }
    }

    pub fn protocol_matches(&self, protocol: u8) -> bool {
        is_icmp_protocol(protocol)
            || matches!(self.protocol, IpProtocolScope::Any)
            || matches!(self.protocol, IpProtocolScope::Number(value) if value == protocol)
    }

    pub fn has_compatible_assignment(&self, assigned: &[IpNet]) -> bool {
        match &self.target {
            AuthorizedIpTarget::Any => !assigned.is_empty(),
            AuthorizedIpTarget::Prefix(prefix) => {
                assigned.iter().any(|address| same_family(*address, *prefix))
            }
            AuthorizedIpTarget::Resolved(addresses) => addresses.iter().any(|address| {
                assigned.iter().any(|prefix| same_address_family(prefix.network(), *address))
            }),
        }
    }

    pub fn advertisement(
        &self,
        configured: &[IpNet],
        assigned: &[IpNet],
    ) -> Result<RouteAdvertisement, RouteError> {
        let networks = match &self.target {
            AuthorizedIpTarget::Any => configured.to_vec(),
            AuthorizedIpTarget::Prefix(target) => configured
                .iter()
                .filter_map(|route| network_intersection(*target, *route))
                .collect(),
            AuthorizedIpTarget::Resolved(addresses) => {
                addresses.iter().copied().map(host_prefix).collect()
            }
        };
        let protocol = match self.protocol {
            IpProtocolScope::Any => 0,
            IpProtocolScope::Number(protocol) => protocol,
        };
        let mut ranges = networks
            .into_iter()
            .filter(|network| assigned.iter().any(|address| same_family(*network, *address)))
            .map(|network| AddressRange {
                start: network.network(),
                end: network.broadcast(),
                protocol,
            })
            .collect::<Vec<_>>();
        ranges.sort_by_key(|range| (version(range.start), range.protocol, range.start));
        ranges.dedup();
        RouteAdvertisement::new(ranges)
    }
}

fn network_intersection(left: IpNet, right: IpNet) -> Option<IpNet> {
    if !same_family(left, right) {
        return None;
    }
    if left.contains(&right.network()) {
        Some(right)
    } else if right.contains(&left.network()) {
        Some(left)
    } else {
        None
    }
}

fn host_prefix(address: IpAddr) -> IpNet {
    IpNet::new(address, if address.is_ipv4() { 32 } else { 128 })
        .unwrap_or_else(|_| unreachable!("an IP host prefix is always valid"))
}

fn same_family(left: IpNet, right: IpNet) -> bool {
    same_address_family(left.network(), right.network())
}

fn same_address_family(left: IpAddr, right: IpAddr) -> bool {
    matches!((left, right), (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_)))
}

fn version(address: IpAddr) -> u8 {
    if address.is_ipv4() {
        4
    } else {
        6
    }
}

#[cfg(test)]
mod tests {
    use maskman_protocol::connect::IpProtocolScope;

    use super::AuthorizedIpScope;

    #[test]
    fn resolved_scope_advertises_only_assigned_families() {
        fn ip(value: &str) -> std::net::IpAddr {
            value.parse().unwrap_or_else(|error| panic!("parse IP {value}: {error}"))
        }
        fn net(value: &str) -> ipnet::IpNet {
            value.parse().unwrap_or_else(|error| panic!("parse network {value}: {error}"))
        }
        let scope = AuthorizedIpScope::resolved(
            vec![ip("8.8.8.8"), ip("2001:4860:4860::8888")],
            IpProtocolScope::Number(17),
        )
        .unwrap_or_else(|| panic!("resolved scope"));
        let assigned = vec![net("100.96.0.1/32")];
        let routes = scope
            .advertisement(&[], &assigned)
            .unwrap_or_else(|error| panic!("route advertisement: {error}"));

        assert_eq!(routes.ranges().len(), 1);
        assert_eq!(routes.ranges()[0].start.to_string(), "8.8.8.8");
        assert_eq!(routes.ranges()[0].protocol, 17);
    }

    #[test]
    fn configured_routes_are_intersected_with_prefix_scope() {
        fn net(value: &str) -> ipnet::IpNet {
            value.parse().unwrap_or_else(|error| panic!("parse network {value}: {error}"))
        }
        let scope = AuthorizedIpScope::prefix(net("8.8.8.0/24"), IpProtocolScope::Any);
        let configured = vec![net("0.0.0.0/0")];
        let assigned = vec![net("100.96.0.1/32")];
        let routes = scope
            .advertisement(&configured, &assigned)
            .unwrap_or_else(|error| panic!("route advertisement: {error}"));

        assert_eq!(routes.ranges().len(), 1);
        assert_eq!(routes.ranges()[0].start.to_string(), "8.8.8.0");
        assert_eq!(routes.ranges()[0].end.to_string(), "8.8.8.255");
    }
}
