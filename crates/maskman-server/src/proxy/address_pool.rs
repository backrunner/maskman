use std::{
    collections::HashSet,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::{Arc, Mutex},
};

use ipnet::IpNet;
use maskman_config::CompiledIp;

#[derive(Clone, Default)]
pub struct AddressPoolSet {
    ipv4: Option<Arc<Mutex<AddressPool>>>,
    ipv6: Option<Arc<Mutex<AddressPool>>>,
}

impl AddressPoolSet {
    pub fn from_config(config: &CompiledIp) -> Self {
        Self {
            ipv4: config.ipv4_pool.map(AddressPool::new).map(|pool| Arc::new(Mutex::new(pool))),
            ipv6: config.ipv6_pool.map(AddressPool::new).map(|pool| Arc::new(Mutex::new(pool))),
        }
    }

    pub fn lease(&self) -> Option<AddressLeaseSet> {
        let mut leases = Vec::new();
        if let Some(pool) = &self.ipv4 {
            if let Some((address, prefix)) = lock_pool(pool).lease() {
                leases.push(AddressLease { pool: pool.clone(), address, prefix });
            }
        }
        if let Some(pool) = &self.ipv6 {
            if let Some((address, prefix)) = lock_pool(pool).lease() {
                leases.push(AddressLease { pool: pool.clone(), address, prefix });
            }
        }
        if leases.is_empty() {
            return None;
        }
        Some(AddressLeaseSet { leases })
    }
}

pub struct AddressLeaseSet {
    leases: Vec<AddressLease>,
}

impl AddressLeaseSet {
    pub fn prefixes(&self) -> impl Iterator<Item = IpNet> + '_ {
        self.leases.iter().map(|lease| lease.prefix)
    }
}

struct AddressLease {
    pool: Arc<Mutex<AddressPool>>,
    address: IpAddr,
    prefix: IpNet,
}

impl Drop for AddressLease {
    fn drop(&mut self) {
        lock_pool(&self.pool).release(self.address);
    }
}

struct AddressPool {
    network: IpNet,
    first: u128,
    last: u128,
    next: u128,
    leased: HashSet<IpAddr>,
}

impl AddressPool {
    fn new(network: IpNet) -> Self {
        let first = numeric(network.network());
        let last = numeric(network.broadcast());
        let (first, last) = usable_bounds(network, first, last);
        Self { network, first, last, next: first, leased: HashSet::new() }
    }

    fn lease(&mut self) -> Option<(IpAddr, IpNet)> {
        if self.first > self.last {
            return None;
        }
        let span = self.last - self.first + 1;
        let scan_limit = span.min(4096);
        for _ in 0..scan_limit {
            let candidate = self.next;
            self.next = if candidate == self.last { self.first } else { candidate + 1 };
            let address = address_from_numeric(self.network, candidate);
            if self.leased.insert(address) {
                return Some((address, host_prefix(address)));
            }
        }
        None
    }

    fn release(&mut self, address: IpAddr) {
        self.leased.remove(&address);
    }
}

fn lock_pool(pool: &Arc<Mutex<AddressPool>>) -> std::sync::MutexGuard<'_, AddressPool> {
    pool.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn usable_bounds(network: IpNet, first: u128, last: u128) -> (u128, u128) {
    match network {
        IpNet::V4(net) if net.prefix_len() < 31 => (first + 1, last - 1),
        IpNet::V6(_) if first < last => (first + 1, last),
        _ => (first, last),
    }
}

fn host_prefix(address: IpAddr) -> IpNet {
    match address {
        IpAddr::V4(address) => IpNet::V4(
            ipnet::Ipv4Net::new(address, 32)
                .unwrap_or_else(|_| unreachable!("a 32-bit IPv4 prefix is always valid")),
        ),
        IpAddr::V6(address) => IpNet::V6(
            ipnet::Ipv6Net::new(address, 128)
                .unwrap_or_else(|_| unreachable!("a 128-bit IPv6 prefix is always valid")),
        ),
    }
}

fn numeric(address: IpAddr) -> u128 {
    match address {
        IpAddr::V4(address) => u128::from(u32::from(address)),
        IpAddr::V6(address) => u128::from(address),
    }
}

fn address_from_numeric(network: IpNet, value: u128) -> IpAddr {
    match network {
        IpNet::V4(_) => IpAddr::V4(Ipv4Addr::from(value as u32)),
        IpNet::V6(_) => IpAddr::V6(Ipv6Addr::from(value)),
    }
}

#[cfg(test)]
mod tests {
    use super::AddressPoolSet;

    #[test]
    fn leases_are_unique_and_released() {
        let network = "192.0.2.0/30".parse().unwrap_or_else(|error| panic!("parse pool: {error}"));
        let pools = AddressPoolSet {
            ipv4: Some(std::sync::Arc::new(std::sync::Mutex::new(super::AddressPool::new(
                network,
            )))),
            ipv6: None,
        };
        let first = pools.lease().unwrap_or_else(|| panic!("first lease"));
        let first_address = first
            .prefixes()
            .next()
            .map(|prefix| prefix.network())
            .unwrap_or_else(|| panic!("first address"));
        let second = pools.lease().unwrap_or_else(|| panic!("second lease"));
        let second_address = second
            .prefixes()
            .next()
            .map(|prefix| prefix.network())
            .unwrap_or_else(|| panic!("second address"));
        assert_ne!(first_address, second_address);
        drop(first);
        let third = pools.lease().unwrap_or_else(|| panic!("reused lease"));
        assert_eq!(third.prefixes().next().map(|prefix| prefix.network()), Some(first_address));
    }
}
