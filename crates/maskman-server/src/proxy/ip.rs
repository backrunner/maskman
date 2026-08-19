use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::{Arc, Mutex},
};

use bytes::Bytes;
use ipnet::IpNet;
use maskman_protocol::{
    capsule::{
        decode_route_advertisement, encode_address_assign, AddressError, AssignedAddress,
        RequestedAddress, RouteAdvertisement, RouteError,
    },
    connect::{IpProtocolScope, IpScope, IpTarget},
    packet::{decrement_hop_limit, PacketView},
};
use thiserror::Error;
use tokio::sync::mpsc;

use super::address_pool::{AddressLeaseSet, AddressPoolSet};
use crate::policy::{EffectivePolicy, PolicyError};

const QUEUE_CAPACITY: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpDropReason {
    Malformed,
    Oversized,
    Source,
    Destination,
    Protocol,
    HopLimit,
    Rate,
    Queue,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum IpControlError {
    #[error("invalid address request: {0}")]
    Address(#[from] AddressError),
    #[error("invalid route advertisement: {0}")]
    Route(#[from] RouteError),
    #[error("route is outside the session policy")]
    Policy,
}

#[derive(Clone)]
pub struct IpSessionHandle {
    assigned: Arc<Vec<IpNet>>,
    scope: IpScope,
    policy: Arc<EffectivePolicy>,
    routes: Arc<Mutex<RouteAdvertisement>>,
    to_tun: mpsc::Sender<Bytes>,
    to_client: mpsc::Sender<Bytes>,
    ingress_limiter: Arc<Mutex<TokenBucket>>,
    egress_limiter: Arc<Mutex<TokenBucket>>,
    mtu: usize,
}

pub struct IpSession {
    pub handle: IpSessionHandle,
    pub to_client: mpsc::Receiver<Bytes>,
    _lease: AddressLeaseSet,
}

impl IpSession {
    pub fn start(
        scope: IpScope,
        pools: &AddressPoolSet,
        policy: Arc<EffectivePolicy>,
        mtu: usize,
        to_tun: mpsc::Sender<Bytes>,
    ) -> Option<Self> {
        let lease = pools.lease()?;
        let assigned = Arc::new(lease.prefixes().collect::<Vec<_>>());
        if assigned.is_empty() {
            return None;
        }
        let (to_client, to_client_rx) = mpsc::channel(QUEUE_CAPACITY);
        let handle = IpSessionHandle {
            assigned,
            scope,
            ingress_limiter: Arc::new(Mutex::new(TokenBucket::new(
                policy.limits.ingress_bytes_per_second,
                policy.limits.burst_bytes,
            ))),
            egress_limiter: Arc::new(Mutex::new(TokenBucket::new(
                policy.limits.egress_bytes_per_second,
                policy.limits.burst_bytes,
            ))),
            policy,
            routes: Arc::new(Mutex::new(RouteAdvertisement::default())),
            to_tun,
            to_client,
            mtu,
        };
        Some(Self { handle, to_client: to_client_rx, _lease: lease })
    }
}

impl IpSessionHandle {
    pub fn assigned(&self) -> &[IpNet] {
        &self.assigned
    }

    pub fn try_send(&self, payload: Bytes) -> Result<(), IpDropReason> {
        let mut packet = payload.to_vec();
        self.validate(&packet, false)?;
        if !allow(&self.ingress_limiter, packet.len()) {
            return Err(IpDropReason::Rate);
        }
        decrement_hop_limit(&mut packet).map_err(|_| IpDropReason::HopLimit)?;
        self.to_tun.try_send(Bytes::from(packet)).map_err(|_| IpDropReason::Queue)
    }

    pub fn try_send_from_tun(&self, payload: Bytes) -> Result<(), IpDropReason> {
        self.validate(&payload, true)?;
        if !allow(&self.egress_limiter, payload.len()) {
            return Err(IpDropReason::Rate);
        }
        self.to_client.try_send(payload).map_err(|_| IpDropReason::Queue)
    }

    pub fn initial_assignment_capsule(&self) -> Result<Vec<u8>, AddressError> {
        let entries = self
            .assigned()
            .iter()
            .map(|prefix| AssignedAddress { request_id: 0, prefix: *prefix })
            .collect::<Vec<_>>();
        encode_assignments(&entries)
    }

    pub fn address_request_capsule(
        &self,
        requests: &[RequestedAddress],
    ) -> Result<Vec<u8>, AddressError> {
        let mut used = vec![false; self.assigned.len()];
        let mut entries = Vec::with_capacity(requests.len() + self.assigned.len());
        for request in requests {
            let assignment = preferred_assignment(self.assigned(), &used, request)
                .or_else(|| family_assignment(self.assigned(), &used, request.prefix));
            if let Some(index) = assignment {
                used[index] = true;
                entries.push(AssignedAddress {
                    request_id: request.request_id,
                    prefix: self.assigned[index],
                });
            } else {
                entries.push(AssignedAddress {
                    request_id: request.request_id,
                    prefix: rejected_assignment(request.prefix),
                });
            }
        }
        entries.extend(
            self.assigned
                .iter()
                .enumerate()
                .filter(|(index, _)| !used[*index])
                .map(|(_, prefix)| AssignedAddress { request_id: 0, prefix: *prefix }),
        );
        encode_assignments(&entries)
    }

    pub fn replace_routes(&self, value: &[u8]) -> Result<(), IpControlError> {
        let next = decode_route_advertisement(value)?;
        for range in next.ranges() {
            if range.protocol != 0 {
                self.policy
                    .authorize_ip_protocol(range.protocol)
                    .map_err(|_: PolicyError| IpControlError::Policy)?;
            }
            self.policy
                .authorize_destination(range.start)
                .map_err(|_: PolicyError| IpControlError::Policy)?;
            self.policy
                .authorize_destination(range.end)
                .map_err(|_: PolicyError| IpControlError::Policy)?;
        }
        *self.routes.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = next;
        Ok(())
    }

    fn validate(&self, payload: &[u8], reverse: bool) -> Result<(), IpDropReason> {
        if payload.is_empty() || payload.len() > self.mtu {
            return Err(IpDropReason::Oversized);
        }
        let view = PacketView::parse(payload).map_err(|_| IpDropReason::Malformed)?;
        if view.total_len() != payload.len() {
            return Err(IpDropReason::Malformed);
        }
        let source = view.source();
        let destination = view.destination();
        let protocol = view.protocol();
        if reverse {
            if !self.assigned.iter().any(|prefix| prefix.contains(&destination)) {
                return Err(IpDropReason::Destination);
            }
            if !scope_matches(&self.scope.target, source)
                || self.policy.authorize_destination(source).is_err()
            {
                return Err(IpDropReason::Source);
            }
        } else {
            if !self.assigned.iter().any(|prefix| prefix.contains(&source)) {
                return Err(IpDropReason::Source);
            }
            if !scope_matches(&self.scope.target, destination)
                || self.policy.authorize_destination(destination).is_err()
            {
                return Err(IpDropReason::Destination);
            }
        }
        if !scope_protocol_matches(self.scope.protocol, protocol)
            || self.policy.authorize_ip_protocol(protocol).is_err()
        {
            return Err(IpDropReason::Protocol);
        }
        let routes = self.routes.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let route_address = if reverse { source } else { destination };
        if !routes.ranges().is_empty()
            && !routes.ranges().iter().any(|range| {
                range.start <= route_address
                    && route_address <= range.end
                    && (range.protocol == 0 || range.protocol == protocol)
            })
        {
            return Err(IpDropReason::Destination);
        }
        Ok(())
    }
}

fn encode_assignments(entries: &[AssignedAddress]) -> Result<Vec<u8>, AddressError> {
    let mut encoded = Vec::new();
    encode_address_assign(entries, &mut encoded)?;
    Ok(encoded)
}

fn preferred_assignment(
    assigned: &[IpNet],
    used: &[bool],
    request: &RequestedAddress,
) -> Option<usize> {
    assigned.iter().enumerate().position(|(index, prefix)| {
        !used[index]
            && same_family(*prefix, request.prefix)
            && request.prefix.contains(&prefix.network())
    })
}

fn family_assignment(assigned: &[IpNet], used: &[bool], requested: IpNet) -> Option<usize> {
    assigned
        .iter()
        .enumerate()
        .position(|(index, prefix)| !used[index] && same_family(*prefix, requested))
}

fn same_family(left: IpNet, right: IpNet) -> bool {
    matches!((left, right), (IpNet::V4(_), IpNet::V4(_)) | (IpNet::V6(_), IpNet::V6(_)))
}

fn rejected_assignment(requested: IpNet) -> IpNet {
    match requested {
        IpNet::V4(_) => IpNet::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 32)
            .unwrap_or_else(|_| unreachable!("an IPv4 host prefix is valid")),
        IpNet::V6(_) => IpNet::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 128)
            .unwrap_or_else(|_| unreachable!("an IPv6 host prefix is valid")),
    }
}

#[derive(Default)]
pub struct IpSessionRegistry {
    state: Mutex<IpRegistryState>,
}

#[derive(Default)]
struct IpRegistryState {
    streams: HashMap<SessionKey, IpSessionHandle>,
    addresses: HashMap<IpAddr, SessionKey>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct SessionKey {
    connection_id: u64,
    stream_id: u64,
}

impl IpSessionRegistry {
    pub fn insert(&self, connection_id: u64, stream_id: u64, session: IpSessionHandle) -> bool {
        let key = SessionKey { connection_id, stream_id };
        let mut state = self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if state.streams.contains_key(&key)
            || session
                .assigned
                .iter()
                .any(|address| state.addresses.contains_key(&address.network()))
        {
            return false;
        }
        for address in session.assigned.iter().map(|prefix| prefix.network()) {
            state.addresses.insert(address, key);
        }
        state.streams.insert(key, session);
        true
    }

    pub fn remove(&self, connection_id: u64, stream_id: u64) -> Option<IpSessionHandle> {
        let key = SessionKey { connection_id, stream_id };
        let mut state = self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let session = state.streams.remove(&key)?;
        state.addresses.retain(|_, value| *value != key);
        Some(session)
    }

    pub fn try_send(
        &self,
        connection_id: u64,
        stream_id: u64,
        payload: Bytes,
    ) -> Result<(), IpDropReason> {
        let key = SessionKey { connection_id, stream_id };
        let session = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .streams
            .get(&key)
            .cloned()
            .ok_or(IpDropReason::Destination)?;
        session.try_send(payload)
    }

    pub fn dispatch_tun(&self, payload: Bytes) -> Result<(), IpDropReason> {
        let destination =
            PacketView::parse(&payload).map_err(|_| IpDropReason::Malformed)?.destination();
        let session = {
            let state = self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            let key = state.addresses.get(&destination).ok_or(IpDropReason::Destination)?;
            state.streams.get(key).cloned().ok_or(IpDropReason::Destination)?
        };
        session.try_send_from_tun(payload)
    }
}

fn scope_matches(target: &IpTarget, address: IpAddr) -> bool {
    match target {
        IpTarget::Any => true,
        IpTarget::Prefix(prefix) => prefix.contains(&address),
        IpTarget::Name(_) => false,
    }
}

fn scope_protocol_matches(scope: IpProtocolScope, protocol: u8) -> bool {
    matches!(scope, IpProtocolScope::Any)
        || matches!(scope, IpProtocolScope::Number(value) if value == protocol)
}

fn allow(bucket: &Arc<Mutex<TokenBucket>>, amount: usize) -> bool {
    bucket.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).allow(amount)
}

struct TokenBucket {
    tokens: u64,
    rate: u64,
    burst: u64,
    last: std::time::Instant,
}

impl TokenBucket {
    fn new(rate: u64, burst: u64) -> Self {
        Self { tokens: burst, rate, burst, last: std::time::Instant::now() }
    }

    fn allow(&mut self, amount: usize) -> bool {
        let nanos = self.last.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64;
        let replenished = (u128::from(self.rate) * u128::from(nanos) / 1_000_000_000) as u64;
        self.tokens = self.tokens.saturating_add(replenished).min(self.burst);
        self.last = std::time::Instant::now();
        let amount = amount as u64;
        if self.tokens < amount {
            return false;
        }
        self.tokens -= amount;
        true
    }
}

#[cfg(test)]
#[path = "ip_tests.rs"]
mod tests;
