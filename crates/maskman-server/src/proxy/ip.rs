use std::{
    collections::HashSet,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::{Arc, Mutex},
};

use bytes::Bytes;
use ipnet::IpNet;
use maskman_protocol::{
    capsule::{
        decode_address_assign, decode_route_advertisement, encode_address_assign, AddressError,
        AssignedAddress, RequestedAddress, RouteAdvertisement, RouteError,
    },
    packet::{build_icmp_error, decrement_hop_limit, is_icmp_protocol, IcmpErrorKind, PacketView},
};
use thiserror::Error;
use tokio::sync::mpsc;

use super::address_pool::{AddressLeaseSet, AddressPoolSet};
pub use super::ip_registry::IpSessionRegistry;
use super::ip_scope::AuthorizedIpScope;
use crate::policy::{EffectivePolicy, PolicyError};

const QUEUE_CAPACITY: usize = 64;
const MAX_SESSION_ROUTES: usize = 256;
const MAX_ADDRESS_REQUESTS: usize = 256;

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
    #[error("route advertisement exceeds the per-session limit")]
    RouteLimit,
    #[error("route advertisement conflicts with another session")]
    RouteConflict,
    #[error("the global route registry is full")]
    RouteCapacity,
    #[error("IP session no longer exists")]
    SessionClosed,
}

#[derive(Clone)]
pub struct IpSessionHandle {
    assigned: Arc<Vec<IpNet>>,
    scope: AuthorizedIpScope,
    policy: Arc<EffectivePolicy>,
    routes: Arc<Mutex<RouteAdvertisement>>,
    peer_assignments: Arc<Mutex<Vec<IpNet>>>,
    request_ids: Arc<Mutex<HashSet<u64>>>,
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
        scope: AuthorizedIpScope,
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
        if !scope.has_compatible_assignment(&assigned) {
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
            peer_assignments: Arc::new(Mutex::new(Vec::new())),
            request_ids: Arc::new(Mutex::new(HashSet::new())),
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

    pub fn supports_ipv6(&self) -> bool {
        self.assigned.iter().any(|prefix| matches!(prefix, IpNet::V6(_)))
    }

    pub fn try_send(&self, payload: Bytes) -> Result<(), IpDropReason> {
        if let Err(reason) = self.validate(&payload, false) {
            self.enqueue_forwarding_error(&payload, reason);
            return Err(reason);
        }
        if !allow(&self.ingress_limiter, payload.len()) {
            return Err(IpDropReason::Rate);
        }
        // Decapsulation does not decrement TTL/Hop Limit.  The packet is
        // still traversing the client-side link and the decrement happens
        // only when this endpoint later encapsulates it for the peer.
        self.to_tun.try_send(payload).map_err(|_| IpDropReason::Queue)
    }

    pub fn try_send_from_tun(&self, payload: Bytes) -> Result<(), IpDropReason> {
        self.validate(&payload, true)?;
        if !allow(&self.egress_limiter, payload.len()) {
            return Err(IpDropReason::Rate);
        }
        let mut packet = payload.to_vec();
        decrement_hop_limit(&mut packet).map_err(|_| IpDropReason::HopLimit)?;
        self.to_client.try_send(Bytes::from(packet)).map_err(|_| IpDropReason::Queue)
    }

    pub fn try_send_generated(&self, payload: Bytes) -> Result<(), IpDropReason> {
        if payload.is_empty() || payload.len() > self.mtu {
            return Err(IpDropReason::Oversized);
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
        if requests.len() > MAX_ADDRESS_REQUESTS {
            return Err(AddressError::TooManyEntries);
        }
        let mut request_ids =
            self.request_ids.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(request) =
            requests.iter().find(|request| request_ids.contains(&request.request_id))
        {
            return Err(AddressError::DuplicateRequestId(request.request_id));
        }
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
        let encoded = encode_assignments(&entries)?;
        request_ids.extend(requests.iter().map(|request| request.request_id));
        Ok(encoded)
    }

    pub fn route_advertisement(
        &self,
        configured: &[IpNet],
    ) -> Result<RouteAdvertisement, RouteError> {
        let advertisement = self.scope.advertisement(configured, self.assigned())?;
        let ranges = advertisement
            .ranges()
            .iter()
            .filter(|range| self.policy.authorize_destination_range(range.start, range.end).is_ok())
            .cloned()
            .collect();
        RouteAdvertisement::new(ranges)
    }

    pub fn replace_peer_assignments(&self, value: &[u8]) -> Result<(), AddressError> {
        let next: Vec<IpNet> =
            decode_address_assign(value)?.into_iter().map(|assignment| assignment.prefix).collect();
        if next.len() > MAX_SESSION_ROUTES {
            return Err(AddressError::TooManyEntries);
        }
        *self.peer_assignments.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = next;
        Ok(())
    }

    pub(super) fn validate_routes(
        &self,
        value: &[u8],
    ) -> Result<RouteAdvertisement, IpControlError> {
        let next = decode_route_advertisement(value)?;
        if next.ranges().len() > MAX_SESSION_ROUTES {
            return Err(IpControlError::RouteLimit);
        }
        for range in next.ranges() {
            if range.protocol != 0 {
                self.policy
                    .authorize_ip_protocol(range.protocol)
                    .map_err(|_: PolicyError| IpControlError::Policy)?;
            }
            self.policy
                .authorize_destination_range(range.start, range.end)
                .map_err(|_: PolicyError| IpControlError::Policy)?;
        }
        Ok(next)
    }

    pub(super) fn commit_routes(&self, next: RouteAdvertisement) {
        *self.routes.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = next;
    }

    fn validate(&self, payload: &[u8], reverse: bool) -> Result<(), IpDropReason> {
        if payload.is_empty() || payload.len() > self.mtu {
            return Err(IpDropReason::Oversized);
        }
        let view = PacketView::parse(payload).map_err(|_| IpDropReason::Malformed)?;
        if view.total_len() != payload.len() {
            return Err(IpDropReason::Malformed);
        }
        if reverse {
            self.validate_from_tun(view)?;
        } else {
            self.validate_from_client(view)?;
        }
        Ok(())
    }

    fn enqueue_forwarding_error(&self, payload: &[u8], reason: IpDropReason) {
        let kind = match reason {
            IpDropReason::Destination | IpDropReason::Protocol => IcmpErrorKind::NoRoute,
            IpDropReason::Source => IcmpErrorKind::SourcePolicy,
            IpDropReason::Oversized => IcmpErrorKind::PacketTooBig { mtu: self.mtu as u32 },
            IpDropReason::HopLimit => IcmpErrorKind::HopLimit,
            _ => return,
        };
        let Ok(view) = PacketView::parse_prefix(payload) else { return };
        if !self.assigned.iter().any(|prefix| prefix.contains(&view.source())) {
            return;
        }
        let Some(source) = self
            .assigned
            .iter()
            .find(|prefix| same_ip_family(prefix.network(), view.source()))
            .map(|prefix| prefix.network())
        else {
            return;
        };
        let Ok(error) = build_icmp_error(payload, source, kind) else { return };
        let _ = self.try_send_generated(Bytes::from(error));
    }

    fn validate_from_client(&self, view: PacketView<'_>) -> Result<(), IpDropReason> {
        if !self.assigned.iter().any(|prefix| prefix.contains(&view.source())) {
            return Err(IpDropReason::Source);
        }
        if !self.scope.destination_matches(view.destination())
            || self.policy.authorize_destination(view.destination()).is_err()
        {
            return Err(IpDropReason::Destination);
        }
        self.validate_protocol(view.protocol())
    }

    fn validate_from_tun(&self, view: PacketView<'_>) -> Result<(), IpDropReason> {
        if !self.reverse_destination_matches(view.destination(), view.protocol()) {
            return Err(IpDropReason::Destination);
        }
        if is_icmp_protocol(view.protocol()) {
            if let Some(invoking) =
                view.icmp_invoking_packet().map_err(|_| IpDropReason::Malformed)?
            {
                return self.validate_icmp_invocation(invoking);
            }
        }
        if !self.scope.destination_matches(view.source())
            || self.policy.authorize_destination(view.source()).is_err()
        {
            return Err(IpDropReason::Source);
        }
        self.validate_protocol(view.protocol())
    }

    fn validate_icmp_invocation(&self, invoking: PacketView<'_>) -> Result<(), IpDropReason> {
        if !self.assigned.iter().any(|prefix| prefix.contains(&invoking.source())) {
            return Err(IpDropReason::Source);
        }
        if !self.scope.destination_matches(invoking.destination())
            || self.policy.authorize_destination(invoking.destination()).is_err()
        {
            return Err(IpDropReason::Destination);
        }
        self.validate_protocol(invoking.protocol())
    }

    fn validate_protocol(&self, protocol: u8) -> Result<(), IpDropReason> {
        if self.scope.protocol_matches(protocol)
            && self.policy.authorize_ip_protocol(protocol).is_ok()
        {
            Ok(())
        } else {
            Err(IpDropReason::Protocol)
        }
    }

    fn reverse_destination_matches(&self, destination: IpAddr, protocol: u8) -> bool {
        if self.assigned.iter().any(|prefix| prefix.contains(&destination)) {
            return true;
        }
        self.routes
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .ranges()
            .iter()
            .any(|route| route.permits(destination, protocol))
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

fn same_ip_family(left: IpAddr, right: IpAddr) -> bool {
    matches!((left, right), (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_)))
}

fn rejected_assignment(requested: IpNet) -> IpNet {
    match requested {
        IpNet::V4(_) => IpNet::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 32)
            .unwrap_or_else(|_| unreachable!("an IPv4 host prefix is valid")),
        IpNet::V6(_) => IpNet::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 128)
            .unwrap_or_else(|_| unreachable!("an IPv6 host prefix is valid")),
    }
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
