use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Arc, Mutex},
};

use bytes::Bytes;
use ipnet::IpNet;
use maskman_protocol::{
    capsule::{
        decode_route_advertisement, encode_address_assign, AddressError, AssignedAddress,
        RouteAdvertisement, RouteError,
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

    pub fn assignment_capsule(
        &self,
        request_ids: impl IntoIterator<Item = u64>,
    ) -> Result<Vec<u8>, AddressError> {
        let prefixes = self.assigned().to_vec();
        let entries = request_ids
            .into_iter()
            .zip(prefixes.iter().cycle())
            .map(|(request_id, prefix)| AssignedAddress { request_id, prefix: *prefix })
            .collect::<Vec<_>>();
        let mut encoded = Vec::new();
        encode_address_assign(&entries, &mut encoded)?;
        Ok(encoded)
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
mod tests {
    use std::sync::Arc;

    use bytes::Bytes;
    use maskman_config::model::ConfigDocument;
    use maskman_protocol::connect::{IpProtocolScope, IpScope, IpTarget};

    use super::{AddressPoolSet, IpDropReason, IpSession, IpSessionRegistry};
    use crate::{auth::Principal, policy};

    fn session() -> (super::IpSession, tokio::sync::mpsc::Receiver<Bytes>) {
        let mut document = ConfigDocument::default();
        document.auth.principals.push(maskman_config::model::PrincipalConfig {
            id: "client".into(),
            roles: vec!["ip".into()],
            certificate_sha256: Vec::new(),
        });
        document.policy.roles.push(maskman_config::model::RoleConfig {
            name: "ip".into(),
            capabilities: vec!["connect-ip".into()],
            allow_destinations: vec!["8.8.8.0/24".into()],
            deny_destinations: Vec::new(),
            deny_private: true,
            allowed_ip_protocols: vec!["17".into()],
            limits: Default::default(),
        });
        document.proxy.ip.client_ipv4_pool = Some("100.96.0.0/30".into());
        let config = maskman_config::compile_document(&document, std::path::Path::new("."))
            .unwrap_or_else(|error| panic!("compile IP config: {error}"));
        let pools = AddressPoolSet::from_config(&config.ip);
        let policy = Arc::new(policy::compile(
            Arc::new(config),
            &Principal { id: "client".into(), roles: vec!["ip".into()] },
        ));
        let (tun_tx, _tun_rx) = tokio::sync::mpsc::channel(8);
        let session = IpSession::start(
            IpScope { target: IpTarget::Any, protocol: IpProtocolScope::Number(17) },
            &pools,
            policy,
            1500,
            tun_tx,
        )
        .unwrap_or_else(|| panic!("start IP session"));
        (session, _tun_rx)
    }

    #[test]
    fn source_and_protocol_are_enforced() {
        let (session, _tun_rx) = session();
        let assigned = session.handle.assigned()[0].network();
        let mut packet = vec![
            0x45, 0, 0, 28, 0, 0, 0, 0, 64, 17, 0, 0, 0, 0, 0, 0, 8, 8, 8, 8, 1, 2, 3, 4, 0, 0, 0,
            0,
        ];
        packet[12..16].copy_from_slice(&match assigned {
            std::net::IpAddr::V4(address) => address.octets(),
            std::net::IpAddr::V6(_) => [0, 0, 0, 0],
        });
        let packet_checksum = checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&packet_checksum.to_be_bytes());
        assert_eq!(session.handle.try_send(Bytes::from(packet.clone())), Ok(()));
        let mut wrong = packet;
        wrong[9] = 6;
        wrong[10] = 0;
        wrong[11] = 0;
        let wrong_checksum = checksum(&wrong[..20]);
        wrong[10..12].copy_from_slice(&wrong_checksum.to_be_bytes());
        assert_eq!(session.handle.try_send(Bytes::from(wrong)), Err(IpDropReason::Protocol));
    }

    #[test]
    fn registry_dispatches_only_to_assigned_destination() {
        let (session, _tun_rx) = session();
        let destination = session.handle.assigned()[0].network();
        let registry = IpSessionRegistry::default();
        assert!(registry.insert(1, 4, session.handle.clone()));
        let mut packet = vec![0x45, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0, 8, 8, 8, 8, 0, 0, 0, 0];
        packet[16..20].copy_from_slice(&match destination {
            std::net::IpAddr::V4(address) => address.octets(),
            std::net::IpAddr::V6(_) => [0, 0, 0, 0],
        });
        let checksum = checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&checksum.to_be_bytes());
        assert!(registry.dispatch_tun(Bytes::from(packet)).is_ok());
    }

    #[test]
    fn reverse_packets_use_route_and_principal_scope() {
        let (session, _tun_rx) = session();
        let route = maskman_protocol::capsule::RouteAdvertisement::new(vec![
            maskman_protocol::capsule::AddressRange {
                start: "8.8.8.0"
                    .parse()
                    .unwrap_or_else(|error| panic!("parse route start: {error}")),
                end: "8.8.8.255".parse().unwrap_or_else(|error| panic!("parse route end: {error}")),
                protocol: 17,
            },
        ])
        .unwrap_or_else(|error| panic!("build route: {error}"));
        let mut encoded = Vec::new();
        maskman_protocol::capsule::encode_route_advertisement(&route, &mut encoded)
            .unwrap_or_else(|error| panic!("encode route: {error}"));
        session
            .handle
            .replace_routes(&encoded)
            .unwrap_or_else(|error| panic!("install route: {error}"));

        let assigned = match session.handle.assigned()[0].network() {
            std::net::IpAddr::V4(address) => address.octets(),
            std::net::IpAddr::V6(_) => panic!("expected IPv4 assignment"),
        };
        let allowed = ipv4_packet([8, 8, 8, 8], assigned, 64);
        assert_eq!(session.handle.try_send_from_tun(Bytes::from(allowed)), Ok(()));
        let denied = ipv4_packet([1, 1, 1, 1], assigned, 64);
        assert_eq!(
            session.handle.try_send_from_tun(Bytes::from(denied)),
            Err(IpDropReason::Source)
        );
    }

    fn ipv4_packet(source: [u8; 4], destination: [u8; 4], ttl: u8) -> Vec<u8> {
        let total = 20;
        let mut packet = vec![0u8; total];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        packet[8] = ttl;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&source);
        packet[16..20].copy_from_slice(&destination);
        let checksum = checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&checksum.to_be_bytes());
        packet
    }

    fn checksum(header: &[u8]) -> u16 {
        let mut sum = 0u32;
        for pair in header.chunks_exact(2) {
            sum += u32::from(u16::from_be_bytes([pair[0], pair[1]]));
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }
}
