use std::{collections::HashMap, net::IpAddr, sync::Mutex};

use bytes::Bytes;
use maskman_protocol::{
    capsule::{AddressRange, RouteAdvertisement},
    packet::{is_icmp_protocol, PacketView},
};

use super::ip::{IpControlError, IpDropReason, IpSessionHandle};

const MAX_REGISTRY_ROUTES: usize = 4_096;

#[derive(Default)]
pub struct IpSessionRegistry {
    state: Mutex<IpRegistryState>,
}

#[derive(Default)]
struct IpRegistryState {
    streams: HashMap<SessionKey, IpSessionHandle>,
    addresses: HashMap<IpAddr, SessionKey>,
    routes: Vec<RegisteredRoute>,
}

#[derive(Clone)]
struct RegisteredRoute {
    range: AddressRange,
    session: SessionKey,
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
                .assigned()
                .iter()
                .any(|address| state.addresses.contains_key(&address.network()))
        {
            return false;
        }
        for address in session.assigned().iter().map(|prefix| prefix.network()) {
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
        state.routes.retain(|route| route.session != key);
        Some(session)
    }

    pub fn replace_routes(
        &self,
        connection_id: u64,
        stream_id: u64,
        value: &[u8],
    ) -> Result<(), IpControlError> {
        let key = SessionKey { connection_id, stream_id };
        let session = {
            let state = self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            state.streams.get(&key).cloned().ok_or(IpControlError::SessionClosed)?
        };
        let next = session.validate_routes(value)?;
        let mut state = self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if !state.streams.contains_key(&key) {
            return Err(IpControlError::SessionClosed);
        }
        validate_replacement(&state, key, &next)?;
        state.routes.retain(|route| route.session != key);
        state.routes.extend(
            next.ranges().iter().cloned().map(|range| RegisteredRoute { range, session: key }),
        );
        sort_routes(&mut state.routes);
        session.commit_routes(next);
        Ok(())
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
        let packet = PacketView::parse(&payload).map_err(|_| IpDropReason::Malformed)?;
        let session = {
            let state = self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            let key = select_session(&state, packet).ok_or(IpDropReason::Destination)?;
            state.streams.get(&key).cloned().ok_or(IpDropReason::Destination)?
        };
        session.try_send_from_tun(payload)
    }
}

fn validate_replacement(
    state: &IpRegistryState,
    key: SessionKey,
    next: &RouteAdvertisement,
) -> Result<(), IpControlError> {
    let retained = state.routes.iter().filter(|route| route.session != key).count();
    if retained + next.ranges().len() > MAX_REGISTRY_ROUTES {
        return Err(IpControlError::RouteCapacity);
    }
    if next.ranges().iter().any(|candidate| {
        state
            .routes
            .iter()
            .any(|route| route.session != key && candidate.conflicts_with(&route.range))
    }) {
        return Err(IpControlError::RouteConflict);
    }
    Ok(())
}

fn sort_routes(routes: &mut [RegisteredRoute]) {
    routes.sort_by_key(|route| {
        (
            route.range.start.is_ipv4() as u8,
            route.range.protocol,
            route.range.start,
            route.range.end,
            route.session.connection_id,
            route.session.stream_id,
        )
    });
}

fn select_session(state: &IpRegistryState, packet: PacketView<'_>) -> Option<SessionKey> {
    if let Some(key) = state.addresses.get(&packet.destination()) {
        return Some(*key);
    }
    let invocation = if is_icmp_protocol(packet.protocol()) {
        packet.icmp_invoking_packet().ok().flatten()
    } else {
        None
    };
    state
        .routes
        .iter()
        .find(|route| {
            invocation.map_or_else(
                || route.range.permits(packet.destination(), packet.protocol()),
                |invoking| route.range.permits(invoking.destination(), invoking.protocol()),
            )
        })
        .map(|route| route.session)
}
