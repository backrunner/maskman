use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant},
};

use bytes::Bytes;

use crate::proxy::udp::UdpSessionHandle;

#[derive(Default)]
pub struct SessionRegistry {
    sessions: Mutex<HashMap<u64, UdpSessionHandle>>,
}

#[derive(Default)]
pub struct QuotaState {
    active: Mutex<HashMap<String, u32>>,
    new_tunnels: Mutex<HashMap<String, TunnelWindow>>,
}

struct TunnelWindow {
    started: Instant,
    count: u32,
}

pub struct QuotaPermit {
    state: std::sync::Arc<QuotaState>,
    principal: String,
}

impl QuotaState {
    pub fn acquire(
        state: std::sync::Arc<Self>,
        principal: &str,
        active_limit: u32,
        new_tunnels_per_minute: u32,
    ) -> Option<QuotaPermit> {
        let mut active = state.active.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let count = active.entry(principal.to_owned()).or_default();
        if *count >= active_limit {
            return None;
        }
        *count += 1;
        drop(active);
        let mut windows = state.new_tunnels.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let window = windows
            .entry(principal.to_owned())
            .or_insert(TunnelWindow { started: Instant::now(), count: 0 });
        if window.started.elapsed() >= Duration::from_secs(60) {
            window.started = Instant::now();
            window.count = 0;
        }
        if window.count >= new_tunnels_per_minute {
            drop(windows);
            let mut active = state.active.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            if let Some(count) = active.get_mut(principal) {
                *count = count.saturating_sub(1);
            }
            return None;
        }
        window.count += 1;
        drop(windows);
        Some(QuotaPermit { state, principal: principal.to_owned() })
    }
}

impl Drop for QuotaPermit {
    fn drop(&mut self) {
        let mut active = self.state.active.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(count) = active.get_mut(&self.principal) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                active.remove(&self.principal);
            }
        }
    }
}

impl SessionRegistry {
    pub fn insert(&self, stream_id: u64, session: UdpSessionHandle) -> bool {
        use std::collections::hash_map::Entry;

        let mut sessions = self.sessions.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        match sessions.entry(stream_id) {
            Entry::Vacant(entry) => {
                entry.insert(session);
                true
            }
            Entry::Occupied(_) => false,
        }
    }

    pub fn remove(&self, stream_id: u64) -> Option<UdpSessionHandle> {
        self.sessions.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).remove(&stream_id)
    }

    pub fn try_send(&self, stream_id: u64, payload: Bytes) -> Option<bool> {
        let sessions = self.sessions.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        sessions.get(&stream_id).map(|session| session.try_send(payload))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::QuotaState;

    #[test]
    fn active_and_new_tunnel_limits_are_bounded() {
        let state = Arc::new(QuotaState::default());
        let first = QuotaState::acquire(state.clone(), "client", 1, 2);
        assert!(first.is_some());
        assert!(QuotaState::acquire(state.clone(), "client", 1, 2).is_none());
        drop(first);
        let second = QuotaState::acquire(state.clone(), "client", 1, 2);
        assert!(second.is_some());
        drop(second);
        assert!(QuotaState::acquire(state, "client", 1, 2).is_none());
    }
}
