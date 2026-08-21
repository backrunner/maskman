use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, Mutex,
};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy)]
pub(crate) enum ActivityKind {
    Connection,
    UdpSession,
    IpSession,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeSnapshot {
    pub uptime_seconds: u64,
    pub active_connections: u64,
    pub accepted_connections: u64,
    pub active_udp_sessions: u64,
    pub active_ip_sessions: u64,
    pub forwarded_packets: u64,
    pub dropped_packets: u64,
    pub last_error: Option<String>,
}

pub(crate) struct RuntimeStats {
    started: std::time::Instant,
    active_connections: AtomicU64,
    accepted_connections: AtomicU64,
    active_udp_sessions: AtomicU64,
    active_ip_sessions: AtomicU64,
    forwarded_packets: AtomicU64,
    dropped_packets: AtomicU64,
    last_error: Mutex<Option<String>>,
}

pub(crate) struct ActivityGuard {
    stats: Arc<RuntimeStats>,
    kind: ActivityKind,
}

impl RuntimeStats {
    pub(crate) fn new() -> Self {
        Self {
            started: std::time::Instant::now(),
            active_connections: AtomicU64::new(0),
            accepted_connections: AtomicU64::new(0),
            active_udp_sessions: AtomicU64::new(0),
            active_ip_sessions: AtomicU64::new(0),
            forwarded_packets: AtomicU64::new(0),
            dropped_packets: AtomicU64::new(0),
            last_error: Mutex::new(None),
        }
    }

    pub(crate) fn begin(self: &Arc<Self>, kind: ActivityKind) -> ActivityGuard {
        match kind {
            ActivityKind::Connection => {
                self.active_connections.fetch_add(1, Ordering::Relaxed);
                self.accepted_connections.fetch_add(1, Ordering::Relaxed);
            }
            ActivityKind::UdpSession => {
                self.active_udp_sessions.fetch_add(1, Ordering::Relaxed);
            }
            ActivityKind::IpSession => {
                self.active_ip_sessions.fetch_add(1, Ordering::Relaxed);
            }
        }
        ActivityGuard { stats: self.clone(), kind }
    }

    pub(crate) fn packet_result(&self, forwarded: bool) {
        let counter = if forwarded { &self.forwarded_packets } else { &self.dropped_packets };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_error(&self, error: impl Into<String>) {
        let mut error = error.into();
        error.truncate(512);
        *self.last_error.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(error);
    }

    pub(crate) fn snapshot(&self) -> RuntimeSnapshot {
        RuntimeSnapshot {
            uptime_seconds: self.started.elapsed().as_secs(),
            active_connections: self.active_connections.load(Ordering::Relaxed),
            accepted_connections: self.accepted_connections.load(Ordering::Relaxed),
            active_udp_sessions: self.active_udp_sessions.load(Ordering::Relaxed),
            active_ip_sessions: self.active_ip_sessions.load(Ordering::Relaxed),
            forwarded_packets: self.forwarded_packets.load(Ordering::Relaxed),
            dropped_packets: self.dropped_packets.load(Ordering::Relaxed),
            last_error: self
                .last_error
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone(),
        }
    }
}

impl Drop for ActivityGuard {
    fn drop(&mut self) {
        let counter = match self.kind {
            ActivityKind::Connection => &self.stats.active_connections,
            ActivityKind::UdpSession => &self.stats.active_udp_sessions,
            ActivityKind::IpSession => &self.stats.active_ip_sessions,
        };
        counter.fetch_sub(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::{ActivityKind, RuntimeStats};

    #[test]
    fn activity_guards_balance_live_counters() {
        let stats = Arc::new(RuntimeStats::new());
        let connection = stats.begin(ActivityKind::Connection);
        let session = stats.begin(ActivityKind::UdpSession);
        stats.packet_result(true);
        stats.packet_result(false);
        let snapshot = stats.snapshot();
        assert_eq!(snapshot.active_connections, 1);
        assert_eq!(snapshot.accepted_connections, 1);
        assert_eq!(snapshot.active_udp_sessions, 1);
        assert_eq!(snapshot.forwarded_packets, 1);
        assert_eq!(snapshot.dropped_packets, 1);
        drop((connection, session));
        assert_eq!(stats.snapshot().active_connections, 0);
        assert_eq!(stats.snapshot().active_udp_sessions, 0);
    }
}
