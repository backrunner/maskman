use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, Mutex, RwLock,
};

use bytes::Bytes;
use maskman_config::CompiledConfig;
use tokio::sync::mpsc;

use crate::{
    proxy::{address_pool::AddressPoolSet, ip::IpSessionRegistry},
    session::QuotaState,
    stats::{RuntimeSnapshot, RuntimeStats},
};

pub struct TransportContext {
    config: RwLock<Arc<CompiledConfig>>,
    config_generation: AtomicU64,
    pub(crate) quotas: Arc<QuotaState>,
    pub(crate) ip_registry: Arc<IpSessionRegistry>,
    pub(crate) address_pools: Arc<AddressPoolSet>,
    pub(crate) tun_tx: mpsc::Sender<Bytes>,
    tun_rx: Mutex<Option<mpsc::Receiver<Bytes>>>,
    next_connection_id: AtomicU64,
    pub(crate) stats: Arc<RuntimeStats>,
}

impl TransportContext {
    pub fn new(config: Arc<CompiledConfig>) -> Self {
        let (tun_tx, tun_rx) = mpsc::channel(64);
        Self {
            address_pools: Arc::new(AddressPoolSet::from_config(&config.ip)),
            config: RwLock::new(config),
            config_generation: AtomicU64::new(1),
            quotas: Arc::new(QuotaState::default()),
            ip_registry: Arc::new(IpSessionRegistry::default()),
            tun_tx,
            tun_rx: Mutex::new(Some(tun_rx)),
            next_connection_id: AtomicU64::new(1),
            stats: Arc::new(RuntimeStats::new()),
        }
    }

    pub fn config_snapshot(&self) -> Arc<CompiledConfig> {
        self.config.read().unwrap_or_else(|poisoned| poisoned.into_inner()).clone()
    }

    pub fn config_generation(&self) -> u64 {
        self.config_generation.load(Ordering::Acquire)
    }

    pub fn runtime_snapshot(&self) -> RuntimeSnapshot {
        self.stats.snapshot()
    }

    pub(crate) fn stats_handle(&self) -> Arc<RuntimeStats> {
        self.stats.clone()
    }

    pub(crate) fn record_runtime_error(&self, error: impl Into<String>) {
        self.stats.record_error(error);
    }

    pub(crate) fn reload(&self, config: CompiledConfig) -> Result<(), String> {
        let mut current = self.config.write().unwrap_or_else(|poisoned| poisoned.into_inner());
        ensure_reload_compatible(&current, &config)?;
        *current = Arc::new(config);
        self.config_generation.fetch_add(1, Ordering::Release);
        Ok(())
    }

    pub fn take_tun_receiver(&self) -> Option<mpsc::Receiver<Bytes>> {
        self.tun_rx.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).take()
    }

    pub fn dispatch_tun_packet(&self, payload: Bytes) -> bool {
        match self.ip_registry.dispatch_tun(payload) {
            Ok(()) => true,
            Err(reason) => {
                // Active sessions account for validation; only a registry miss
                // needs accounting at this boundary.
                if matches!(reason, crate::proxy::ip::IpDropReason::Destination) {
                    self.stats.packet_result(false);
                }
                false
            }
        }
    }

    pub(super) fn next_connection_id(&self) -> u64 {
        self.next_connection_id.fetch_add(1, Ordering::Relaxed)
    }
}

fn ensure_reload_compatible(current: &CompiledConfig, next: &CompiledConfig) -> Result<(), String> {
    let mut changed = Vec::new();
    if current.listen != next.listen {
        changed.push("server.listen");
    }
    if current.base_path != next.base_path {
        changed.push("server.base_path");
    }
    if current.idle_timeout != next.idle_timeout
        || current.drain_timeout != next.drain_timeout
        || current.max_connections != next.max_connections
        || current.max_requests_per_connection != next.max_requests_per_connection
        || current.max_header_bytes != next.max_header_bytes
    {
        changed.push("server transport limits");
    }
    if current.state_dir != next.state_dir {
        changed.push("server.state_dir");
    }
    if current.certificate_file != next.certificate_file
        || current.private_key_file != next.private_key_file
        || current.client_ca_file != next.client_ca_file
        || std::mem::discriminant(&current.auth_mode) != std::mem::discriminant(&next.auth_mode)
    {
        changed.push("TLS/auth transport mode");
    }
    if !same_ip_config(&current.ip, &next.ip) {
        changed.push("proxy.ip");
    }
    if current.metrics_listen != next.metrics_listen {
        changed.push("observability.metrics_listen");
    }
    if changed.is_empty() {
        Ok(())
    } else {
        Err(format!("reload requires restart because {} changed", changed.join(", ")))
    }
}

fn same_ip_config(left: &maskman_config::CompiledIp, right: &maskman_config::CompiledIp) -> bool {
    left.enabled == right.enabled
        && left.interface_name == right.interface_name
        && left.mtu == right.mtu
        && left.ipv4_pool == right.ipv4_pool
        && left.ipv6_pool == right.ipv6_pool
        && left.advertise_routes == right.advertise_routes
        && left.nat_managed == right.nat_managed
        && left.nat_egress_interface == right.nat_egress_interface
}
