use std::{
    net::{SocketAddr, UdpSocket},
    path::{Path, PathBuf},
};

use maskman_config::CompiledConfig;
use maskman_platform::{NetworkJournal, TunConfig, TunDevice};

use crate::ServerError;

/// Handles opened and owned by the supervisor until the worker exits.
///
/// Listener sockets and the TUN descriptor are deliberately kept alive in the
/// parent while the child is being spawned. The journal is persisted before
/// the child starts so a supervisor crash leaves an inspectable cleanup plan.
pub struct PreparedResources {
    pub(crate) listeners: Vec<UdpSocket>,
    pub(crate) tun: Option<TunDevice>,
    pub(crate) journal_path: Option<PathBuf>,
}

impl PreparedResources {
    pub(crate) fn journal_path(&self) -> Option<&Path> {
        self.journal_path.as_deref()
    }

    pub(crate) fn listener_fds(&self) -> Result<Vec<i32>, ServerError> {
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            for socket in &self.listeners {
                maskman_platform::make_inheritable(socket)
                    .map_err(|error| ServerError::Transport(error.to_string()))?;
            }
            Ok(self.listeners.iter().map(AsRawFd::as_raw_fd).collect())
        }
        #[cfg(not(unix))]
        {
            Err(ServerError::Transport("worker fd inheritance is unavailable".into()))
        }
    }

    pub(crate) fn tun_fd(&self) -> Result<Option<i32>, ServerError> {
        let Some(tun) = self.tun.as_ref() else { return Ok(None) };
        #[cfg(unix)]
        {
            tun.prepare_inheritance().map_err(|error| ServerError::Transport(error.to_string()))?;
            tun.raw_fd().map(Some).map_err(|error| ServerError::Transport(error.to_string()))
        }
        #[cfg(not(unix))]
        {
            let _ = tun;
            Err(ServerError::Transport("worker fd inheritance is unavailable".into()))
        }
    }

    pub(crate) fn into_worker_parts(self) -> (Vec<UdpSocket>, Option<TunDevice>, Option<PathBuf>) {
        (self.listeners, self.tun, self.journal_path)
    }
}

pub async fn prepare(config: &CompiledConfig) -> Result<PreparedResources, ServerError> {
    let journal_path = config.ip.enabled.then(|| config.state_dir.join("resource-journal.json"));
    let mut journal = match journal_path.as_deref() {
        Some(path) => {
            let journal = NetworkJournal::load(path)
                .map_err(|error| ServerError::Transport(error.to_string()))?;
            if !journal.is_empty() {
                return Err(ServerError::Transport(format!(
                    "owned platform resources remain in {}; run maskman cleanup before starting",
                    path.display()
                )));
            }
            Some(journal)
        }
        None => None,
    };
    let listeners = bind_listeners(&config.listen)?;
    if !config.ip.enabled {
        return Ok(PreparedResources { listeners, tun: None, journal_path: None });
    }
    let journal_path = journal_path
        .as_deref()
        .ok_or_else(|| ServerError::Transport("IP journal path was not initialized".into()))?;
    let mut journal = journal
        .take()
        .ok_or_else(|| ServerError::Transport("IP journal was not initialized".into()))?;

    if let Err(error) = maskman_platform::enable_forwarding_persisted(&mut journal, journal_path) {
        rollback_sysctls(&journal);
        let _ = cleanup_failed_start(journal_path).await;
        return Err(ServerError::Transport(error.to_string()));
    }
    if let Err(error) = persist(&journal, journal_path) {
        let _ = cleanup_failed_start(journal_path).await;
        return Err(error);
    }

    if config.ip.nat_managed {
        if let Err(error) = maskman_platform::apply_managed_nat_persisted(
            maskman_platform::ManagedNatConfig {
                egress_interface: &config.ip.nat_egress_interface,
                ipv4_pool: config.ip.ipv4_pool,
                ipv6_pool: config.ip.ipv6_pool,
            },
            &mut journal,
            journal_path,
        ) {
            let _ = cleanup_failed_start(journal_path).await;
            return Err(ServerError::Transport(error.to_string()));
        }
        if let Err(error) = persist(&journal, journal_path) {
            let _ = cleanup_failed_start(journal_path).await;
            return Err(error);
        }
    }

    let tun = match TunDevice::create_persisted(
        TunConfig { name: config.ip.interface_name.clone(), mtu: config.ip.mtu as u16 },
        &mut journal,
        journal_path,
    ) {
        Ok(device) => device,
        Err(error) => {
            let _ = cleanup_failed_start(journal_path).await;
            return Err(ServerError::Transport(error.to_string()));
        }
    };
    if let Err(error) = persist(&journal, journal_path) {
        let _ = cleanup_failed_start(journal_path).await;
        return Err(error);
    }
    if let Err(error) = provision_routes(config, &tun, &mut journal, journal_path).await {
        let _ = cleanup_failed_start(journal_path).await;
        return Err(error);
    }
    Ok(PreparedResources {
        listeners,
        tun: Some(tun),
        journal_path: Some(journal_path.to_path_buf()),
    })
}

pub async fn cleanup(path: Option<&Path>) -> Result<(), ServerError> {
    let Some(path) = path else { return Ok(()) };
    maskman_platform::cleanup_journal(path, false)
        .await
        .map(|_| ())
        .map_err(|error| ServerError::Transport(format!("resource cleanup failed: {error}")))
}

async fn cleanup_failed_start(path: &Path) -> Result<(), maskman_platform::PlatformError> {
    let journal = maskman_platform::NetworkJournal::load(path)?;
    if journal.entries().iter().any(is_pending) {
        // A pending entry means the platform mutation may have completed but
        // its active journal promotion was not durably observed. Keep the
        // ownership record for an explicit operator cleanup instead of
        // deleting evidence and risking an orphaned resource.
        return Ok(());
    }
    maskman_platform::cleanup_journal(path, false).await.map(|_| ())
}

fn is_pending(entry: &maskman_platform::JournalEntry) -> bool {
    matches!(
        entry,
        maskman_platform::JournalEntry::TunPending { .. }
            | maskman_platform::JournalEntry::RoutePending { .. }
            | maskman_platform::JournalEntry::RouteNamedPending { .. }
            | maskman_platform::JournalEntry::NatPending { .. }
            | maskman_platform::JournalEntry::SysctlPending { .. }
    )
}

fn bind_listeners(addresses: &[SocketAddr]) -> Result<Vec<UdpSocket>, ServerError> {
    let mut listeners = Vec::with_capacity(addresses.len());
    for address in addresses {
        let socket = UdpSocket::bind(address).map_err(|error| {
            ServerError::Transport(format!("bind QUIC listener {address}: {error}"))
        })?;
        socket.set_nonblocking(true).map_err(|error| {
            ServerError::Transport(format!("configure QUIC listener {address}: {error}"))
        })?;
        listeners.push(socket);
    }
    Ok(listeners)
}

fn persist(journal: &NetworkJournal, path: &Path) -> Result<(), ServerError> {
    journal.persist(path).map_err(|error| ServerError::Transport(error.to_string()))
}

fn rollback_sysctls(journal: &NetworkJournal) {
    for entry in journal.entries().iter().rev() {
        if matches!(entry, maskman_platform::JournalEntry::Sysctl { .. }) {
            let _ = maskman_platform::restore_forwarding(entry);
        }
    }
}

#[cfg(target_os = "linux")]
async fn provision_routes(
    config: &CompiledConfig,
    device: &TunDevice,
    journal: &mut NetworkJournal,
    journal_path: &Path,
) -> Result<(), ServerError> {
    let interface_index =
        device.interface_index().map_err(|error| ServerError::Transport(error.to_string()))?;
    let manager = maskman_platform::LinuxRouteManager::connect()
        .map_err(|error| ServerError::Transport(error.to_string()))?;
    for route in [config.ip.ipv4_pool, config.ip.ipv6_pool].into_iter().flatten() {
        manager
            .add_route_persisted(route, interface_index, journal, journal_path)
            .await
            .map_err(|error| ServerError::Transport(error.to_string()))?;
        persist(journal, journal_path)?;
    }
    Ok(())
}

#[cfg(target_os = "macos")]
async fn provision_routes(
    config: &CompiledConfig,
    device: &TunDevice,
    journal: &mut NetworkJournal,
    journal_path: &Path,
) -> Result<(), ServerError> {
    let manager = maskman_platform::MacRouteManager::connect()
        .map_err(|error| ServerError::Transport(error.to_string()))?;
    for route in [config.ip.ipv4_pool, config.ip.ipv6_pool].into_iter().flatten() {
        manager
            .add_route_persisted(route, device.name(), journal, journal_path)
            .map_err(|error| ServerError::Transport(error.to_string()))?;
        persist(journal, journal_path)?;
    }
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
async fn provision_routes(
    _config: &CompiledConfig,
    _device: &TunDevice,
    _journal: &mut NetworkJournal,
    _journal_path: &Path,
) -> Result<(), ServerError> {
    Err(ServerError::Transport("route provisioning is unavailable on this platform".into()))
}
