use std::path::Path;
use std::sync::Arc;

#[cfg(unix)]
use std::os::fd::{AsRawFd, RawFd};

use tokio::io::unix::AsyncFd;
use tun_rs::{DeviceBuilder, Layer, SyncDevice};

use crate::{JournalEntry, NetworkJournal, PlatformError};

#[derive(Debug, Clone)]
pub struct TunConfig {
    pub name: String,
    pub mtu: u16,
}

pub struct TunDevice {
    device: Arc<AsyncFd<SyncDevice>>,
    name: String,
    mtu: u16,
}

impl TunDevice {
    pub fn create(config: TunConfig, journal: &mut NetworkJournal) -> Result<Self, PlatformError> {
        Self::create_inner(config, journal, None)
    }

    pub fn create_persisted(
        config: TunConfig,
        journal: &mut NetworkJournal,
        journal_path: &Path,
    ) -> Result<Self, PlatformError> {
        Self::create_inner(config, journal, Some(journal_path))
    }

    fn create_inner(
        config: TunConfig,
        journal: &mut NetworkJournal,
        journal_path: Option<&Path>,
    ) -> Result<Self, PlatformError> {
        validate(&config)?;
        let pending = JournalEntry::TunPending { name: config.name.clone() };
        if let Some(path) = journal_path {
            journal.prepare(pending, path)?;
        } else {
            journal.record(pending);
        }
        let mut builder =
            DeviceBuilder::new().mtu(config.mtu).layer(Layer::L3).packet_information(false);
        if cfg!(target_os = "linux") || config.name.starts_with("utun") {
            builder = builder.name(&config.name);
        }
        let device = builder.build_sync().map_err(PlatformError::TunIo)?;
        device.set_nonblocking(true).map_err(PlatformError::TunIo)?;
        let actual_name = device.name().map_err(PlatformError::TunIo)?;
        validate(&TunConfig { name: actual_name.clone(), mtu: config.mtu })?;
        if let Some(path) = journal_path {
            journal.replace_last_tun_pending(actual_name.clone(), path)?;
        } else if let Some(JournalEntry::TunPending { .. }) = journal.entries().last() {
            let _ = journal.replace_last_tun_pending_without_persist(actual_name.clone());
        }
        let device = AsyncFd::new(device).map_err(PlatformError::TunIo)?;
        Ok(Self { device: Arc::new(device), name: actual_name, mtu: config.mtu })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn mtu(&self) -> u16 {
        self.mtu
    }

    #[cfg(unix)]
    pub(crate) fn from_inherited_fd(
        raw_fd: RawFd,
        name: String,
        mtu: u16,
    ) -> Result<Self, PlatformError> {
        validate(&TunConfig { name: name.clone(), mtu })?;
        if raw_fd < 0 {
            return Err(PlatformError::InvalidTun("worker received an invalid TUN fd".into()));
        }
        // SAFETY: the worker receives ownership of a descriptor opened by the
        // supervisor and consumes it exactly once.
        let device = unsafe { SyncDevice::from_fd(raw_fd) }.map_err(PlatformError::TunIo)?;
        device.set_nonblocking(true).map_err(PlatformError::TunIo)?;
        let actual_name = device.name().unwrap_or(name);
        let device = AsyncFd::new(device).map_err(PlatformError::TunIo)?;
        Ok(Self { device: Arc::new(device), name: actual_name, mtu })
    }

    pub fn interface_index(&self) -> Result<u32, PlatformError> {
        self.device.get_ref().if_index().map_err(PlatformError::TunIo)
    }

    #[cfg(unix)]
    pub fn raw_fd(&self) -> Result<RawFd, PlatformError> {
        Ok(self.device.get_ref().as_raw_fd())
    }

    #[cfg(unix)]
    pub fn prepare_inheritance(&self) -> Result<(), PlatformError> {
        crate::make_inheritable(self.device.get_ref())
    }

    pub async fn recv(&self, packet: &mut [u8]) -> Result<usize, PlatformError> {
        loop {
            let mut guard = self.device.readable().await.map_err(PlatformError::TunIo)?;
            match guard.try_io(|inner| inner.get_ref().recv(packet)) {
                Ok(result) => return result.map_err(PlatformError::TunIo),
                Err(_) => continue,
            }
        }
    }

    pub async fn send(&self, packet: &[u8]) -> Result<usize, PlatformError> {
        loop {
            let mut guard = self.device.writable().await.map_err(PlatformError::TunIo)?;
            match guard.try_io(|inner| inner.get_ref().send(packet)) {
                Ok(result) => return result.map_err(PlatformError::TunIo),
                Err(_) => continue,
            }
        }
    }
}

fn validate(config: &TunConfig) -> Result<(), PlatformError> {
    if !cfg!(target_os = "macos") && config.name.trim().is_empty() {
        return Err(PlatformError::InvalidTun("interface name is empty".into()));
    }
    if config.name.len() > 15 {
        return Err(PlatformError::InvalidTun("interface name exceeds the platform limit".into()));
    }
    if config.mtu < 1_280 {
        return Err(PlatformError::InvalidTun("MTU must be at least 1280".into()));
    }
    #[cfg(target_os = "linux")]
    if !config.name.starts_with("maskman") {
        return Err(PlatformError::InvalidTun(
            "Linux TUN names must use the maskman ownership prefix".into(),
        ));
    }
    #[cfg(target_os = "macos")]
    if !config.name.is_empty() && !config.name.starts_with("utun") {
        return Err(PlatformError::InvalidTun(
            "macOS TUN names must use the utun ownership prefix".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{validate, TunConfig};

    #[test]
    fn rejects_unsafe_tun_shape_before_privileged_open() {
        if !cfg!(target_os = "macos") {
            assert!(validate(&TunConfig { name: String::new(), mtu: 1500 }).is_err());
        }
        assert!(validate(&TunConfig { name: "maskman0".into(), mtu: 1279 }).is_err());
        let valid_name = if cfg!(target_os = "macos") { "" } else { "maskman0" };
        assert!(validate(&TunConfig { name: valid_name.into(), mtu: 1500 }).is_ok());
    }
}
