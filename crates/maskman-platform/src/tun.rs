use std::sync::Arc;

use tappers::{Interface, Tun};
use tokio::io::unix::AsyncFd;

use crate::{JournalEntry, NetworkJournal, PlatformError};

#[derive(Debug, Clone)]
pub struct TunConfig {
    pub name: String,
    pub mtu: u16,
}

pub struct TunDevice {
    device: Arc<AsyncFd<Tun>>,
    name: String,
    mtu: u16,
}

impl TunDevice {
    pub fn create(config: TunConfig, journal: &mut NetworkJournal) -> Result<Self, PlatformError> {
        validate(&config)?;
        let requested = Interface::new(&config.name).map_err(PlatformError::TunIo)?;
        let create_unnamed = cfg!(target_os = "macos") && !config.name.starts_with("utun");
        if !create_unnamed && requested.exists().map_err(PlatformError::TunIo)? {
            return Err(PlatformError::InvalidTun(format!(
                "interface {} already exists; cleanup its owned journal entry first",
                config.name
            )));
        }
        let mut device = if create_unnamed {
            Tun::new().map_err(PlatformError::TunIo)?
        } else {
            Tun::new_named(requested).map_err(PlatformError::TunIo)?
        };
        device.set_nonblocking(true).map_err(PlatformError::TunIo)?;
        let actual_name =
            device.name().map_err(PlatformError::TunIo)?.name().to_string_lossy().into_owned();
        journal.record(JournalEntry::Tun { name: actual_name.clone() });
        let device = AsyncFd::new(device).map_err(PlatformError::TunIo)?;
        Ok(Self { device: Arc::new(device), name: actual_name, mtu: config.mtu })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn mtu(&self) -> u16 {
        self.mtu
    }

    pub fn interface_index(&self) -> Result<u32, PlatformError> {
        self.device
            .get_ref()
            .name()
            .map_err(PlatformError::TunIo)?
            .index()
            .map_err(PlatformError::TunIo)
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
    if config.name.trim().is_empty() {
        return Err(PlatformError::InvalidTun("interface name is empty".into()));
    }
    if config.name.len() > 15 {
        return Err(PlatformError::InvalidTun("interface name exceeds the platform limit".into()));
    }
    if config.mtu < 1_280 {
        return Err(PlatformError::InvalidTun("MTU must be at least 1280".into()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{validate, TunConfig};

    #[test]
    fn rejects_unsafe_tun_shape_before_privileged_open() {
        assert!(validate(&TunConfig { name: String::new(), mtu: 1500 }).is_err());
        assert!(validate(&TunConfig { name: "maskman0".into(), mtu: 1279 }).is_err());
        assert!(validate(&TunConfig { name: "maskman0".into(), mtu: 1500 }).is_ok());
    }
}
