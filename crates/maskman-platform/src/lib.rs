#![forbid(unsafe_code)]

mod journal;
mod tun;

#[cfg(target_os = "linux")]
mod linux;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum PlatformError {
    #[error("service management is not implemented; use maskman serve")]
    ServiceManagementUnavailable,
    #[error("invalid TUN configuration: {0}")]
    InvalidTun(String),
    #[error("TUN I/O failed: {0}")]
    TunIo(#[source] std::io::Error),
    #[error("network operation failed: {0}")]
    Network(String),
}

pub use journal::{JournalEntry, NetworkJournal};
pub fn platform_name() -> &'static str {
    if cfg!(target_os = "macos") {
        "macOS"
    } else if cfg!(target_os = "linux") {
        "Linux"
    } else {
        "unsupported"
    }
}

pub use tun::{TunConfig, TunDevice};

#[cfg(target_os = "linux")]
pub use linux::LinuxRouteManager;
