#![forbid(unsafe_code)]

mod journal;
mod service;
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
    #[error("service operation failed: {0}")]
    ServiceCommand(#[source] std::io::Error),
    #[error("service file operation failed: {0}")]
    ServiceIo(#[source] std::io::Error),
    #[error("service definition is not installed")]
    ServiceNotInstalled,
    #[error("invalid service specification: {0}")]
    InvalidService(String),
    #[error("resource journal operation failed: {0}")]
    Journal(#[source] std::io::Error),
    #[error("resource cleanup is not supported for this journal entry: {0}")]
    UnsupportedCleanup(String),
}

pub use journal::{cleanup as cleanup_journal, CleanupReport, JournalEntry, NetworkJournal};
pub use service::{
    control as service_control, default_config_path, default_service_path, default_state_dir,
    install as install_service, status as service_status, uninstall as uninstall_service,
    ServiceAction, ServiceSpec, ServiceStatus,
};
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
