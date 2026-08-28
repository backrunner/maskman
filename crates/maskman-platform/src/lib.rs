// Platform is the only crate allowed to contain narrowly-scoped fd ownership
// shims. Every unsafe block below documents the descriptor invariant it relies
// on; protocol and CLI crates remain `forbid(unsafe_code)`.
#![allow(unsafe_code)]

mod forwarding;
mod identity;
mod journal;
mod nat;
mod privilege;
mod service;
mod tun;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "linux")]
mod service_openrc;
#[cfg(target_os = "linux")]
mod service_systemd;

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

pub use forwarding::{enable_forwarding, enable_forwarding_persisted, restore_forwarding};
pub use identity::{ensure_worker_identity, WorkerIdentityProvision};
pub use journal::{cleanup as cleanup_journal, CleanupReport, JournalEntry, NetworkJournal};
pub use nat::{
    apply_managed_nat, apply_managed_nat_persisted, cleanup_managed_nat, managed_nat_available,
    managed_nat_resource_id, ManagedNatConfig,
};
pub use privilege::{
    apply_worker_hardening, control_peer_allowed, current_uid, inherited_tun, inherited_udp,
    make_inheritable, prepare_worker_access, spawn_worker, terminate_worker, worker_identity,
    worker_identity_available,
};
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
#[cfg(target_os = "macos")]
pub use macos::MacRouteManager;
