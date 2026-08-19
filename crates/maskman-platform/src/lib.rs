#![forbid(unsafe_code)]

use thiserror::Error;

#[derive(Debug, Error)]
pub enum PlatformError {
    #[error("service management is not implemented in M0; use maskman serve")]
    ServiceManagementUnavailable,
}

pub fn platform_name() -> &'static str {
    if cfg!(target_os = "macos") {
        "macOS"
    } else if cfg!(target_os = "linux") {
        "Linux"
    } else {
        "unsupported"
    }
}
