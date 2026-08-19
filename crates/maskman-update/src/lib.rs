#![forbid(unsafe_code)]

use thiserror::Error;

#[derive(Debug, Error)]
pub enum UpdateError {
    #[error("self-update is not implemented in M0; release signing and rollback must land first")]
    NotImplemented,
}

pub fn check() -> Result<(), UpdateError> {
    Err(UpdateError::NotImplemented)
}
