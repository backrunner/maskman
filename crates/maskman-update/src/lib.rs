#![forbid(unsafe_code)]

use std::{io, path::PathBuf, time::Duration};

use ed25519_dalek::VerifyingKey;
use reqwest::blocking::Client;
use semver::Version;
use thiserror::Error;

mod install;
mod install_paths;
mod release;
mod target;
mod verify;

pub use install::install_verified;
pub use release::ReleaseInfo;
pub use target::target_triple;

pub(crate) const API_BASE: &str = "https://api.github.com";
pub(crate) const MAX_DOWNLOAD_BYTES: usize = 128 * 1024 * 1024;
pub(crate) const MAX_ARCHIVE_FILE_BYTES: u64 = 64 * 1024 * 1024;
pub(crate) const MAX_ARCHIVE_TOTAL_BYTES: u64 = 128 * 1024 * 1024;
pub(crate) const MAX_ARCHIVE_ENTRIES: usize = 512;
pub(crate) const MAX_HEALTH_WAIT: Duration = Duration::from_secs(5);

pub(crate) const INSECURE_TEST_PUBLIC_KEY_HEX: &str =
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
pub const RELEASE_PUBLIC_KEY_HEX: Option<&str> = option_env!("MASKMAN_RELEASE_PUBLIC_KEY_HEX");

#[derive(Debug, Error)]
pub enum UpdateError {
    #[error("invalid GitHub repository `{0}`")]
    InvalidRepository(String),
    #[error("invalid version `{0}`")]
    InvalidVersion(String),
    #[error("the current target is not one of the supported release triples")]
    UnsupportedTarget,
    #[error(
        "self-update is disabled because this binary was built without \
         MASKMAN_RELEASE_PUBLIC_KEY_HEX"
    )]
    ReleaseKeyUnavailable,
    #[error("self-update refuses the public RFC 8032 test key")]
    InsecureReleaseKey,
    #[error("GitHub release request failed: {0}")]
    Http(String),
    #[error("no signed release was found for version {0} and target {1}")]
    ReleaseNotFound(String, String),
    #[error("maskman {0} is already the newest signed release for {1}")]
    NoUpdateAvailable(String, String),
    #[error("release asset `{0}` is missing")]
    MissingAsset(String),
    #[error("release asset exceeds the {0} byte limit")]
    DownloadTooLarge(usize),
    #[error("SHA-256 digest does not match the signed release asset")]
    DigestMismatch,
    #[error("release signature is invalid")]
    SignatureInvalid,
    #[error("release signature has an invalid encoding")]
    SignatureEncoding,
    #[error("archive is invalid: {0}")]
    Archive(String),
    #[error("update filesystem operation failed: {0}")]
    Io(#[source] io::Error),
    #[error("staged binary check failed: {0}")]
    StagedCheck(String),
    #[error("service health check failed: {0}")]
    Health(String),
    #[error("update rollback failed: {0}")]
    Rollback(String),
}

pub trait ServiceController {
    fn stop(&self) -> Result<(), UpdateError>;
    fn start(&self) -> Result<(), UpdateError>;
    fn healthy(&self) -> Result<bool, UpdateError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedArtifact {
    pub version: Version,
    pub archive: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallOutcome {
    pub version: Version,
    pub backup: Option<PathBuf>,
    pub rolled_back: bool,
}

pub(crate) struct UpdateClientState {
    pub repository: String,
    pub current_version: Version,
    pub target: String,
    pub api_base: String,
    pub public_key: VerifyingKey,
    pub http: Client,
}

pub use release::UpdateClient;

pub fn check(repository: &str, current_version: &str) -> Result<ReleaseInfo, UpdateError> {
    UpdateClient::new(repository, current_version)?.latest(None)
}
