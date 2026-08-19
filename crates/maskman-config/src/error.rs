use std::{io, path::PathBuf};

use thiserror::Error;

use crate::validate::ValidationError;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read config {path}: {source}")]
    Read { path: PathBuf, source: io::Error },
    #[error("failed to write config {path}: {source}")]
    Write { path: PathBuf, source: io::Error },
    #[error("config is not valid UTF-8: {0}")]
    Utf8(#[from] std::str::Utf8Error),
    #[error("config path must end in .toml or .json: {0}")]
    UnsupportedFormat(PathBuf),
    #[error("invalid TOML config: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("invalid JSON config: {0}")]
    Json(#[from] serde_json::Error),
    #[error("failed to serialize TOML config: {0}")]
    TomlSerialize(#[source] toml::ser::Error),
    #[error("failed to serialize JSON config: {0}")]
    JsonSerialize(#[source] serde_json::Error),
    #[error(transparent)]
    Validation(#[from] ValidationError),
    #[error("validated config could not be compiled: {0}")]
    Invariant(String),
}
