mod compile;
mod error;
mod load;
pub mod model;
mod validate;

use std::{
    path::{Path, PathBuf},
    str::FromStr,
};

pub use compile::{
    CompiledConfig, CompiledIp, CompiledLimits, CompiledRole, CompiledToken, CompiledUdp,
};
pub use error::ConfigError;
pub use load::{render, write_atomic};
pub use model::{AuthMode, ConfigDocument};
pub use validate::{parse_duration, resolve_path, validate, ValidationError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigFormat {
    Toml,
    Json,
}

impl ConfigFormat {
    pub fn from_path(path: &Path) -> Result<Self, ConfigError> {
        match path.extension().and_then(|extension| extension.to_str()) {
            Some("toml") => Ok(Self::Toml),
            Some("json") => Ok(Self::Json),
            _ => Err(ConfigError::UnsupportedFormat(path.to_path_buf())),
        }
    }
}

impl FromStr for ConfigFormat {
    type Err = ConfigError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "toml" => Ok(Self::Toml),
            "json" => Ok(Self::Json),
            _ => Err(ConfigError::UnsupportedFormat(PathBuf::from(value))),
        }
    }
}

pub fn load(path: &Path) -> Result<ConfigDocument, ConfigError> {
    load::load(path)
}

pub fn compile(path: &Path) -> Result<CompiledConfig, ConfigError> {
    let document = load(path)?;
    let base_dir = path.parent().unwrap_or_else(|| Path::new("."));
    compile::compile(&document, base_dir)
}

pub fn compile_document(
    document: &ConfigDocument,
    base_dir: &Path,
) -> Result<CompiledConfig, ConfigError> {
    compile::compile(document, base_dir)
}

#[cfg(test)]
mod tests {
    use super::{load, model::ConfigDocument, render, validate, write_atomic, ConfigFormat};

    #[test]
    fn default_config_round_trips_as_toml() {
        let document = ConfigDocument::default();
        let rendered = match render(&document, ConfigFormat::Toml) {
            Ok(rendered) => rendered,
            Err(error) => panic!("render: {error}"),
        };
        let parsed: ConfigDocument = match toml::from_str(&rendered) {
            Ok(parsed) => parsed,
            Err(error) => panic!("parse: {error}"),
        };
        if let Err(error) = validate(&parsed) {
            panic!("defaults validate: {error}");
        }
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let result = toml::from_str::<ConfigDocument>("schema_version = 1\nunknown = true\n");
        assert!(result.is_err());
    }

    #[test]
    fn atomic_writer_round_trips_toml_and_json() {
        let root = std::env::temp_dir().join(format!("maskman-config-{}", std::process::id()));
        let toml_path = root.join("config.toml");
        let json_path = root.join("config.json");
        let document = ConfigDocument::default();
        let _ = std::fs::remove_dir_all(&root);
        if let Err(error) = write_atomic(&toml_path, &document) {
            panic!("write TOML: {error}");
        }
        if let Err(error) = write_atomic(&json_path, &document) {
            panic!("write JSON: {error}");
        }
        let toml_loaded = match load(&toml_path) {
            Ok(value) => value,
            Err(error) => panic!("load TOML: {error}"),
        };
        let json_loaded = match load(&json_path) {
            Ok(value) => value,
            Err(error) => panic!("load JSON: {error}"),
        };
        assert_eq!(toml_loaded.schema_version, 1);
        assert_eq!(json_loaded.schema_version, 1);
        let _ = std::fs::remove_dir_all(root);
    }
}
