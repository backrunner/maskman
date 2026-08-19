use std::{fs, path::Path};

use crate::{error::ConfigError, model::ConfigDocument, ConfigFormat};

pub fn load(path: &Path) -> Result<ConfigDocument, ConfigError> {
    let bytes =
        fs::read(path).map_err(|source| ConfigError::Read { path: path.to_path_buf(), source })?;
    let format = ConfigFormat::from_path(path)?;
    let document = match format {
        ConfigFormat::Toml => {
            let text = std::str::from_utf8(&bytes)?;
            toml::from_str::<ConfigDocument>(text)?
        }
        ConfigFormat::Json => serde_json::from_slice::<ConfigDocument>(&bytes)?,
    };
    Ok(document)
}

pub fn render(document: &ConfigDocument, format: ConfigFormat) -> Result<String, ConfigError> {
    match format {
        ConfigFormat::Toml => toml::to_string_pretty(document).map_err(ConfigError::TomlSerialize),
        ConfigFormat::Json => {
            serde_json::to_string_pretty(document).map_err(ConfigError::JsonSerialize)
        }
    }
}
