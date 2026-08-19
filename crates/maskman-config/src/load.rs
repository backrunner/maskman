use std::{fs, io::Write, path::Path};

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

pub fn write_atomic(path: &Path, document: &ConfigDocument) -> Result<(), ConfigError> {
    let format = ConfigFormat::from_path(path)?;
    let rendered = render(document, format)?;
    let parent = path
        .parent()
        .filter(|value| !value.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)
        .map_err(|source| ConfigError::Write { path: parent.to_path_buf(), source })?;
    let file_name =
        path.file_name().and_then(|value| value.to_str()).ok_or_else(|| ConfigError::Write {
            path: path.to_path_buf(),
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "config has no file name",
            ),
        })?;
    let temporary = parent.join(format!(".{file_name}.tmp-{}", std::process::id()));
    let permissions = fs::metadata(path).ok().map(|metadata| metadata.permissions());
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .map_err(|source| ConfigError::Write { path: temporary.clone(), source })?;
    #[cfg(unix)]
    if let Some(permissions) = permissions.as_ref() {
        file.set_permissions(permissions.clone())
            .map_err(|source| ConfigError::Write { path: temporary.clone(), source })?;
    }
    #[cfg(unix)]
    if permissions.is_none() {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|source| ConfigError::Write { path: temporary.clone(), source })?;
    }
    file.write_all(rendered.as_bytes())
        .map_err(|source| ConfigError::Write { path: temporary.clone(), source })?;
    file.sync_all().map_err(|source| ConfigError::Write { path: temporary.clone(), source })?;
    drop(file);
    fs::rename(&temporary, path)
        .map_err(|source| ConfigError::Write { path: path.to_path_buf(), source })
}
