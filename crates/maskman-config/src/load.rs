use std::sync::atomic::{AtomicU64, Ordering};
use std::{fs, io::Write, path::Path};

use crate::{error::ConfigError, model::ConfigDocument, ConfigFormat};

static NEXT_TEMP_FILE: AtomicU64 = AtomicU64::new(0);

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
    reject_existing_symlink(path)?;
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
    let (temporary, mut file) = reserve_temporary(parent, file_name)?;
    let result = (|| {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(fs::Permissions::from_mode(0o600))
                .map_err(|source| ConfigError::Write { path: temporary.clone(), source })?;
        }
        file.write_all(rendered.as_bytes())
            .map_err(|source| ConfigError::Write { path: temporary.clone(), source })?;
        file.sync_all().map_err(|source| ConfigError::Write { path: temporary.clone(), source })?;
        drop(file);
        reject_existing_symlink(path)?;
        fs::rename(&temporary, path)
            .map_err(|source| ConfigError::Write { path: path.to_path_buf(), source })?;
        sync_directory(parent)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn reject_existing_symlink(path: &Path) -> Result<(), ConfigError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(ConfigError::Write {
            path: path.to_path_buf(),
            source: std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "refusing to replace a symbolic-link configuration path",
            ),
        }),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(ConfigError::Write { path: path.to_path_buf(), source }),
    }
}

fn reserve_temporary(
    parent: &Path,
    file_name: &str,
) -> Result<(std::path::PathBuf, fs::File), ConfigError> {
    for _ in 0..32 {
        let sequence = NEXT_TEMP_FILE.fetch_add(1, Ordering::Relaxed);
        let temporary = parent.join(format!(".{file_name}.tmp-{}-{sequence}", std::process::id()));
        match fs::OpenOptions::new().write(true).create_new(true).open(&temporary) {
            Ok(file) => return Ok((temporary, file)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(source) => return Err(ConfigError::Write { path: temporary, source }),
        }
    }
    Err(ConfigError::Write {
        path: parent.to_path_buf(),
        source: std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "could not reserve a unique configuration temporary file",
        ),
    })
}

fn sync_directory(path: &Path) -> Result<(), ConfigError> {
    fs::File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| ConfigError::Write { path: path.to_path_buf(), source })
}
