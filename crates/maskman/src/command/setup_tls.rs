use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use anyhow::{Context, Result};
use rcgen::{generate_simple_self_signed, CertifiedKey};

const TEMP_FILE_ATTEMPTS: u64 = 32;
static NEXT_TEMP_FILE: AtomicU64 = AtomicU64::new(0);

pub struct DevelopmentTls {
    pub certificate: PathBuf,
    pub private_key: PathBuf,
    generated: bool,
}

impl DevelopmentTls {
    pub fn cleanup_after_failure(&self) {
        if self.generated {
            let _ = fs::remove_file(&self.certificate);
            let _ = fs::remove_file(&self.private_key);
        }
    }

    pub fn was_generated(&self) -> bool {
        self.generated
    }
}

pub fn ensure(
    config_path: &Path,
    document: &maskman_config::ConfigDocument,
) -> Result<DevelopmentTls> {
    let base = config_path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let certificate = maskman_config::resolve_path(base, &document.tls.certificate_file);
    let private_key = maskman_config::resolve_path(base, &document.tls.private_key_file);
    if certificate == private_key || certificate == config_path || private_key == config_path {
        anyhow::bail!(
            "development TLS certificate, private key, and config paths must be distinct"
        );
    }

    let certificate_exists = regular_file_exists(&certificate)?;
    let private_key_exists = regular_file_exists(&private_key)?;
    match (certificate_exists, private_key_exists) {
        (true, true) => {
            return Ok(DevelopmentTls { certificate, private_key, generated: false });
        }
        (true, false) | (false, true) => {
            anyhow::bail!(
                "development TLS files are incomplete; both {} and {} must exist or both must be absent",
                certificate.display(),
                private_key.display()
            );
        }
        (false, false) => {}
    }

    let CertifiedKey { cert, key_pair } = generate_simple_self_signed(vec![
        "localhost".to_owned(),
        "127.0.0.1".to_owned(),
        "::1".to_owned(),
    ])
    .context("generating development TLS certificate")?;
    let key_stage = stage_private_file(&private_key, key_pair.serialize_pem().as_bytes())?;
    let certificate_stage = match stage_private_file(&certificate, cert.pem().as_bytes()) {
        Ok(stage) => stage,
        Err(error) => {
            let _ = fs::remove_file(key_stage);
            return Err(error);
        }
    };
    if let Err(error) = commit_new_file(&key_stage, &private_key) {
        let _ = fs::remove_file(&key_stage);
        let _ = fs::remove_file(&certificate_stage);
        return Err(error);
    }
    if let Err(error) = commit_new_file(&certificate_stage, &certificate) {
        let _ = fs::remove_file(&private_key);
        let _ = fs::remove_file(&certificate_stage);
        return Err(error);
    }
    Ok(DevelopmentTls { certificate, private_key, generated: true })
}

fn regular_file_exists(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => Ok(true),
        Ok(_) => anyhow::bail!("refusing non-regular development TLS path {}", path.display()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).with_context(|| format!("inspecting {}", path.display())),
    }
}

fn stage_private_file(path: &Path, content: &[u8]) -> Result<PathBuf> {
    let parent =
        path.parent().ok_or_else(|| anyhow::anyhow!("{} has no parent", path.display()))?;
    fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    let metadata =
        fs::symlink_metadata(parent).with_context(|| format!("inspecting {}", parent.display()))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        anyhow::bail!("development TLS parent must be a real directory: {}", parent.display());
    }
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| anyhow::anyhow!("{} has no valid file name", path.display()))?;
    for _ in 0..TEMP_FILE_ATTEMPTS {
        let sequence = NEXT_TEMP_FILE.fetch_add(1, Ordering::Relaxed);
        let temporary = parent.join(format!(".{file_name}.tmp-{}-{sequence}", std::process::id()));
        match OpenOptions::new().write(true).create_new(true).open(&temporary) {
            Ok(mut file) => {
                set_private_permissions(&file)?;
                file.write_all(content)
                    .with_context(|| format!("writing {}", temporary.display()))?;
                file.sync_all().with_context(|| format!("syncing {}", temporary.display()))?;
                return Ok(temporary);
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(error).with_context(|| format!("creating {}", temporary.display()))
            }
        }
    }
    anyhow::bail!("could not reserve a development TLS temporary file for {}", path.display())
}

fn commit_new_file(temporary: &Path, destination: &Path) -> Result<()> {
    fs::hard_link(temporary, destination).with_context(|| {
        format!("installing {}; refusing to replace an existing TLS file", destination.display())
    })?;
    fs::remove_file(temporary).with_context(|| format!("removing {}", temporary.display()))?;
    let parent = destination
        .parent()
        .ok_or_else(|| anyhow::anyhow!("{} has no parent", destination.display()))?;
    fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .with_context(|| format!("syncing {}", parent.display()))
}

#[cfg(unix)]
fn set_private_permissions(file: &fs::File) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .context("setting development TLS permissions")
}

#[cfg(not(unix))]
fn set_private_permissions(_file: &fs::File) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::ensure;

    static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

    fn root() -> std::path::PathBuf {
        let sequence = NEXT_ROOT.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("maskman-setup-tls-{}-{sequence}", std::process::id()))
    }

    #[test]
    fn development_tls_is_generated_once_and_loads() {
        let root = root();
        let config_path = root.join("config.toml");
        let document = maskman_config::ConfigDocument::default();
        let tls = ensure(&config_path, &document)
            .unwrap_or_else(|error| panic!("generate development TLS: {error:#}"));
        assert!(tls.was_generated());
        let compiled = maskman_config::compile_document(&document, &root)
            .unwrap_or_else(|error| panic!("compile config: {error}"));
        maskman_server::validate_tls(&compiled)
            .unwrap_or_else(|error| panic!("validate development TLS: {error}"));
        let reused = ensure(&config_path, &document)
            .unwrap_or_else(|error| panic!("reuse development TLS: {error:#}"));
        assert!(!reused.was_generated());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&tls.private_key)
                    .unwrap_or_else(|error| panic!("stat key: {error}"))
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        std::fs::remove_dir_all(root).unwrap_or_else(|error| panic!("remove root: {error}"));
    }

    #[test]
    fn development_tls_refuses_partial_or_special_destinations() {
        let root = root();
        std::fs::create_dir_all(root.join("tls"))
            .unwrap_or_else(|error| panic!("create TLS root: {error}"));
        std::fs::write(root.join("tls/fullchain.pem"), b"existing")
            .unwrap_or_else(|error| panic!("write certificate: {error}"));
        let document = maskman_config::ConfigDocument::default();
        assert!(ensure(&root.join("config.toml"), &document).is_err());
        assert_eq!(std::fs::read(root.join("tls/fullchain.pem")).unwrap_or_default(), b"existing");
        std::fs::remove_dir_all(root).unwrap_or_else(|error| panic!("remove root: {error}"));
    }
}
