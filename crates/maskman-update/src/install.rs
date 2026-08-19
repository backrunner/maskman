use std::{
    fs, io,
    path::{Component, Path, PathBuf},
    process::Command,
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use flate2::read::GzDecoder;

use crate::{InstallOutcome, ServiceController, UpdateError, VerifiedArtifact};

pub fn install_verified(
    artifact: &VerifiedArtifact,
    binary_path: &Path,
    config_path: Option<&Path>,
    service: Option<&dyn ServiceController>,
) -> Result<InstallOutcome, UpdateError> {
    let parent = binary_path.parent().ok_or_else(|| {
        UpdateError::Io(io::Error::new(io::ErrorKind::InvalidInput, "binary path has no parent"))
    })?;
    fs::create_dir_all(parent).map_err(UpdateError::Io)?;
    let stage = unique_stage(parent)?;
    let result = install_staged(artifact, binary_path, config_path, service, &stage);
    let cleanup = fs::remove_dir_all(&stage);
    match (result, cleanup) {
        (Ok(outcome), Ok(())) => Ok(outcome),
        (Ok(_outcome), Err(error)) => Err(UpdateError::Io(error)),
        (Err(error), Ok(())) => Err(error),
        (Err(error), Err(cleanup_error)) => Err(UpdateError::Rollback(format!(
            "{error}; unable to remove staging directory: {cleanup_error}"
        ))),
    }
}

fn install_staged(
    artifact: &VerifiedArtifact,
    binary_path: &Path,
    config_path: Option<&Path>,
    service: Option<&dyn ServiceController>,
    stage: &Path,
) -> Result<InstallOutcome, UpdateError> {
    let staged_binary = unpack_archive(&artifact.archive, stage)?;
    staged_checks(&staged_binary, config_path, &artifact.version)?;
    let backup = backup_path(binary_path);
    if let Some(service) = service {
        service.stop()?;
    }
    let had_binary = binary_path.exists();
    if had_binary {
        if backup.exists() {
            if let Err(error) = fs::remove_file(&backup) {
                restart_after_failure(service);
                return Err(UpdateError::Io(error));
            }
        }
        if let Err(error) = fs::rename(binary_path, &backup) {
            restart_after_failure(service);
            return Err(UpdateError::Io(error));
        }
    }
    if let Err(error) = fs::rename(&staged_binary, binary_path) {
        let restore = restore_binary(binary_path, &backup, had_binary);
        restart_after_failure(service);
        return match restore {
            Ok(()) => Err(UpdateError::Io(error)),
            Err(restore_error) => Err(UpdateError::Rollback(format!(
                "install failed: {error}; restore failed: {restore_error}"
            ))),
        };
    }
    if let Err(error) = sync_parent(binary_path) {
        let restore = restore_binary(binary_path, &backup, had_binary);
        restart_after_failure(service);
        return match restore {
            Ok(()) => Err(error),
            Err(restore_error) => Err(UpdateError::Rollback(format!(
                "sync failed: {error}; restore failed: {restore_error}"
            ))),
        };
    }
    if let Some(service) = service {
        if let Err(error) = service.start() {
            return rollback(binary_path, &backup, had_binary, service, error);
        }
        let deadline = std::time::Instant::now() + crate::MAX_HEALTH_WAIT;
        loop {
            match service.healthy() {
                Ok(true) => break,
                Ok(false) => {}
                Err(error) => return rollback(binary_path, &backup, had_binary, service, error),
            }
            if std::time::Instant::now() >= deadline {
                return rollback(
                    binary_path,
                    &backup,
                    had_binary,
                    service,
                    UpdateError::Health("service did not become healthy within 5 seconds".into()),
                );
            }
            thread::sleep(Duration::from_millis(100));
        }
    }
    Ok(InstallOutcome {
        version: artifact.version.clone(),
        backup: had_binary.then_some(backup),
        rolled_back: false,
    })
}

fn rollback(
    binary_path: &Path,
    backup: &Path,
    had_binary: bool,
    service: &dyn ServiceController,
    error: UpdateError,
) -> Result<InstallOutcome, UpdateError> {
    restore_binary(binary_path, backup, had_binary).map_err(|rollback_error| {
        UpdateError::Rollback(format!("{error}; restoring old binary failed: {rollback_error}"))
    })?;
    service.start().map_err(|start_error| {
        UpdateError::Rollback(format!("{error}; restored binary but restart failed: {start_error}"))
    })?;
    Err(error)
}

fn restore_binary(binary_path: &Path, backup: &Path, had_binary: bool) -> Result<(), UpdateError> {
    if binary_path.exists() {
        fs::remove_file(binary_path).map_err(UpdateError::Io)?;
    }
    if had_binary {
        fs::rename(backup, binary_path).map_err(UpdateError::Io)?;
    }
    sync_parent(binary_path)
}

fn restart_after_failure(service: Option<&dyn ServiceController>) {
    if let Some(service) = service {
        let _ = service.start();
    }
}

fn staged_checks(
    staged: &Path,
    config: Option<&Path>,
    version: &semver::Version,
) -> Result<(), UpdateError> {
    let output = Command::new(staged)
        .arg("--version")
        .output()
        .map_err(|error| UpdateError::StagedCheck(error.to_string()))?;
    if !output.status.success()
        || !String::from_utf8_lossy(&output.stdout).contains(&version.to_string())
    {
        return Err(UpdateError::StagedCheck(
            "staged --version did not report the release version".into(),
        ));
    }
    if let Some(config) = config {
        let output = Command::new(staged)
            .args(["--config", config.to_string_lossy().as_ref(), "config", "validate"])
            .output()
            .map_err(|error| UpdateError::StagedCheck(error.to_string()))?;
        if !output.status.success() {
            return Err(UpdateError::StagedCheck("staged config validation failed".into()));
        }
    }
    Ok(())
}

fn unpack_archive(archive: &[u8], stage: &Path) -> Result<PathBuf, UpdateError> {
    if archive.len() > crate::MAX_DOWNLOAD_BYTES {
        return Err(UpdateError::DownloadTooLarge(crate::MAX_DOWNLOAD_BYTES));
    }
    fs::create_dir_all(stage).map_err(UpdateError::Io)?;
    let decoder = GzDecoder::new(archive);
    let mut archive = tar::Archive::new(decoder);
    let mut entries = 0usize;
    let mut total = 0u64;
    let mut binary = None;
    for item in archive.entries().map_err(|error| UpdateError::Archive(error.to_string()))? {
        let mut entry = item.map_err(|error| UpdateError::Archive(error.to_string()))?;
        entries += 1;
        if entries > crate::MAX_ARCHIVE_ENTRIES {
            return Err(UpdateError::Archive("too many entries".into()));
        }
        let path =
            entry.path().map_err(|error| UpdateError::Archive(error.to_string()))?.to_path_buf();
        validate_archive_path(&path)?;
        let kind = entry.header().entry_type();
        if kind.is_symlink() || kind.is_hard_link() || (!kind.is_file() && !kind.is_dir()) {
            return Err(UpdateError::Archive(format!(
                "unsupported link or special entry {}",
                path.display()
            )));
        }
        let size =
            entry.header().size().map_err(|error| UpdateError::Archive(error.to_string()))?;
        if size > crate::MAX_ARCHIVE_FILE_BYTES
            || total.saturating_add(size) > crate::MAX_ARCHIVE_TOTAL_BYTES
        {
            return Err(UpdateError::Archive("archive expands beyond the size limit".into()));
        }
        total = total.saturating_add(size);
        let destination = stage.join(&path);
        entry.unpack(&destination).map_err(|error| UpdateError::Archive(error.to_string()))?;
        if kind.is_file()
            && (path == Path::new("maskman") || path == Path::new("bin/maskman"))
            && binary.replace(destination).is_some()
        {
            return Err(UpdateError::Archive("archive contains multiple maskman binaries".into()));
        }
    }
    let binary =
        binary.ok_or_else(|| UpdateError::Archive("archive does not contain maskman".into()))?;
    set_executable(&binary)?;
    Ok(binary)
}

fn validate_archive_path(path: &Path) -> Result<(), UpdateError> {
    if path.is_absolute() {
        return Err(UpdateError::Archive("absolute paths are not allowed".into()));
    }
    for component in path.components() {
        if matches!(component, Component::ParentDir | Component::Prefix(_)) {
            return Err(UpdateError::Archive(format!("path traversal entry {}", path.display())));
        }
    }
    Ok(())
}

fn unique_stage(parent: &Path) -> Result<PathBuf, UpdateError> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| UpdateError::Io(io::Error::other(error)))?
        .as_nanos();
    let path = parent.join(format!(".maskman-update-{}-{nanos}", std::process::id()));
    fs::create_dir(&path).map_err(UpdateError::Io)?;
    Ok(path)
}

fn backup_path(binary: &Path) -> PathBuf {
    binary.with_extension("previous")
}

fn sync_parent(path: &Path) -> Result<(), UpdateError> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::File::open(parent).map_err(UpdateError::Io)?.sync_all().map_err(UpdateError::Io)
}

#[cfg(unix)]
fn set_executable(path: &Path) -> Result<(), UpdateError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).map_err(UpdateError::Io)
}

#[cfg(not(unix))]
fn set_executable(_path: &Path) -> Result<(), UpdateError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{install_verified, validate_archive_path};
    use crate::VerifiedArtifact;
    use flate2::{write::GzEncoder, Compression};
    use semver::Version;
    use std::{fs, path::Path};
    use tar::Builder;

    #[test]
    fn archive_path_rejects_traversal_and_absolute_names() {
        assert!(validate_archive_path(Path::new("../maskman")).is_err());
        assert!(validate_archive_path(Path::new("/tmp/maskman")).is_err());
        assert!(validate_archive_path(Path::new("bin/maskman")).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn install_runs_staged_version_check_and_keeps_one_backup() {
        let root = std::env::temp_dir().join(format!("maskman-update-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        if let Err(error) = fs::create_dir_all(&root) {
            panic!("create test directory: {error}");
        }
        let binary = root.join("maskman");
        if let Err(error) = fs::write(&binary, b"old binary") {
            panic!("write old binary: {error}");
        }
        let script = b"#!/bin/sh\nprintf 'maskman 9.9.9\\n'\n";
        let mut compressed = GzEncoder::new(Vec::new(), Compression::fast());
        {
            let mut builder = Builder::new(&mut compressed);
            let mut header = tar::Header::new_gnu();
            header.set_size(script.len() as u64);
            header.set_mode(0o755);
            header.set_cksum();
            if let Err(error) = builder.append_data(&mut header, "maskman", script.as_slice()) {
                panic!("append archive entry: {error}");
            }
            if let Err(error) = builder.finish() {
                panic!("finish archive: {error}");
            }
        }
        let archive = match compressed.finish() {
            Ok(value) => value,
            Err(error) => panic!("compress archive: {error}"),
        };
        let artifact = VerifiedArtifact {
            version: Version::parse("9.9.9").unwrap_or_else(|error| panic!("version: {error}")),
            archive,
        };
        let outcome = match install_verified(&artifact, &binary, None, None) {
            Ok(value) => value,
            Err(error) => panic!("install archive: {error}"),
        };
        assert_eq!(
            outcome.version,
            Version::parse("9.9.9").unwrap_or_else(|error| panic!("version: {error}"))
        );
        assert_eq!(fs::read(&binary).unwrap_or_default(), script);
        assert_eq!(fs::read(root.join("maskman.previous")).unwrap_or_default(), b"old binary");
        let _ = fs::remove_dir_all(root);
    }
}
