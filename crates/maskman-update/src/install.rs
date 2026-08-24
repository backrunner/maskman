use std::{
    fs, io,
    path::{Component, Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use flate2::read::GzDecoder;

use crate::{
    install_paths::{current_binary_state, inspect_path, validate_backup_path, ExistingPath},
    InstallOutcome, ServiceController, UpdateError, VerifiedArtifact,
};

pub fn install_verified(
    artifact: &VerifiedArtifact,
    binary_path: &Path,
    config_path: Option<&Path>,
    service: Option<&dyn ServiceController>,
) -> Result<InstallOutcome, UpdateError> {
    match inspect_path(binary_path)? {
        ExistingPath::Missing | ExistingPath::File => {}
        ExistingPath::Symlink => {
            return Err(UpdateError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "refusing to replace a symbolic-link binary path",
            )))
        }
        ExistingPath::Directory | ExistingPath::Other => {
            return Err(UpdateError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "update binary path is not a regular file",
            )))
        }
    }
    let parent = binary_path.parent().ok_or_else(|| {
        UpdateError::Io(io::Error::new(io::ErrorKind::InvalidInput, "binary path has no parent"))
    })?;
    match inspect_path(parent)? {
        ExistingPath::Missing | ExistingPath::Directory => {}
        ExistingPath::Symlink => {
            return Err(UpdateError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "update binary parent must not be a symbolic link",
            )))
        }
        ExistingPath::File | ExistingPath::Other => {
            return Err(UpdateError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "update binary parent is not a directory",
            )))
        }
    }
    fs::create_dir_all(parent).map_err(UpdateError::Io)?;
    let _lock = UpdateLock::acquire(parent)?;
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

struct UpdateLock {
    path: PathBuf,
}

impl UpdateLock {
    fn acquire(parent: &Path) -> Result<Self, UpdateError> {
        let path = parent.join(".maskman-update.lock");
        match fs::OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(file) => {
                drop(file);
                Ok(Self { path })
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Err(UpdateError::Io(
                io::Error::new(io::ErrorKind::WouldBlock, "another update is already in progress"),
            )),
            Err(error) => Err(UpdateError::Io(error)),
        }
    }
}

impl Drop for UpdateLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
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
    current_binary_state(binary_path)?;
    validate_backup_path(&backup)?;
    if let Some(service) = service {
        service.stop()?;
    }
    let had_binary = match current_binary_state(binary_path) {
        Ok(value) => value,
        Err(error) => {
            restart_after_failure(service);
            return Err(error);
        }
    };
    if let Err(error) = validate_backup_path(&backup) {
        restart_after_failure(service);
        return Err(error);
    }
    if had_binary {
        match inspect_path(&backup).inspect_err(|_| {
            restart_after_failure(service);
        })? {
            ExistingPath::Missing => {}
            ExistingPath::File => {
                if let Err(error) = fs::remove_file(&backup) {
                    restart_after_failure(service);
                    return Err(UpdateError::Io(error));
                }
            }
            ExistingPath::Symlink | ExistingPath::Directory | ExistingPath::Other => {
                restart_after_failure(service);
                return Err(UpdateError::Io(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "update backup path is not a regular file",
                )));
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
    service.stop().map_err(|stop_error| {
        UpdateError::Rollback(format!(
            "{error}; stopping failed service before restore failed: {stop_error}"
        ))
    })?;
    restore_binary(binary_path, backup, had_binary).map_err(|rollback_error| {
        UpdateError::Rollback(format!("{error}; restoring old binary failed: {rollback_error}"))
    })?;
    service.start().map_err(|start_error| {
        UpdateError::Rollback(format!("{error}; restored binary but restart failed: {start_error}"))
    })?;
    Err(error)
}

fn restore_binary(binary_path: &Path, backup: &Path, had_binary: bool) -> Result<(), UpdateError> {
    match inspect_path(binary_path)? {
        ExistingPath::Missing => {}
        ExistingPath::File => fs::remove_file(binary_path).map_err(UpdateError::Io)?,
        ExistingPath::Symlink => {
            return Err(UpdateError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "refusing to restore over a symbolic-link binary path",
            )))
        }
        ExistingPath::Directory | ExistingPath::Other => {
            return Err(UpdateError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "cannot restore over a non-file binary path",
            )))
        }
    }
    if had_binary {
        if !matches!(inspect_path(backup)?, ExistingPath::File) {
            return Err(UpdateError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "update backup is not a regular file",
            )));
        }
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
    let output = run_staged(staged, &["--version"])?;
    if !output.status.success()
        || !String::from_utf8_lossy(&output.stdout).contains(&version.to_string())
    {
        return Err(UpdateError::StagedCheck(
            "staged --version did not report the release version".into(),
        ));
    }
    if let Some(config) = config {
        let config_value = config.to_string_lossy().into_owned();
        let output = run_staged(staged, &["--config", &config_value, "config", "validate"])?;
        if !output.status.success() {
            return Err(UpdateError::StagedCheck("staged config validation failed".into()));
        }
    }
    Ok(())
}

fn run_staged(binary: &Path, args: &[&str]) -> Result<std::process::Output, UpdateError> {
    let mut child = spawn_staged(binary, args)?;
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        if child.try_wait().map_err(|error| UpdateError::StagedCheck(error.to_string()))?.is_some()
        {
            return child
                .wait_with_output()
                .map_err(|error| UpdateError::StagedCheck(error.to_string()));
        }
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(UpdateError::StagedCheck(
                "staged binary did not finish validation within 5 seconds".into(),
            ));
        }
        thread::sleep(Duration::from_millis(25));
    }
}

fn spawn_staged(binary: &Path, args: &[&str]) -> Result<std::process::Child, UpdateError> {
    const MAX_TEXT_BUSY_RETRIES: usize = 8;
    let mut retries = 0;
    loop {
        let result = Command::new(binary)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn();
        match result {
            Ok(child) => return Ok(child),
            Err(error) if is_text_busy(&error) && retries < MAX_TEXT_BUSY_RETRIES => {
                retries += 1;
                thread::sleep(Duration::from_millis(10 * retries as u64));
            }
            Err(error) => return Err(UpdateError::StagedCheck(error.to_string())),
        }
    }
}

#[cfg(unix)]
fn is_text_busy(error: &io::Error) -> bool {
    // ETXTBSY is not exposed as an io::ErrorKind; this is its stable Unix errno.
    error.raw_os_error() == Some(26)
}

#[cfg(not(unix))]
fn is_text_busy(_error: &io::Error) -> bool {
    false
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
#[path = "install_tests.rs"]
mod tests;
