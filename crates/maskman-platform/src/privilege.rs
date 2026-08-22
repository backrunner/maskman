use std::{
    fs, io,
    net::UdpSocket,
    path::Path,
    process::{Child, Command, Stdio},
};

use crate::PlatformError;

pub const WORKER_USER: &str = "maskman";
pub const WORKER_GROUP: &str = "maskman";

#[cfg(unix)]
use std::os::fd::{AsFd, FromRawFd, OwnedFd, RawFd};

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, PermissionsExt};

#[cfg(unix)]
use std::os::unix::process::CommandExt;

/// Clear close-on-exec for a descriptor that is intentionally handed to the
/// worker. The caller must keep the descriptor open until `spawn_worker`
/// returns.
#[cfg(unix)]
pub fn make_inheritable<Fd: AsFd>(fd: Fd) -> Result<(), PlatformError> {
    use nix::fcntl::{fcntl, FcntlArg, FdFlag};

    let current = fcntl(fd.as_fd(), FcntlArg::F_GETFD)
        .map_err(|error| PlatformError::Network(format!("inspect inherited fd: {error}")))?;
    let flags = FdFlag::from_bits_truncate(current);
    fcntl(fd.as_fd(), FcntlArg::F_SETFD(flags & !FdFlag::FD_CLOEXEC))
        .map_err(|error| PlatformError::Network(format!("prepare inherited fd: {error}")))?;
    Ok(())
}

#[cfg(not(unix))]
pub fn make_inheritable<T>(_fd: T) -> Result<(), PlatformError> {
    Err(PlatformError::Network("fd inheritance is unavailable on this platform".into()))
}

/// Reconstruct a UDP socket from a descriptor inherited across exec.
#[cfg(unix)]
pub fn inherited_udp(raw_fd: RawFd) -> Result<UdpSocket, PlatformError> {
    if raw_fd < 0 {
        return Err(PlatformError::Network("worker received an invalid UDP fd".into()));
    }
    // SAFETY: the supervisor passes an open socket descriptor and transfers
    // ownership exactly once through the worker environment.
    let owned = unsafe { OwnedFd::from_raw_fd(raw_fd) };
    let socket = UdpSocket::from(owned);
    socket
        .set_nonblocking(true)
        .map_err(|error| PlatformError::Network(format!("configure inherited UDP fd: {error}")))?;
    Ok(socket)
}

#[cfg(not(unix))]
pub fn inherited_udp(_raw_fd: i32) -> Result<UdpSocket, PlatformError> {
    Err(PlatformError::Network("inherited UDP fds are unavailable on this platform".into()))
}

/// Spawn the unprivileged worker and transfer only the descriptors listed in
/// `listener_fds` and `tun_fd`. The worker command is intentionally hidden
/// from the public CLI; it is an internal role boundary.
pub fn spawn_worker(
    binary: &Path,
    config: &Path,
    listener_fds: &[i32],
    tun_fd: Option<i32>,
) -> Result<Child, PlatformError> {
    if listener_fds.is_empty() || listener_fds.len() > 64 {
        return Err(PlatformError::InvalidService(
            "worker requires between one and 64 listener descriptors".into(),
        ));
    }
    let listener_value = listener_fds.iter().map(ToString::to_string).collect::<Vec<_>>().join(",");
    let mut command = Command::new(binary);
    command
        .env_clear()
        .arg("--config")
        .arg(config)
        .arg("worker")
        .env("MASKMAN_ROLE", "worker")
        .env("MASKMAN_LISTENER_FDS", listener_value)
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    if let Some(fd) = tun_fd {
        if fd < 0 {
            return Err(PlatformError::InvalidService("worker received an invalid TUN fd".into()));
        }
        command.env("MASKMAN_TUN_FD", fd.to_string());
    }

    #[cfg(unix)]
    {
        let user = nix::unistd::User::from_name(WORKER_USER)
            .map_err(|error| PlatformError::Network(format!("lookup worker identity: {error}")))?
            .ok_or_else(|| {
                PlatformError::InvalidService(format!(
                    "dedicated worker identity {WORKER_USER} is not present"
                ))
            })?;
        let uid = user.uid;
        let gid = user.gid;
        // `CommandExt::groups` is unstable on the minimum supported Rust
        // toolchain. Keep the privilege transition in one pre-exec closure so
        // supplementary groups are cleared before dropping root.
        // SAFETY: this closure only calls libc-backed nix primitives with
        // immutable uid/gid values and runs in the child between fork/exec.
        unsafe {
            command.pre_exec(move || {
                clear_supplementary_groups(gid)?;
                nix::unistd::setgid(gid)
                    .map_err(|error| io::Error::from_raw_os_error(error as i32))?;
                nix::unistd::setuid(uid)
                    .map_err(|error| io::Error::from_raw_os_error(error as i32))?;
                Ok(())
            });
        }
    }
    command.spawn().map_err(PlatformError::ServiceCommand)
}

#[cfg(unix)]
fn clear_supplementary_groups(gid: nix::unistd::Gid) -> io::Result<()> {
    let group = [gid.as_raw() as libc::gid_t];
    // SAFETY: `group` is a valid one-element array for the duration of the
    // libc call, and the child is still single-threaded in pre-exec.
    let result = unsafe { libc::setgroups(1, group.as_ptr()) };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Prepare files and the state directory for the worker identity used by an
/// installed service. The supervisor still owns system mutations, but the
/// worker must be able to read the compiled configuration and TLS material
/// after the uid/gid transition.
#[cfg(unix)]
pub fn prepare_worker_access(
    config: &Path,
    certificate: &Path,
    private_key: &Path,
    client_ca: Option<&Path>,
    state_dir: &Path,
) -> Result<(), PlatformError> {
    if current_uid() != 0 {
        return Err(PlatformError::InvalidService(
            "installing the supervisor service requires root to grant worker file access".into(),
        ));
    }
    let user = nix::unistd::User::from_name(WORKER_USER)
        .map_err(|error| PlatformError::Network(format!("lookup worker identity: {error}")))?
        .ok_or_else(|| {
            PlatformError::InvalidService(format!(
                "dedicated worker identity {WORKER_USER} is not present"
            ))
        })?;
    ensure_state_directory(state_dir, user.uid.as_raw(), user.gid.as_raw())?;
    for path in [Some(config), Some(certificate), Some(private_key), client_ca] {
        let Some(path) = path else { continue };
        grant_file_access(path, user.uid.as_raw(), user.gid.as_raw())?;
    }
    Ok(())
}

#[cfg(not(unix))]
pub fn prepare_worker_access(
    _config: &Path,
    _certificate: &Path,
    _private_key: &Path,
    _client_ca: Option<&Path>,
    _state_dir: &Path,
) -> Result<(), PlatformError> {
    Err(PlatformError::InvalidService("worker file access is unavailable on this platform".into()))
}

#[cfg(unix)]
fn ensure_state_directory(path: &Path, uid: u32, gid: u32) -> Result<(), PlatformError> {
    if !path.is_absolute() {
        return Err(PlatformError::InvalidService(format!(
            "worker state directory must be absolute: {}",
            path.display()
        )));
    }
    if path == Path::new("/") {
        return Err(PlatformError::InvalidService(
            "worker state directory must not be the filesystem root".into(),
        ));
    }
    ensure_directory_chain(path, uid, gid)?;
    nix::unistd::chown(
        path,
        Some(nix::unistd::Uid::from_raw(0)),
        Some(nix::unistd::Gid::from_raw(gid)),
    )
    .map_err(|error| PlatformError::Network(format!("grant state directory ownership: {error}")))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o770))
        .map_err(PlatformError::ServiceIo)?;
    audit_directory_ancestors(path, "worker state directory", uid, gid)?;

    let log_dir = path.join("logs");
    ensure_directory_chain(&log_dir, uid, gid)?;
    nix::unistd::chown(
        &log_dir,
        Some(nix::unistd::Uid::from_raw(0)),
        Some(nix::unistd::Gid::from_raw(gid)),
    )
    .map_err(|error| PlatformError::Network(format!("grant log directory ownership: {error}")))?;
    fs::set_permissions(&log_dir, fs::Permissions::from_mode(0o770))
        .map_err(PlatformError::ServiceIo)?;
    audit_directory_ancestors(&log_dir, "worker log directory", uid, gid)
}

#[cfg(unix)]
fn ensure_directory_chain(path: &Path, uid: u32, gid: u32) -> Result<(), PlatformError> {
    let mut missing = Vec::new();
    let mut current = path;
    let existing = loop {
        match fs::symlink_metadata(current) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    return Err(PlatformError::InvalidService(format!(
                        "worker state directory is not a real directory: {}",
                        current.display()
                    )));
                }
                break current;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                missing.push(current.to_path_buf());
                current = current.parent().ok_or_else(|| {
                    PlatformError::InvalidService(format!(
                        "worker state directory has no parent: {}",
                        path.display()
                    ))
                })?;
            }
            Err(error) => {
                return Err(PlatformError::InvalidService(format!(
                    "inspect worker state directory {}: {error}",
                    current.display()
                )))
            }
        }
    };
    audit_directory_ancestors(existing, "worker state directory", uid, gid)?;
    for directory in missing.into_iter().rev() {
        fs::create_dir(&directory).map_err(|error| {
            PlatformError::InvalidService(format!(
                "create worker state directory {}: {error}",
                directory.display()
            ))
        })?;
        nix::unistd::chown(
            &directory,
            Some(nix::unistd::Uid::from_raw(0)),
            Some(nix::unistd::Gid::from_raw(gid)),
        )
        .map_err(|error| {
            PlatformError::Network(format!(
                "grant worker state directory ownership {}: {error}",
                directory.display()
            ))
        })?;
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o750))
            .map_err(PlatformError::ServiceIo)?;
    }
    Ok(())
}

#[cfg(unix)]
fn grant_file_access(path: &Path, uid: u32, gid: u32) -> Result<(), PlatformError> {
    if !path.is_absolute() {
        return Err(PlatformError::InvalidService(format!(
            "worker file path must be absolute: {}",
            path.display()
        )));
    }
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        PlatformError::InvalidService(format!(
            "worker file {} is unavailable: {error}",
            path.display()
        ))
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(PlatformError::InvalidService(format!(
            "worker file is not a regular file: {}",
            path.display()
        )));
    }
    let parent = path.parent().ok_or_else(|| {
        PlatformError::InvalidService(format!("worker file has no parent: {}", path.display()))
    })?;
    audit_directory_ancestors(parent, "worker file parent", uid, gid)?;
    nix::unistd::chown(
        path,
        Some(nix::unistd::Uid::from_raw(0)),
        Some(nix::unistd::Gid::from_raw(gid)),
    )
    .map_err(|error| PlatformError::Network(format!("grant worker file ownership: {error}")))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o640)).map_err(PlatformError::ServiceIo)
}

#[cfg(unix)]
fn audit_directory_ancestors(
    path: &Path,
    label: &str,
    uid: u32,
    gid: u32,
) -> Result<(), PlatformError> {
    let mut current = Some(path);
    while let Some(candidate) = current {
        match fs::symlink_metadata(candidate) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    return Err(PlatformError::InvalidService(format!(
                        "{label} ancestor is not a real directory: {}",
                        candidate.display()
                    )));
                }
                if !has_directory_search_access(&metadata, uid, gid) {
                    return Err(PlatformError::InvalidService(format!(
                        "worker cannot traverse {label} ancestor {}; grant execute access",
                        candidate.display()
                    )));
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(PlatformError::InvalidService(format!(
                    "inspect {label} ancestor {}: {error}",
                    candidate.display()
                )));
            }
        }
        if candidate == Path::new("/") {
            break;
        }
        current = candidate.parent();
    }
    Ok(())
}

#[cfg(unix)]
fn has_directory_search_access(metadata: &fs::Metadata, uid: u32, gid: u32) -> bool {
    let mode = metadata.permissions().mode();
    let bit = if metadata.uid() == uid {
        0o100
    } else if metadata.gid() == gid {
        0o010
    } else {
        0o001
    };
    mode & bit != 0
}

pub fn terminate_worker(child: &Child) -> Result<(), PlatformError> {
    #[cfg(unix)]
    {
        use nix::{
            sys::signal::{kill, Signal},
            unistd::Pid,
        };
        let pid = i32::try_from(child.id())
            .map_err(|_| PlatformError::Network("worker pid is out of range".into()))?;
        kill(Pid::from_raw(pid), Signal::SIGTERM)
            .map_err(|error| PlatformError::Network(format!("stop worker: {error}")))
    }
    #[cfg(not(unix))]
    {
        child.kill().map_err(|error| PlatformError::ServiceCommand(error))
    }
}

#[cfg(unix)]
pub fn inherited_tun(
    raw_fd: RawFd,
    name: String,
    mtu: u16,
) -> Result<crate::TunDevice, PlatformError> {
    crate::TunDevice::from_inherited_fd(raw_fd, name, mtu)
}

#[cfg(not(unix))]
pub fn inherited_tun(
    _raw_fd: i32,
    _name: String,
    _mtu: u16,
) -> Result<crate::TunDevice, PlatformError> {
    Err(PlatformError::Network("inherited TUN fds are unavailable on this platform".into()))
}

/// Apply restrictions that are safe for both foreground and service runs.
/// UID/GID selection is owned by systemd/launchd; this function only hardens
/// the already-selected worker and never attempts a privileged escalation.
pub fn apply_worker_hardening() -> Result<(), PlatformError> {
    #[cfg(target_os = "linux")]
    {
        nix::sys::prctl::set_no_new_privs()
            .map_err(|error| PlatformError::Network(format!("set no_new_privs: {error}")))?;
        nix::sys::prctl::set_dumpable(false)
            .map_err(|error| PlatformError::Network(format!("disable core dumps: {error}")))?;
    }
    Ok(())
}

pub fn worker_identity() -> (&'static str, &'static str) {
    (WORKER_USER, WORKER_GROUP)
}

pub fn current_uid() -> u32 {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        nix::unistd::getuid().as_raw()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    0
}

pub fn control_peer_allowed(uid: u32) -> bool {
    uid == 0 || uid == current_uid()
}

#[cfg(target_os = "linux")]
pub fn worker_identity_available() -> bool {
    nix::unistd::User::from_name(WORKER_USER).ok().flatten().is_some()
}

#[cfg(target_os = "macos")]
pub fn worker_identity_available() -> bool {
    nix::unistd::User::from_name(WORKER_USER).ok().flatten().is_some()
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn worker_identity_available() -> bool {
    false
}

#[cfg(test)]
#[path = "privilege_tests.rs"]
mod tests;
