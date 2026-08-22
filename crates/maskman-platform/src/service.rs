use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
};

use crate::PlatformError;

const TEMP_FILE_ATTEMPTS: u64 = 32;
static NEXT_TEMP_FILE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceAction {
    Start,
    Stop,
    Reload,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceStatus {
    pub installed: bool,
    pub running: bool,
    pub pid: Option<u32>,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceSpec {
    pub binary: PathBuf,
    pub config: PathBuf,
    pub state_dir: PathBuf,
    pub service_path: PathBuf,
}

impl ServiceSpec {
    pub fn new(
        binary: PathBuf,
        config: PathBuf,
        state_dir: PathBuf,
    ) -> Result<Self, PlatformError> {
        require_absolute(&binary, "binary")?;
        require_absolute(&config, "config")?;
        require_absolute(&state_dir, "state directory")?;
        Ok(Self { binary, config, state_dir, service_path: default_service_path() })
    }

    pub fn with_service_path(mut self, service_path: PathBuf) -> Result<Self, PlatformError> {
        require_absolute(&service_path, "service path")?;
        self.service_path = service_path;
        Ok(self)
    }

    pub fn render(&self) -> Result<String, PlatformError> {
        validate_path_text(&self.binary, "binary")?;
        validate_path_text(&self.config, "config")?;
        validate_path_text(&self.state_dir, "state directory")?;
        if cfg!(target_os = "macos") {
            Ok(render_launchd(self))
        } else if cfg!(target_os = "linux") {
            Ok(render_systemd(self))
        } else {
            Err(PlatformError::ServiceManagementUnavailable)
        }
    }
}

pub fn default_config_path() -> PathBuf {
    if cfg!(target_os = "macos") {
        PathBuf::from("/Library/Application Support/Maskman/config.toml")
    } else {
        PathBuf::from("/etc/maskman/config.toml")
    }
}

pub fn default_state_dir() -> PathBuf {
    if cfg!(target_os = "macos") {
        PathBuf::from("/Library/Application Support/Maskman/state")
    } else {
        PathBuf::from("/var/lib/maskman")
    }
}

pub fn default_service_path() -> PathBuf {
    if cfg!(target_os = "macos") {
        PathBuf::from("/Library/LaunchDaemons/top.backrunner.maskman.plist")
    } else {
        PathBuf::from("/etc/systemd/system/maskman.service")
    }
}

pub fn install(spec: &ServiceSpec, dry_run: bool) -> Result<bool, PlatformError> {
    let rendered = spec.render()?;
    let path_state = inspect_service_path(&spec.service_path)?;
    match path_state {
        ServicePathState::Missing | ServicePathState::Regular => {}
        ServicePathState::Symlink => {
            return Err(PlatformError::InvalidService(
                "refusing to replace a symbolic-link service definition".into(),
            ))
        }
        ServicePathState::Other => {
            return Err(PlatformError::InvalidService(
                "service definition path is not a regular file".into(),
            ))
        }
    }
    if dry_run {
        return Ok(!matches!(path_state, ServicePathState::Missing));
    }
    let _identity = crate::ensure_worker_identity(false)?;
    write_atomic(&spec.service_path, rendered.as_bytes())?;
    manager_command("install", spec)?;
    if cfg!(target_os = "linux") {
        manager_command("enable", spec)?;
    }
    Ok(true)
}

pub fn uninstall(spec: &ServiceSpec, dry_run: bool) -> Result<(), PlatformError> {
    match inspect_service_path(&spec.service_path)? {
        ServicePathState::Missing => return Ok(()),
        ServicePathState::Symlink => {
            return Err(PlatformError::InvalidService(
                "refusing to operate on a symbolic-link service definition".into(),
            ))
        }
        ServicePathState::Regular => {}
        ServicePathState::Other => {
            return Err(PlatformError::InvalidService(
                "service definition path is not a regular file".into(),
            ))
        }
    }
    if !dry_run {
        let _ = manager_command("stop", spec);
        manager_command("uninstall", spec)?;
        if matches!(inspect_service_path(&spec.service_path)?, ServicePathState::Regular) {
            fs::remove_file(&spec.service_path).map_err(PlatformError::ServiceIo)?;
        }
        if cfg!(target_os = "linux") {
            manager_command("daemon-reload", spec)?;
        }
    }
    Ok(())
}

pub fn control(spec: &ServiceSpec, action: ServiceAction) -> Result<(), PlatformError> {
    match inspect_service_path(&spec.service_path)? {
        ServicePathState::Regular => {}
        ServicePathState::Missing => return Err(PlatformError::ServiceNotInstalled),
        ServicePathState::Symlink | ServicePathState::Other => {
            return Err(PlatformError::InvalidService(
                "service definition path is not a regular file".into(),
            ))
        }
    }
    let action = match action {
        ServiceAction::Start => "start",
        ServiceAction::Stop => "stop",
        ServiceAction::Reload => "reload",
    };
    manager_command(action, spec).map(|_| ())
}

pub fn status(spec: &ServiceSpec) -> Result<ServiceStatus, PlatformError> {
    match inspect_service_path(&spec.service_path)? {
        ServicePathState::Missing => {
            return Ok(ServiceStatus {
                installed: false,
                running: false,
                pid: None,
                detail: "service definition is not installed".into(),
            })
        }
        ServicePathState::Regular => {}
        ServicePathState::Symlink | ServicePathState::Other => {
            return Err(PlatformError::InvalidService(
                "service definition path is not a regular file".into(),
            ))
        }
    }
    if cfg!(target_os = "linux") {
        status_systemd(&spec.service_path)
    } else if cfg!(target_os = "macos") {
        status_launchd()
    } else {
        Err(PlatformError::ServiceManagementUnavailable)
    }
}

fn write_atomic(path: &Path, content: &[u8]) -> Result<(), PlatformError> {
    reject_existing_symlink(path)?;
    let parent = path.parent().ok_or_else(|| {
        PlatformError::ServiceIo(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "service path has no parent",
        ))
    })?;
    fs::create_dir_all(parent).map_err(PlatformError::ServiceIo)?;
    let file_name = path.file_name().and_then(|name| name.to_str()).ok_or_else(|| {
        PlatformError::ServiceIo(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "service path has no valid file name",
        ))
    })?;
    let (temporary, mut file) = create_temporary(parent, file_name)?;
    let result = (|| {
        set_service_permissions(&temporary)?;
        file.write_all(content).map_err(PlatformError::ServiceIo)?;
        file.sync_all().map_err(PlatformError::ServiceIo)?;
        drop(file);
        reject_existing_symlink(path)?;
        fs::rename(&temporary, path).map_err(PlatformError::ServiceIo)?;
        set_service_permissions(path)?;
        fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(PlatformError::ServiceIo)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ServicePathState {
    Missing,
    Regular,
    Symlink,
    Other,
}

fn inspect_service_path(path: &Path) -> Result<ServicePathState, PlatformError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Ok(ServicePathState::Symlink),
        Ok(metadata) if metadata.is_file() => Ok(ServicePathState::Regular),
        Ok(_) => Ok(ServicePathState::Other),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(ServicePathState::Missing),
        Err(error) => Err(PlatformError::ServiceIo(error)),
    }
}

fn reject_existing_symlink(path: &Path) -> Result<(), PlatformError> {
    if matches!(inspect_service_path(path)?, ServicePathState::Symlink) {
        return Err(PlatformError::InvalidService(
            "refusing to replace a symbolic-link service definition".into(),
        ));
    }
    Ok(())
}

fn create_temporary(parent: &Path, file_name: &str) -> Result<(PathBuf, fs::File), PlatformError> {
    for _ in 0..TEMP_FILE_ATTEMPTS {
        let sequence = NEXT_TEMP_FILE.fetch_add(1, Ordering::Relaxed);
        let path = parent.join(format!(".{file_name}.tmp-{}-{sequence}", std::process::id()));
        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(file) => return Ok((path, file)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(PlatformError::ServiceIo(error)),
        }
    }
    Err(PlatformError::ServiceIo(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "could not reserve a unique service temporary file",
    )))
}

fn require_absolute(path: &Path, field: &str) -> Result<(), PlatformError> {
    if path.is_absolute() {
        Ok(())
    } else {
        Err(PlatformError::InvalidService(format!("{field} path must be absolute")))
    }
}

fn validate_path_text(path: &Path, field: &str) -> Result<(), PlatformError> {
    let value = path
        .to_str()
        .ok_or_else(|| PlatformError::InvalidService(format!("{field} path is not valid UTF-8")))?;
    if value.contains(['\0', '\n', '\r']) {
        return Err(PlatformError::InvalidService(format!(
            "{field} path contains a control character"
        )));
    }
    Ok(())
}

fn render_systemd(spec: &ServiceSpec) -> String {
    format!(
        "[Unit]\nDescription=Maskman MASQUE proxy\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nType=simple\nGroup=maskman\nExecStart={} --config {} serve\nExecReload=/bin/kill -HUP $MAINPID\nEnvironment=MASKMAN_ROLE=supervisor\nKillMode=control-group\nRestart=on-failure\nRestartSec=2s\nStartLimitIntervalSec=60s\nStartLimitBurst=5\nRuntimeDirectory=maskman\nStateDirectory=maskman\nStateDirectoryMode=0770\nConfigurationDirectory=maskman\nWorkingDirectory={}\nLimitNOFILE=65536\nCapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_SETUID CAP_SETGID\nAmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_SETUID CAP_SETGID\nNoNewPrivileges=true\nPrivateTmp=true\nProtectSystem=strict\nProtectHome=true\nDeviceAllow=/dev/net/tun rw\nRestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK\nRestrictSUIDSGID=true\nLockPersonality=true\nReadWritePaths={}\nReadOnlyPaths={}\n\n[Install]\nWantedBy=multi-user.target\n",
        systemd_quote(&spec.binary),
        systemd_quote(&spec.config),
        systemd_quote(&spec.state_dir),
        systemd_quote(&spec.state_dir),
        systemd_quote(spec.config.parent().unwrap_or_else(|| Path::new("/"))),
    )
}

fn render_launchd(spec: &ServiceSpec) -> String {
    let log_dir = spec.state_dir.join("logs");
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n<dict>\n  <key>Label</key><string>top.backrunner.maskman</string>\n  <key>ProgramArguments</key><array><string>{}</string><string>--config</string><string>{}</string><string>serve</string></array>\n  <key>EnvironmentVariables</key><dict><key>MASKMAN_ROLE</key><string>supervisor</string></dict>\n  <key>RunAtLoad</key><true/>\n  <key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>\n  <key>ThrottleInterval</key><integer>2</integer>\n  <key>SoftResourceLimits</key><dict><key>NumberOfFiles</key><integer>65536</integer></dict>\n  <key>HardResourceLimits</key><dict><key>NumberOfFiles</key><integer>65536</integer></dict>\n  <key>StandardOutPath</key><string>{}/stdout.log</string>\n  <key>StandardErrorPath</key><string>{}/stderr.log</string>\n</dict>\n</plist>\n",
        xml_escape(&spec.binary),
        xml_escape(&spec.config),
        xml_escape(&log_dir),
        xml_escape(&log_dir),
    )
}

fn systemd_quote(path: &Path) -> String {
    let value = path.to_string_lossy().replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{value}\"")
}

fn xml_escape(path: &Path) -> String {
    path.to_string_lossy()
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn manager_command(action: &str, spec: &ServiceSpec) -> Result<(), PlatformError> {
    let mut command = if cfg!(target_os = "macos") {
        launchd_command(action, &spec.service_path)
    } else if cfg!(target_os = "linux") {
        systemd_command(action, &spec.service_path)?
    } else {
        return Err(PlatformError::ServiceManagementUnavailable);
    };
    let output = command.stdin(Stdio::null()).output().map_err(PlatformError::ServiceCommand)?;
    let expected_idempotent_error = matches!(action, "install" | "uninstall")
        && String::from_utf8_lossy(&output.stderr)
            .to_ascii_lowercase()
            .contains(if action == "install" { "already" } else { "not found" });
    if output.status.success() || expected_idempotent_error {
        Ok(())
    } else {
        Err(PlatformError::ServiceCommand(std::io::Error::other(
            String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        )))
    }
}

fn systemd_command(action: &str, service_path: &Path) -> Result<Command, PlatformError> {
    let unit = service_path
        .file_name()
        .and_then(|value| value.to_str())
        .filter(|value| value.ends_with(".service"))
        .ok_or_else(|| {
            PlatformError::InvalidService(
                "systemd service path must have a .service file name".into(),
            )
        })?;
    let mut command = Command::new("systemctl");
    match action {
        "install" => {
            command.args(["daemon-reload", "--quiet"]);
        }
        "daemon-reload" => {
            command.args(["daemon-reload", "--quiet"]);
        }
        "uninstall" => {
            command.args(["disable", "--now", unit]);
        }
        "enable" => {
            command.args(["enable", unit]);
        }
        "reload" => {
            command.args(["reload", unit]);
        }
        _ => {
            command.args([action, unit]);
        }
    }
    Ok(command)
}

fn launchd_command(action: &str, service_path: &Path) -> Command {
    let mut command = Command::new("launchctl");
    match action {
        "install" => {
            command.args(["bootstrap", "system"]).arg(service_path);
        }
        "uninstall" => {
            command.args(["bootout", "system"]).arg(service_path);
        }
        "reload" => {
            command.args(["kickstart", "-k", "system/top.backrunner.maskman"]);
        }
        "start" => {
            command.args(["kickstart", "system/top.backrunner.maskman"]);
        }
        "stop" => {
            command.args(["kill", "SIGTERM", "system/top.backrunner.maskman"]);
        }
        _ => {}
    }
    command
}

fn status_systemd(service_path: &Path) -> Result<ServiceStatus, PlatformError> {
    let unit = service_path
        .file_name()
        .and_then(|value| value.to_str())
        .filter(|value| value.ends_with(".service"))
        .ok_or_else(|| {
            PlatformError::InvalidService(
                "systemd service path must have a .service file name".into(),
            )
        })?;
    let output = Command::new("systemctl")
        .args(["show", unit, "--property=ActiveState,MainPID", "--value"])
        .output()
        .map_err(PlatformError::ServiceCommand)?;
    if !output.status.success() {
        return Ok(ServiceStatus {
            installed: true,
            running: false,
            pid: None,
            detail: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        });
    }
    let output_text = String::from_utf8_lossy(&output.stdout);
    let lines = output_text.lines().collect::<Vec<_>>();
    let running = lines.first().copied() == Some("active");
    let pid =
        lines.get(1).and_then(|value| value.trim().parse::<u32>().ok()).filter(|pid| *pid > 0);
    Ok(ServiceStatus {
        installed: true,
        running,
        pid,
        detail: lines.first().unwrap_or(&"unknown").to_string(),
    })
}

fn status_launchd() -> Result<ServiceStatus, PlatformError> {
    let output = Command::new("launchctl")
        .args(["print", "system/top.backrunner.maskman"])
        .output()
        .map_err(PlatformError::ServiceCommand)?;
    let detail = String::from_utf8_lossy(if output.status.success() {
        &output.stdout
    } else {
        &output.stderr
    })
    .lines()
    .next()
    .unwrap_or("inactive")
    .to_owned();
    let pid = String::from_utf8_lossy(&output.stdout)
        .lines()
        .find_map(|line| line.trim().strip_prefix("pid = ").and_then(|value| value.parse().ok()));
    Ok(ServiceStatus { installed: true, running: output.status.success(), pid, detail })
}

#[cfg(unix)]
fn set_service_permissions(path: &Path) -> Result<(), PlatformError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o644)).map_err(PlatformError::ServiceIo)
}

#[cfg(not(unix))]
fn set_service_permissions(_path: &Path) -> Result<(), PlatformError> {
    Ok(())
}

#[cfg(test)]
#[path = "service_tests.rs"]
mod tests;
