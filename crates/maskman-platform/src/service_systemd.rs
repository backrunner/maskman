use std::{
    path::Path,
    process::{Command, Stdio},
};

use crate::{service::ServiceSpec, PlatformError, ServiceStatus};

pub fn render(spec: &ServiceSpec) -> String {
    format!(
        "[Unit]\nDescription=Maskman MASQUE proxy\nAfter=network-online.target\nWants=network-online.target\nStartLimitIntervalSec=60s\nStartLimitBurst=5\n\n[Service]\nType=simple\nGroup=maskman\nExecStart={} --config {} serve\nExecReload=/bin/kill -HUP $MAINPID\nEnvironment=MASKMAN_ROLE=supervisor\nKillMode=control-group\nRestart=on-failure\nRestartSec=2s\nRuntimeDirectory=maskman\nStateDirectory=maskman\nStateDirectoryMode=0770\nConfigurationDirectory=maskman\nWorkingDirectory={}\nLimitNOFILE=65536\nCapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_SETUID CAP_SETGID\nAmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_SETUID CAP_SETGID\nNoNewPrivileges=true\nPrivateTmp=true\nProtectSystem=strict\nProtectHome=true\nDeviceAllow=/dev/net/tun rw\nRestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK\nRestrictSUIDSGID=true\nLockPersonality=true\nReadWritePaths={}\nReadOnlyPaths={}\n\n[Install]\nWantedBy=multi-user.target\n",
        systemd_quote(&spec.binary),
        systemd_quote(&spec.config),
        systemd_path(&spec.state_dir),
        systemd_path(&spec.state_dir),
        systemd_path(spec.config.parent().unwrap_or_else(|| Path::new("/"))),
    )
}

/// Render a path for a systemd path directive. Quote only when the path needs
/// it: old systemd releases do not strip quotes from path settings and treat
/// them as literal characters, so routine paths must stay unquoted. `%` is
/// always escaped to avoid specifier expansion.
fn systemd_path(path: &Path) -> String {
    let value = path.to_string_lossy().replace('%', "%%");
    if value.bytes().any(|byte| byte.is_ascii_whitespace() || matches!(byte, b'"' | b'\'')) {
        format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
    } else {
        value
    }
}

/// Minimum systemd release the rendered unit relies on: StateDirectory,
/// ConfigurationDirectory, LockPersonality, and StateDirectoryMode all landed
/// in v235. Older releases silently ignore the sandbox directives, which is
/// not an acceptable degradation, so install refuses them instead.
const MIN_SYSTEMD_VERSION: u32 = 235;

pub fn require_supported_systemd() -> Result<(), PlatformError> {
    let output = Command::new("systemctl")
        .arg("--version")
        .stdin(Stdio::null())
        .output()
        .map_err(PlatformError::ServiceCommand)?;
    if !output.status.success() {
        return Err(PlatformError::ServiceCommand(std::io::Error::other(
            String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        )));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let major = systemd_major_version(&stdout).ok_or_else(|| {
        PlatformError::InvalidService("cannot parse `systemctl --version` output".into())
    })?;
    if major < MIN_SYSTEMD_VERSION {
        return Err(PlatformError::InvalidService(format!(
            "systemd {major} is too old; maskman requires systemd >= {MIN_SYSTEMD_VERSION} for its sandboxed unit — upgrade the distribution instead of weakening the unit"
        )));
    }
    Ok(())
}

fn systemd_major_version(version_output: &str) -> Option<u32> {
    version_output.lines().next()?.split_whitespace().nth(1)?.parse().ok()
}

fn systemd_quote(path: &Path) -> String {
    let value = path.to_string_lossy().replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{value}\"")
}

pub fn command(action: &str, service_path: &Path) -> Result<Command, PlatformError> {
    let unit = unit_name(service_path)?;
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

pub fn status(service_path: &Path) -> Result<ServiceStatus, PlatformError> {
    let unit = unit_name(service_path)?;
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

fn unit_name(service_path: &Path) -> Result<&str, PlatformError> {
    service_path
        .file_name()
        .and_then(|value| value.to_str())
        .filter(|value| value.ends_with(".service"))
        .ok_or_else(|| {
            PlatformError::InvalidService(
                "systemd service path must have a .service file name".into(),
            )
        })
}

#[cfg(test)]
#[path = "service_systemd_tests.rs"]
mod tests;
