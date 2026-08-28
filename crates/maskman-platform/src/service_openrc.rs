use std::{
    fs,
    path::Path,
    process::{Command, Stdio},
};

use crate::{service::ServiceSpec, PlatformError, ServiceStatus};

/// Render an OpenRC service script for Alpine-style hosts.
///
/// Paths are validated against a conservative charset instead of being
/// shell-escaped: openrc-run evaluates the start line through the shell more
/// than once (variable expansion plus `eval`), so no single layer of quoting
/// survives, and `supervise-daemon` expands `$command`/`$directory` unquoted
/// anyway. Rejecting unsafe paths fails closed instead of promising escaping
/// that cannot hold.
///
/// OpenRC has no equivalent of the systemd sandbox directives (StateDirectory,
/// ProtectSystem, RestrictAddressFamilies, ...). The worker still drops to the
/// dedicated maskman identity internally, but the kernel-level sandbox is
/// absent; this trade-off is documented in the operator runbook.
pub fn render(spec: &ServiceSpec) -> Result<String, PlatformError> {
    let binary = openrc_path(&spec.binary, "binary")?;
    let config = openrc_path(&spec.config, "config")?;
    let state_dir = openrc_path(&spec.state_dir, "state directory")?;
    let stdout_log = openrc_path(&spec.state_dir.join("logs/stdout.log"), "state directory")?;
    let stderr_log = openrc_path(&spec.state_dir.join("logs/stderr.log"), "state directory")?;
    let log_dir = openrc_path(&spec.state_dir.join("logs"), "state directory")?;
    Ok(format!(
        "#!/sbin/openrc-run\nname=\"maskman\"\ndescription=\"Maskman MASQUE proxy\"\nsupervisor=\"supervise-daemon\"\ncommand={binary}\ncommand_args=\"--config {config} serve\"\ndirectory={state_dir}\npidfile=\"/run/maskman.pid\"\noutput_log={stdout_log}\nerror_log={stderr_log}\n\ndepend() {{\n    need net\n    after firewall\n}}\n\nstart_pre() {{\n    checkpath --directory --mode 0750 --owner root:maskman {state_dir} {log_dir}\n}}\n\nreload() {{\n    ebegin \"Reloading maskman\"\n    start-stop-daemon --signal HUP --pidfile \"$pidfile\"\n    eend $?\n}}\n"
    ))
}

fn openrc_path(path: &Path, field: &str) -> Result<String, PlatformError> {
    let value = path
        .to_str()
        .ok_or_else(|| PlatformError::InvalidService(format!("{field} path is not valid UTF-8")))?;
    if value.is_empty()
        || !value.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"/._-".contains(&byte))
    {
        return Err(PlatformError::InvalidService(format!(
            "{field} path {value:?} contains characters an OpenRC service script cannot safely represent"
        )));
    }
    Ok(value.to_owned())
}

pub fn command(action: &str, service_path: &Path) -> Result<Command, PlatformError> {
    let name = service_name(service_path)?;
    let mut command = match action {
        "install" | "enable" => {
            let mut command = Command::new("rc-update");
            command.args(["add", name, "default"]);
            command
        }
        "uninstall" => {
            let mut command = Command::new("rc-update");
            command.args(["del", name, "default"]);
            command
        }
        _ => {
            let mut command = Command::new("rc-service");
            command.args([name, action]);
            command
        }
    };
    command.stdin(Stdio::null());
    Ok(command)
}

pub fn status(service_path: &Path) -> Result<ServiceStatus, PlatformError> {
    let name = service_name(service_path)?;
    let output = Command::new("rc-service")
        .args([name, "status"])
        .stdin(Stdio::null())
        .output()
        .map_err(PlatformError::ServiceCommand)?;
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let running = output.status.success() && stdout.contains("started");
    let pid = if running {
        fs::read_to_string("/run/maskman.pid")
            .ok()
            .and_then(|value| value.trim().parse::<u32>().ok())
            .filter(|pid| *pid > 0)
    } else {
        None
    };
    let detail = stdout.lines().next().unwrap_or("unknown").to_owned();
    Ok(ServiceStatus { installed: true, running, pid, detail })
}

fn service_name(service_path: &Path) -> Result<&str, PlatformError> {
    service_path
        .file_name()
        .and_then(|value| value.to_str())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            PlatformError::InvalidService("OpenRC service path must have a file name".into())
        })
}

#[cfg(test)]
#[path = "service_openrc_tests.rs"]
mod tests;
