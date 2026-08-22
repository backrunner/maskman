use std::{
    fs,
    io::{self, IsTerminal, Write},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::{
    cli::{ActionArgs, StatusArgs, UpdateArgs},
    output::Output,
};

use super::update_service::PlatformService;

pub async fn serve(config: Option<&Path>, _output: Output) -> Result<()> {
    let path = require_config(config)?;
    let compiled = maskman_config::compile(&path)
        .with_context(|| format!("loading config {}", path.display()))?;
    let path = absolute_path(&path)?;
    maskman_server::serve_with_config_path(compiled, path).await.map_err(Into::into)
}

pub async fn worker(config: Option<&Path>) -> Result<()> {
    let path = require_config(config)?;
    let compiled = maskman_config::compile(&path)
        .with_context(|| format!("loading config {}", path.display()))?;
    let path = absolute_path(&path)?;
    let resources = maskman_server::worker_resources_from_environment(&compiled)
        .map_err(|error| anyhow::anyhow!(error))?;
    maskman_server::serve_worker_with_resources(compiled, path, resources).await.map_err(Into::into)
}

pub async fn status(config: Option<&Path>, args: StatusArgs, output: Output) -> Result<()> {
    let path = config.map(PathBuf::from).unwrap_or_else(maskman_platform::default_config_path);
    let compiled = if path.exists() {
        Some(
            maskman_config::compile(&path)
                .with_context(|| format!("loading config {}", path.display()))?,
        )
    } else {
        None
    };
    let binary = std::env::current_exe().context("locating current maskman binary")?;
    let state_dir = compiled
        .as_ref()
        .map(|config| config.state_dir.clone())
        .unwrap_or_else(maskman_platform::default_state_dir);
    let spec = maskman_platform::ServiceSpec::new(binary, absolute_path(&path)?, state_dir)?;
    let service = maskman_platform::service_status(&spec).unwrap_or_else(|error| {
        maskman_platform::ServiceStatus {
            installed: spec.service_path.exists(),
            running: false,
            pid: None,
            detail: format!("service manager unavailable: {error}"),
        }
    });
    let daemon = match compiled.as_ref() {
        Some(config) => control_status(config).await.ok(),
        None => None,
    };
    let listen = daemon
        .as_ref()
        .map(|status| status.listen.clone())
        .or_else(|| {
            compiled.as_ref().map(|config| config.listen.iter().map(ToString::to_string).collect())
        })
        .unwrap_or_default();
    let runtime = daemon.as_ref().map(|status| &status.runtime);
    let daemon_ready = daemon.as_ref().is_some_and(|daemon| daemon.ready);
    let connections = runtime.map_or(0, |runtime| runtime.active_connections);
    let udp_sessions = runtime.map_or(0, |runtime| runtime.active_udp_sessions);
    let ip_sessions = runtime.map_or(0, |runtime| runtime.active_ip_sessions);
    let config_hash =
        compiled.as_ref().and_then(|_| fs::read(&path).ok()).map(|bytes| hex_digest(&bytes));
    if args.json {
        let status = StatusOutput {
            version: env!("CARGO_PKG_VERSION").to_owned(),
            service: ServiceOutput {
                installed: service.installed,
                running: service.running,
                pid: service.pid,
                detail: service.detail,
            },
            config: ConfigOutput { path, hash_sha256: config_hash },
            listen,
            metrics_listen: daemon.as_ref().map(|status| status.metrics_listen.clone()),
            connections,
            udp_sessions,
            ip_sessions,
            runtime: runtime.cloned(),
            daemon: daemon.clone(),
            transport_ready: daemon_ready,
            proxy_ready: daemon_ready,
        };
        println!("{}", serde_json::to_string(&status).context("encoding status JSON")?);
    } else if let Some(daemon) = daemon {
        output.success(format!(
            "maskman daemon is ready (pid {}, uptime {}s, connections {}, udp {}, ip {})",
            daemon.pid,
            daemon.runtime.uptime_seconds,
            daemon.runtime.active_connections,
            daemon.runtime.active_udp_sessions,
            daemon.runtime.active_ip_sessions,
        ));
    } else if service.running {
        output.warning("maskman process is running but its control socket is unavailable");
    } else if service.installed {
        output.warning(format!("maskman service is installed but inactive ({})", service.detail));
    } else {
        output.warning("maskman service is not installed");
    }
    Ok(())
}

#[derive(Debug, Serialize)]
struct StatusOutput {
    version: String,
    service: ServiceOutput,
    config: ConfigOutput,
    listen: Vec<String>,
    metrics_listen: Option<String>,
    connections: u64,
    udp_sessions: u64,
    ip_sessions: u64,
    runtime: Option<maskman_server::RuntimeSnapshot>,
    daemon: Option<maskman_server::control::DaemonStatus>,
    transport_ready: bool,
    proxy_ready: bool,
}

#[derive(Debug, Serialize)]
struct ServiceOutput {
    installed: bool,
    running: bool,
    pid: Option<u32>,
    detail: String,
}

#[derive(Debug, Serialize)]
struct ConfigOutput {
    path: PathBuf,
    hash_sha256: Option<String>,
}

pub fn action(name: &str, config: Option<&Path>, args: ActionArgs, output: Output) -> Result<()> {
    let path = require_config(config)?;
    let compiled = maskman_config::compile(&path)
        .with_context(|| format!("validating config {}", path.display()))?;
    let binary = std::env::current_exe().context("locating current maskman binary")?;
    let spec = maskman_platform::ServiceSpec::new(
        binary,
        absolute_path(&path)?,
        compiled.state_dir.clone(),
    )?;
    match name {
        "install" => {
            require_confirmation(&args, "install service")?;
            let rendered = spec.render()?;
            maskman_server::validate_tls(&compiled)
                .context("validating TLS certificate, private key, and client CA")?;
            if args.dry_run {
                let identity = maskman_platform::ensure_worker_identity(true)?;
                let identity_plan = match identity {
                    maskman_platform::WorkerIdentityProvision::Existing => "already present",
                    maskman_platform::WorkerIdentityProvision::Created
                    | maskman_platform::WorkerIdentityProvision::WouldCreate => "would create",
                };
                println!(
                    "worker identity {}: {}",
                    maskman_platform::worker_identity().0,
                    identity_plan
                );
                println!("service file: {}\n{}", spec.service_path.display(), rendered);
                return Ok(());
            }
            maskman_platform::ensure_worker_identity(false)
                .map_err(|error| anyhow::anyhow!(error))
                .context("creating the dedicated maskman worker identity")?;
            maskman_platform::prepare_worker_access(
                &spec.config,
                &compiled.certificate_file,
                &compiled.private_key_file,
                compiled.client_ca_file.as_deref(),
                &compiled.state_dir,
            )
            .map_err(|error| anyhow::anyhow!(error))
            .context("preparing configuration and TLS files for the maskman worker")?;
            maskman_platform::install_service(&spec, false)?;
            output.success(format!("installed {}", spec.service_path.display()));
        }
        "uninstall" => {
            require_confirmation(&args, "uninstall service")?;
            maskman_platform::uninstall_service(&spec, args.dry_run)?;
            output.success("service definition removed");
        }
        "start" | "stop" => {
            let action = match name {
                "start" => maskman_platform::ServiceAction::Start,
                "stop" => maskman_platform::ServiceAction::Stop,
                _ => unreachable!("lifecycle action was validated"),
            };
            if args.dry_run {
                output.info(format!("would {name} {}", spec.service_path.display()));
            } else {
                maskman_platform::service_control(&spec, action)?;
                output.success(format!("{name} requested"));
            }
        }
        _ => anyhow::bail!("unsupported lifecycle action {name}"),
    }
    Ok(())
}

pub async fn reload(config: Option<&Path>, args: ActionArgs, output: Output) -> Result<()> {
    let path = require_config(config)?;
    let compiled = maskman_config::compile(&path)
        .with_context(|| format!("validating config {}", path.display()))?;
    if args.dry_run {
        output.success("configuration is valid; reload was not requested");
        return Ok(());
    }
    let socket = maskman_server::control::socket_path(&compiled);
    let response = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        maskman_server::control::request(&socket, maskman_server::control::ControlCommand::Reload),
    )
    .await
    .context("timed out waiting for daemon reload")?
    .with_context(|| format!("contacting daemon at {}", socket.display()))?;
    if !response.ok {
        anyhow::bail!(
            "daemon rejected reload: {}",
            response.error.as_deref().unwrap_or("unknown control error")
        );
    }
    let generation =
        response.status.as_ref().map(|status| status.config_generation).unwrap_or_default();
    output.success(format!("configuration reloaded (generation {generation})"));
    Ok(())
}

async fn control_status(
    config: &maskman_config::CompiledConfig,
) -> Result<maskman_server::control::DaemonStatus> {
    let socket = maskman_server::control::socket_path(config);
    let response = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        maskman_server::control::request(&socket, maskman_server::control::ControlCommand::Status),
    )
    .await
    .context("control status timed out")??;
    if !response.ok {
        anyhow::bail!(response.error.unwrap_or_else(|| "control status failed".to_owned()));
    }
    response.status.ok_or_else(|| anyhow::anyhow!("daemon returned no status payload"))
}

pub async fn cleanup(config: Option<&Path>, args: ActionArgs, output: Output) -> Result<()> {
    require_confirmation(&args, "clean owned network resources")?;
    let path = config.map(PathBuf::from).unwrap_or_else(maskman_platform::default_config_path);
    let state_dir = if path.exists() {
        maskman_config::compile(&path)
            .with_context(|| format!("loading config {}", path.display()))?
            .state_dir
    } else {
        maskman_platform::default_state_dir()
    };
    let journal = state_dir.join("resource-journal.json");
    let report = maskman_platform::cleanup_journal(&journal, args.dry_run).await?;
    if args.dry_run {
        output.info(format!("would inspect {} resource(s)", report.inspected));
    }
    output.success(format!("{} resource(s) cleaned", report.removed));
    Ok(())
}

pub fn update(config: Option<&Path>, args: UpdateArgs, output: Output) -> Result<()> {
    let config_path = config.map(PathBuf::from).filter(|path| path.exists());
    let document = config_path
        .as_deref()
        .map(maskman_config::load)
        .transpose()
        .context("loading update configuration")?;
    let repository = document
        .as_ref()
        .map(|value| value.update.repository.as_str())
        .unwrap_or("backrunner/maskman");
    let client = maskman_update::UpdateClient::new(repository, env!("CARGO_PKG_VERSION"))
        .map_err(|error| anyhow::anyhow!(error))?;
    let release = match client.latest(args.version.as_deref()) {
        Ok(release) => release,
        Err(maskman_update::UpdateError::NoUpdateAvailable(version, target)) => {
            output.success(format!("current {version}; no newer signed release for {target}"));
            return Ok(());
        }
        Err(error) => return Err(anyhow::anyhow!(error)),
    };
    if args.check {
        output.success(format!(
            "current {}; latest signed {} for {}",
            client.current_version(),
            release.version,
            client.target()
        ));
        return Ok(());
    }
    if !args.yes {
        if !io::stdin().is_terminal() {
            anyhow::bail!(
                "update changes the installed binary; pass --yes in non-interactive mode"
            );
        }
        print!("Install signed maskman {}? [y/N]: ", release.version);
        io::stdout().flush().context("flushing update confirmation")?;
        let mut answer = String::new();
        io::stdin().read_line(&mut answer).context("reading update confirmation")?;
        if !matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
            anyhow::bail!("update cancelled");
        }
    }
    output.info(format!("downloading signed release {}", release.version));
    let artifact = client.download_verified(&release).map_err(|error| anyhow::anyhow!(error))?;
    let binary = std::env::current_exe().context("locating current maskman binary")?;
    let controller = match config_path.as_deref() {
        Some(path) => {
            let compiled = maskman_config::compile(path)
                .with_context(|| format!("loading config {}", path.display()))?;
            let spec = maskman_platform::ServiceSpec::new(
                binary.clone(),
                absolute_path(path)?,
                compiled.state_dir.clone(),
            )?;
            let status = maskman_platform::service_status(&spec)?;
            status
                .installed
                .then(|| PlatformService::new(spec, &compiled, release.version.to_string()))
        }
        None => None,
    };
    let controller_ref =
        controller.as_ref().map(|value| value as &dyn maskman_update::ServiceController);
    let outcome = maskman_update::install_verified(
        &artifact,
        &binary,
        config_path.as_deref(),
        controller_ref,
    )
    .map_err(|error| anyhow::anyhow!(error))?;
    output.success(format!("updated maskman to {}", outcome.version));
    Ok(())
}

fn require_config(config: Option<&Path>) -> Result<PathBuf> {
    let path = config.map(PathBuf::from).unwrap_or_else(maskman_platform::default_config_path);
    if !path.exists() {
        anyhow::bail!("config {} does not exist; run maskman setup first", path.display());
    }
    Ok(path)
}

fn absolute_path(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        std::env::current_dir()
            .context("locating current directory")
            .map(|directory| directory.join(path))
    }
}

fn require_confirmation(args: &ActionArgs, action: &str) -> Result<()> {
    if !args.yes && !args.dry_run {
        anyhow::bail!("{action} changes system state; pass --yes or use --dry-run")
    }
    Ok(())
}

fn hex_digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{require_confirmation, ConfigOutput, ServiceOutput, StatusOutput};
    use crate::cli::ActionArgs;

    #[test]
    fn destructive_lifecycle_actions_require_confirmation_or_dry_run() {
        assert!(require_confirmation(
            &ActionArgs { yes: false, dry_run: false },
            "clean resources"
        )
        .is_err());
        assert!(require_confirmation(&ActionArgs { yes: true, dry_run: false }, "clean resources")
            .is_ok());
        assert!(require_confirmation(&ActionArgs { yes: false, dry_run: true }, "clean resources")
            .is_ok());
    }

    #[test]
    fn status_json_schema_has_stable_operational_keys() {
        let value = serde_json::to_value(StatusOutput {
            version: "0.1.0".into(),
            service: ServiceOutput {
                installed: false,
                running: false,
                pid: None,
                detail: "inactive".into(),
            },
            config: ConfigOutput { path: PathBuf::from("/tmp/config.toml"), hash_sha256: None },
            listen: Vec::new(),
            metrics_listen: None,
            connections: 0,
            udp_sessions: 0,
            ip_sessions: 0,
            runtime: None,
            daemon: None,
            transport_ready: false,
            proxy_ready: false,
        })
        .unwrap_or_else(|error| panic!("serialize status: {error}"));
        for key in [
            "version",
            "service",
            "config",
            "listen",
            "connections",
            "udp_sessions",
            "ip_sessions",
            "transport_ready",
            "proxy_ready",
        ] {
            assert!(value.get(key).is_some(), "missing status key {key}");
        }
    }
}
