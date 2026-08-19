use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};

use crate::{
    cli::{ActionArgs, StatusArgs, UpdateArgs},
    output::Output,
};

pub async fn serve(config: Option<&Path>, _output: Output) -> Result<()> {
    let path = require_config(config)?;
    let compiled = maskman_config::compile(&path)
        .with_context(|| format!("loading config {}", path.display()))?;
    maskman_server::serve(compiled).await.map_err(Into::into)
}

pub fn status(config: Option<&Path>, args: StatusArgs, output: Output) -> Result<()> {
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
    let service = maskman_platform::service_status(&spec)?;
    let (listen, connections, udp_sessions, ip_sessions) = compiled
        .as_ref()
        .map(|config| {
            let status = maskman_server::status(config);
            (
                status.listen.iter().map(ToString::to_string).collect::<Vec<_>>(),
                status.connections,
                status.udp_sessions,
                status.ip_sessions,
            )
        })
        .unwrap_or_default();
    let config_hash =
        compiled.as_ref().and_then(|_| fs::read(&path).ok()).map(|bytes| hex_digest(&bytes));
    if args.json {
        println!(
            "{}",
            serde_json::json!({
                "version": env!("CARGO_PKG_VERSION"),
                "service": {
                    "installed": service.installed,
                    "running": service.running,
                    "pid": service.pid,
                    "detail": service.detail,
                },
                "config": {
                    "path": path,
                    "hash_sha256": config_hash,
                },
                "listen": listen,
                "connections": connections,
                "udp_sessions": udp_sessions,
                "ip_sessions": ip_sessions,
                "transport_ready": service.running,
                "proxy_ready": service.running && compiled.is_some(),
            })
        );
    } else if service.running {
        output.success(format!(
            "maskman service is running{}",
            service.pid.map(|pid| format!(" (pid {pid})")).unwrap_or_default()
        ));
    } else if service.installed {
        output.warning(format!("maskman service is installed but inactive ({})", service.detail));
    } else {
        output.warning("maskman service is not installed");
    }
    Ok(())
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
            if args.dry_run {
                println!("service file: {}\n{}", spec.service_path.display(), rendered);
                return Ok(());
            }
            maskman_platform::install_service(&spec, false)?;
            output.success(format!("installed {}", spec.service_path.display()));
        }
        "uninstall" => {
            require_confirmation(&args, "uninstall service")?;
            maskman_platform::uninstall_service(&spec, args.dry_run)?;
            output.success("service definition removed");
        }
        "start" | "stop" | "reload" => {
            let action = match name {
                "start" => maskman_platform::ServiceAction::Start,
                "stop" => maskman_platform::ServiceAction::Stop,
                _ => maskman_platform::ServiceAction::Reload,
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

pub async fn cleanup(config: Option<&Path>, args: ActionArgs, output: Output) -> Result<()> {
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

pub fn update(args: UpdateArgs, _output: Output) -> Result<()> {
    if args.check {
        return Err(anyhow::anyhow!("update check requires the signed release client (M7)"));
    }
    Err(anyhow::anyhow!("signed update client is not configured in this build"))
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
