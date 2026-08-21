use std::path::Path;

use anyhow::{Context, Result};

use crate::{cli::ConfigCommand, output::Output};

pub fn run(config: Option<&Path>, command: ConfigCommand, output: Output) -> Result<()> {
    match command {
        ConfigCommand::Validate { check_system } => {
            let path = config.ok_or_else(|| anyhow::anyhow!("--config is required"))?;
            let compiled = maskman_config::compile(path)
                .with_context(|| format!("validating config {}", path.display()))?;
            maskman_server::validate_tls(&compiled)
                .context("validating TLS certificate, private key, and client CA")?;
            output.info(format!("validated {}", path.display()));
            if check_system {
                check_system_prerequisites(&compiled.ip)?;
                output.success(format!(
                    "{} platform prerequisites available",
                    maskman_platform::platform_name()
                ));
            }
            output.success(format!(
                "configuration valid: {} listener(s), auth_required={}, udp={}, ip={}",
                compiled.listen.len(),
                compiled.auth_required,
                compiled.udp.enabled,
                compiled.ip.enabled
            ));
            Ok(())
        }
        ConfigCommand::Migrate { dry_run } => {
            let path = config.ok_or_else(|| anyhow::anyhow!("--config is required"))?;
            let mut document = maskman_config::load(path)
                .with_context(|| format!("loading config {}", path.display()))?;
            if document.schema_version > 1 {
                anyhow::bail!(
                    "config schema {} is newer than this binary; install a newer maskman",
                    document.schema_version
                );
            }
            let changed = document.schema_version != 1;
            document.schema_version = 1;
            maskman_config::validate(&document).context("validating migrated configuration")?;
            if dry_run {
                if changed {
                    output.info(format!("would migrate {} to schema 1", path.display()));
                } else {
                    output.success(format!("{} is already schema 1", path.display()));
                }
            } else if changed {
                maskman_config::write_atomic(path, &document)
                    .with_context(|| format!("writing migrated config {}", path.display()))?;
                output.success(format!("migrated {} to schema 1", path.display()));
            } else {
                output.success(format!("{} is already schema 1", path.display()));
            }
            Ok(())
        }
    }
}

fn check_system_prerequisites(ip: &maskman_config::CompiledIp) -> Result<()> {
    if ip.enabled && !maskman_platform::worker_identity_available() {
        anyhow::bail!(
            "service worker identity `maskman` is missing; create the dedicated user/group first"
        );
    }
    if !ip.enabled {
        return Ok(());
    }
    if ip.nat_managed && !maskman_platform::managed_nat_available() {
        anyhow::bail!(
            "managed NAT is enabled but the platform backend (nftables/pfctl) is unavailable"
        );
    }
    if cfg!(target_os = "linux") && !std::path::Path::new("/dev/net/tun").exists() {
        anyhow::bail!("CONNECT-IP is enabled but /dev/net/tun is unavailable")
    }
    if !cfg!(target_os = "linux") && !cfg!(target_os = "macos") {
        anyhow::bail!("CONNECT-IP platform support is unavailable on this target")
    }
    Ok(())
}
