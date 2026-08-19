use std::path::Path;

use anyhow::{Context, Result};

use crate::{cli::ConfigCommand, output::Output};

pub fn run(config: Option<&Path>, command: ConfigCommand, output: Output) -> Result<()> {
    match command {
        ConfigCommand::Validate { check_system } => {
            let path = config.ok_or_else(|| anyhow::anyhow!("--config is required"))?;
            let compiled = maskman_config::compile(path)
                .with_context(|| format!("validating config {}", path.display()))?;
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
    }
}

fn check_system_prerequisites(ip: &maskman_config::CompiledIp) -> Result<()> {
    if !ip.enabled {
        return Ok(());
    }
    if ip.nat_managed {
        anyhow::bail!("managed NAT is not available on this build; use nat.mode = \"disabled\"");
    }
    if cfg!(target_os = "linux") && !std::path::Path::new("/dev/net/tun").exists() {
        anyhow::bail!("CONNECT-IP is enabled but /dev/net/tun is unavailable")
    }
    if !cfg!(target_os = "linux") && !cfg!(target_os = "macos") {
        anyhow::bail!("CONNECT-IP platform support is unavailable on this target")
    }
    Ok(())
}
