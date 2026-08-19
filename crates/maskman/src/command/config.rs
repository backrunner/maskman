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
                output.warning("system prerequisite checks are not implemented in M0");
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
