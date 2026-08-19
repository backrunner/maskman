use std::path::Path;

use anyhow::{Context, Result};

use crate::{
    cli::{StatusArgs, UpdateArgs},
    output::Output,
};

pub async fn serve(config: Option<&Path>, _output: Output) -> Result<()> {
    let path = config.ok_or_else(|| anyhow::anyhow!("--config is required for serve"))?;
    let compiled = maskman_config::compile(path)
        .with_context(|| format!("loading config {}", path.display()))?;
    maskman_server::serve(compiled).await.map_err(Into::into)
}

pub fn status(config: Option<&Path>, args: StatusArgs, output: Output) -> Result<()> {
    let path = config.ok_or_else(|| anyhow::anyhow!("--config is required for status"))?;
    let compiled = maskman_config::compile(path)
        .with_context(|| format!("loading config {}", path.display()))?;
    let status = maskman_server::status(&compiled);
    if args.json {
        println!(
            "{}",
            serde_json::json!({
                "version": env!("CARGO_PKG_VERSION"),
                "listen": status.listen.iter().map(ToString::to_string).collect::<Vec<_>>(),
                "connections": status.connections,
                "udp_sessions": status.udp_sessions,
                "ip_sessions": status.ip_sessions,
                "transport_ready": true,
                "proxy_ready": false
            })
        );
    } else {
        output.warning("HTTP/3 transport is available; proxy forwarding is not implemented yet");
        output.success(format!(
            "configured listeners: {}, active connections: {}",
            status.listen.len(),
            status.connections
        ));
    }
    Ok(())
}

pub fn action(name: &str, _yes: bool, _output: Output) -> Result<()> {
    anyhow::bail!("{name} is not implemented in M0; use maskman serve --config <path>")
}

pub fn update(args: UpdateArgs, _output: Output) -> Result<()> {
    if args.check {
        anyhow::bail!("update checks are not implemented in M0")
    }
    anyhow::bail!("update is not implemented in M0; signing and rollback land in M7")
}
