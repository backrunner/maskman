use std::{
    io::IsTerminal,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};

use crate::{
    cli::{TokenCommand, TokenCreateArgs, TokenListArgs, TokenRevokeArgs},
    output::Output,
};

pub fn run(config: Option<&Path>, command: TokenCommand, output: Output) -> Result<()> {
    let path = require_config(config)?;
    match command {
        TokenCommand::Create(args) => create(&path, args, output),
        TokenCommand::Revoke(args) => revoke(&path, args, output),
        TokenCommand::List(args) => list(&path, args),
    }
}

fn create(path: &Path, args: TokenCreateArgs, output: Output) -> Result<()> {
    require_confirmation(args.yes, "create bearer token")?;
    let mut document =
        maskman_config::load(path).with_context(|| format!("loading config {}", path.display()))?;
    let principal = args
        .principal
        .or_else(|| document.auth.principals.first().map(|value| value.id.clone()))
        .ok_or_else(|| {
            anyhow::anyhow!("no principal exists; run setup or add a principal first")
        })?;
    if !document.auth.principals.iter().any(|value| value.id == principal) {
        anyhow::bail!("principal {principal} is not configured");
    }
    let id = args.id.unwrap_or_else(generate_token_id);
    validate_identifier(&id, "token ID")?;
    if document.auth.bearer_tokens.iter().any(|value| value.id == id) {
        anyhow::bail!("bearer token {id} already exists");
    }
    let mut secret = [0u8; 32];
    OsRng.fill_bytes(&mut secret);
    let encoded = URL_SAFE_NO_PAD.encode(secret);
    let digest = Sha256::digest(encoded.as_bytes());
    let secret_sha256 = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    document.auth.bearer_tokens.push(maskman_config::model::BearerTokenConfig {
        id: id.clone(),
        principal: principal.clone(),
        secret_sha256,
        expires_at: args.expires_at,
        enabled: true,
    });
    maskman_config::validate(&document).context("validating token update")?;
    maskman_config::write_atomic(path, &document)
        .with_context(|| format!("writing {}", path.display()))?;
    output.success(format!("created bearer token {id} for principal {principal}"));
    println!("Bearer token (shown once): mm_{id}_{encoded}");
    if args.reload {
        reload_service(path)?;
        output.success("requested service reload");
    }
    Ok(())
}

fn revoke(path: &Path, args: TokenRevokeArgs, output: Output) -> Result<()> {
    require_confirmation(args.yes, "revoke bearer token")?;
    let mut document =
        maskman_config::load(path).with_context(|| format!("loading config {}", path.display()))?;
    let token = document
        .auth
        .bearer_tokens
        .iter_mut()
        .find(|value| value.id == args.id)
        .ok_or_else(|| anyhow::anyhow!("bearer token {} does not exist", args.id))?;
    if !token.enabled {
        output.warning(format!("bearer token {} is already revoked", args.id));
    } else {
        token.enabled = false;
        maskman_config::validate(&document).context("validating token update")?;
        maskman_config::write_atomic(path, &document)
            .with_context(|| format!("writing {}", path.display()))?;
        output.success(format!("revoked bearer token {}", args.id));
    }
    if args.reload {
        reload_service(path)?;
        output.success("requested service reload");
    }
    Ok(())
}

fn list(path: &Path, args: TokenListArgs) -> Result<()> {
    let document =
        maskman_config::load(path).with_context(|| format!("loading config {}", path.display()))?;
    if args.json {
        let tokens = document
            .auth
            .bearer_tokens
            .iter()
            .map(|token| {
                serde_json::json!({
                    "id": token.id,
                    "principal": token.principal,
                    "expires_at": token.expires_at,
                    "enabled": token.enabled,
                })
            })
            .collect::<Vec<_>>();
        println!("{}", serde_json::json!({"tokens": tokens}));
        return Ok(());
    }
    println!("ID\tPRINCIPAL\tENABLED\tEXPIRES_AT");
    for token in document.auth.bearer_tokens {
        println!(
            "{}\t{}\t{}\t{}",
            token.id,
            token.principal,
            token.enabled,
            token.expires_at.as_deref().unwrap_or("never")
        );
    }
    Ok(())
}

fn reload_service(path: &Path) -> Result<()> {
    let config = maskman_config::compile(path)
        .with_context(|| format!("loading config {}", path.display()))?;
    let binary = std::env::current_exe().context("locating current maskman binary")?;
    let absolute =
        if path.is_absolute() { path.to_path_buf() } else { std::env::current_dir()?.join(path) };
    let spec = maskman_platform::ServiceSpec::new(binary, absolute, config.state_dir)?;
    maskman_platform::service_control(&spec, maskman_platform::ServiceAction::Reload)
        .context("reloading maskman service")?;
    Ok(())
}

fn require_config(config: Option<&Path>) -> Result<PathBuf> {
    let path = config.map(PathBuf::from).unwrap_or_else(maskman_platform::default_config_path);
    if !path.exists() {
        anyhow::bail!("config {} does not exist; run maskman setup first", path.display());
    }
    Ok(path)
}

fn require_confirmation(yes: bool, action: &str) -> Result<()> {
    if !yes && !std::io::stdin().is_terminal() {
        anyhow::bail!("{action} changes configuration; pass --yes in non-interactive mode");
    }
    Ok(())
}

fn validate_identifier(value: &str, field: &str) -> Result<()> {
    if value.is_empty()
        || !value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "-._".contains(character))
    {
        anyhow::bail!("{field} must contain only ASCII letters, numbers, '.', '_' or '-'");
    }
    Ok(())
}

fn generate_token_id() -> String {
    let mut bytes = [0u8; 6];
    OsRng.fill_bytes(&mut bytes);
    let suffix = bytes.iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    format!("tok_{suffix}")
}
