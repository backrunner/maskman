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

pub async fn run(config: Option<&Path>, command: TokenCommand, output: Output) -> Result<()> {
    let path = require_config(config)?;
    match command {
        TokenCommand::Create(args) => create(&path, args, output).await,
        TokenCommand::Revoke(args) => revoke(&path, args, output).await,
        TokenCommand::List(args) => list(&path, args),
    }
}

async fn create(path: &Path, args: TokenCreateArgs, output: Output) -> Result<()> {
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
    write_config_with_worker_access(path, &document)?;
    output.success(format!("created bearer token {id} for principal {principal}"));
    println!("Bearer token (shown once): mm_{id}_{encoded}");
    super::print_surge_credentials(&document, &format!("mm_{id}_{encoded}"));
    if args.reload {
        reload_service(path).await?;
        output.success("requested service reload");
    }
    Ok(())
}

async fn revoke(path: &Path, args: TokenRevokeArgs, output: Output) -> Result<()> {
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
        write_config_with_worker_access(path, &document)?;
        output.success(format!("revoked bearer token {}", args.id));
    }
    if args.reload {
        reload_service(path).await?;
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

async fn reload_service(path: &Path) -> Result<()> {
    let config = maskman_config::compile(path)
        .with_context(|| format!("loading config {}", path.display()))?;
    let socket = maskman_server::control::socket_path(&config);
    if let Some(response) = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        maskman_server::control::request(&socket, maskman_server::control::ControlCommand::Reload),
    )
    .await
    .ok()
    .and_then(|result| result.ok())
    {
        if response.ok {
            return Ok(());
        }
        anyhow::bail!(
            "daemon rejected credential reload: {}",
            response.error.as_deref().unwrap_or("unknown control error")
        );
    }
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

fn write_config_with_worker_access(
    path: &Path,
    document: &maskman_config::ConfigDocument,
) -> Result<()> {
    let absolute = absolute_path(path)?;
    let base_dir = absolute.parent().unwrap_or_else(|| Path::new("/"));
    let compiled = maskman_config::compile_document(document, base_dir)
        .with_context(|| format!("compiling updated configuration {}", path.display()))?;
    let binary = std::env::current_exe().context("locating current maskman binary")?;
    let spec =
        maskman_platform::ServiceSpec::new(binary, absolute.clone(), compiled.state_dir.clone())?;
    let installed = spec.service_path.exists();
    if installed {
        prepare_worker_access(&spec, &compiled)?;
    }
    maskman_config::write_atomic(path, document)
        .with_context(|| format!("writing {}", path.display()))?;
    if installed {
        let refreshed = maskman_config::compile(&absolute)
            .with_context(|| format!("reloading updated configuration {}", path.display()))?;
        prepare_worker_access(&spec, &refreshed)?;
    }
    Ok(())
}

fn prepare_worker_access(
    spec: &maskman_platform::ServiceSpec,
    config: &maskman_config::CompiledConfig,
) -> Result<()> {
    maskman_platform::prepare_worker_access(
        &spec.config,
        &config.certificate_file,
        &config.private_key_file,
        config.client_ca_file.as_deref(),
        &config.state_dir,
    )
    .map_err(|error| anyhow::anyhow!(error))
    .context(
        "the installed worker cannot read configuration or TLS files; run maskman install as root",
    )
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
