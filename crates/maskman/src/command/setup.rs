use std::{
    io::{self, IsTerminal, Write},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};

use crate::{
    cli::{AuthModeArg, ConfigFormatArg, SetupArgs},
    output::Output,
};

#[path = "setup_tls.rs"]
mod development_tls;

pub fn run(config: Option<&Path>, mut args: SetupArgs, output: Output) -> Result<()> {
    let interactive =
        !args.non_interactive && io::stdin().is_terminal() && io::stdout().is_terminal();
    if interactive {
        collect_interactive(&mut args, config)?;
    }
    let explicit_output = args.output.is_some();
    let output_path = args
        .output
        .take()
        .or_else(|| config.map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from(format!("config.{}", args.format.extension())));
    format_for_output(&output_path, args.format, explicit_output || config.is_none())?;
    if output_path.exists() && !args.yes {
        if !interactive {
            anyhow::bail!(
                "{} already exists; pass --yes in non-interactive mode to replace it",
                output_path.display()
            );
        }
        if !confirm(&format!("Replace {}?", output_path.display()), false)? {
            anyhow::bail!("setup cancelled; existing configuration was left unchanged");
        }
    }
    let validate_supplied_tls = args.certificate_file.is_some() || args.private_key_file.is_some();
    let (mut document, token) = build_document(&args)?;
    if args.development && args.state_dir.is_none() {
        // Development setup must be usable by an ordinary user. Relative
        // paths are resolved from the config directory by maskman-config.
        document.server.state_dir = "state".into();
    }
    maskman_config::validate(&document).context("validating generated configuration")?;
    let generated_tls = if args.development {
        Some(development_tls::ensure(&output_path, &document)?)
    } else {
        None
    };
    if validate_supplied_tls {
        validate_document_tls(&output_path, &document)?;
    }
    if args.development {
        if let Err(error) = validate_document_tls(&output_path, &document) {
            if let Some(tls) = &generated_tls {
                tls.cleanup_after_failure();
            }
            return Err(error);
        }
    }
    if let Err(error) = maskman_config::write_atomic(&output_path, &document)
        .with_context(|| format!("writing {}", output_path.display()))
    {
        if let Some(tls) = &generated_tls {
            tls.cleanup_after_failure();
        }
        return Err(error);
    }
    output.success(format!("wrote {}", output_path.display()));
    if let Some(tls) = generated_tls {
        let action = if tls.was_generated() { "generated" } else { "reused" };
        output.success(format!(
            "{action} development TLS certificate {} and private key {}",
            tls.certificate.display(),
            tls.private_key.display()
        ));
    }
    if let Some(token) = token {
        println!("Bearer token (shown once): {token}");
    }
    if !args.development && !validate_supplied_tls {
        output.warning(
            "TLS files are placeholders; provide certificate_file and private_key_file before serving",
        );
    }
    output.info(format!("next: maskman --config {} config validate", output_path.display()));
    Ok(())
}

fn validate_document_tls(
    config_path: &Path,
    document: &maskman_config::ConfigDocument,
) -> Result<()> {
    let base = config_path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let compiled = maskman_config::compile_document(document, base)
        .context("compiling generated TLS configuration")?;
    maskman_server::validate_tls(&compiled).context("validating TLS certificate and private key")
}

fn format_for_output(
    path: &Path,
    requested: ConfigFormatArg,
    enforce_requested: bool,
) -> Result<maskman_config::ConfigFormat> {
    let actual = maskman_config::ConfigFormat::from_path(path)
        .map_err(|_| anyhow::anyhow!("{} must end in .toml or .json", path.display()))?;
    if enforce_requested && actual != requested.into_format() {
        anyhow::bail!(
            "output {} does not match --format {}; choose a .{} path or change --format",
            path.display(),
            requested.extension(),
            requested.extension()
        );
    }
    Ok(actual)
}

fn build_document(args: &SetupArgs) -> Result<(maskman_config::ConfigDocument, Option<String>)> {
    let mut document = maskman_config::ConfigDocument::default();
    if !args.listen.is_empty() {
        document.server.listen = args.listen.clone();
    }
    if let Some(value) = &args.base_path {
        document.server.base_path = value.clone();
    }
    if let Some(value) = &args.state_dir {
        document.server.state_dir = value.clone();
    }
    if let Some(value) = &args.certificate_file {
        document.tls.certificate_file = value.clone();
    }
    if let Some(value) = &args.private_key_file {
        document.tls.private_key_file = value.clone();
    }
    document.tls.client_ca_file = args.client_ca_file.clone();
    document.auth.mode = args.auth_mode.into_model();
    document.auth.required = !matches!(args.auth_mode, AuthModeArg::None);
    document.auth.principals.push(maskman_config::model::PrincipalConfig {
        id: args.principal_id.clone(),
        roles: vec!["default".into()],
        certificate_sha256: args.certificate_sha256.clone(),
    });
    let (token, token_config) = generate_token(&args.token_id, &args.principal_id, args.auth_mode)?;
    if let Some(token_config) = token_config {
        document.auth.bearer_tokens.push(token_config);
    }
    document.policy.roles.push(maskman_config::model::RoleConfig {
        name: "default".into(),
        capabilities: capabilities(args.enable_udp, args.enable_ip),
        allow_destinations: vec!["0.0.0.0/0".into(), "::/0".into()],
        deny_destinations: Vec::new(),
        deny_private: true,
        allowed_ip_protocols: vec!["*".into()],
        limits: maskman_config::model::LimitsConfig::default(),
    });
    document.proxy.udp.enabled = args.enable_udp;
    document.proxy.ip.enabled = args.enable_ip;
    document.proxy.ip.client_ipv4_pool = args.ipv4_pool.clone();
    document.proxy.ip.client_ipv6_pool = args.ipv6_pool.clone();
    document.proxy.ip.advertise_routes = args.advertise_routes.clone();
    document.proxy.ip.nat.mode = args.nat_mode.into_model();
    document.proxy.ip.nat.egress_interface = args.nat_interface.clone();
    Ok((document, token))
}

fn capabilities(enable_udp: bool, enable_ip: bool) -> Vec<String> {
    let mut capabilities = Vec::with_capacity(2);
    if enable_udp {
        capabilities.push("connect-udp".into());
    }
    if enable_ip {
        capabilities.push("connect-ip".into());
    }
    capabilities
}

fn generate_token(
    token_id: &str,
    principal: &str,
    mode: AuthModeArg,
) -> Result<(Option<String>, Option<maskman_config::model::BearerTokenConfig>)> {
    if token_id.is_empty()
        || !token_id.chars().all(|value| value.is_ascii_alphanumeric() || "-._".contains(value))
    {
        anyhow::bail!("token ID must contain only ASCII letters, numbers, '.', '_' or '-'");
    }
    if principal.is_empty()
        || !principal.chars().all(|value| value.is_ascii_alphanumeric() || "-._".contains(value))
    {
        anyhow::bail!("principal ID must contain only ASCII letters, numbers, '.', '_' or '-'");
    }
    if matches!(mode, AuthModeArg::None | AuthModeArg::Mtls) {
        return Ok((None, None));
    }
    let mut secret = [0u8; 32];
    OsRng.fill_bytes(&mut secret);
    let encoded = URL_SAFE_NO_PAD.encode(secret);
    let token = format!("mm_{token_id}_{encoded}");
    let digest = Sha256::digest(encoded.as_bytes());
    let secret_sha256 = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    Ok((
        Some(token),
        Some(maskman_config::model::BearerTokenConfig {
            id: token_id.into(),
            principal: principal.into(),
            secret_sha256,
            expires_at: None,
            enabled: true,
        }),
    ))
}

fn collect_interactive(args: &mut SetupArgs, config: Option<&Path>) -> Result<()> {
    if args.output.is_none() && config.is_none() {
        let default = format!("config.{}", args.format.extension());
        args.output = Some(PathBuf::from(prompt("Configuration path", &default)?));
    }
    if args.listen.is_empty() {
        args.listen.push(prompt("Listen address", "0.0.0.0:443")?);
    }
    if args.base_path.is_none() {
        args.base_path = Some(prompt("MASQUE base path", "/.well-known/masque")?);
    }
    args.development = confirm("Use development TLS placeholders?", true)?;
    if matches!(args.auth_mode, AuthModeArg::Mtls | AuthModeArg::BearerOrMtls) {
        if args.client_ca_file.is_none() {
            args.client_ca_file = Some(prompt("Client CA PEM path", "tls/client-ca.pem")?);
        }
        if args.certificate_sha256.is_empty() {
            let digest = prompt("Allowed client certificate SHA-256", "")?;
            if !digest.is_empty() {
                args.certificate_sha256.push(digest);
            }
        }
    }
    args.enable_udp = confirm("Enable CONNECT-UDP?", true)?;
    args.enable_ip = confirm("Enable CONNECT-IP?", false)?;
    if args.enable_ip && args.ipv4_pool.is_none() && args.ipv6_pool.is_none() {
        args.ipv4_pool = Some(prompt("IPv4 client pool", "100.96.0.0/11")?);
        args.ipv6_pool = Some(prompt("IPv6 client pool", "fd42:6d61:736b::/64")?);
    }
    Ok(())
}

fn prompt(label: &str, default: &str) -> Result<String> {
    print!("{label} [{default}]: ");
    io::stdout().flush().context("flushing setup prompt")?;
    let mut value = String::new();
    io::stdin().read_line(&mut value).context("reading setup prompt")?;
    let value = value.trim();
    Ok(if value.is_empty() { default.into() } else { value.into() })
}

fn confirm(label: &str, default: bool) -> Result<bool> {
    let suffix = if default { "Y/n" } else { "y/N" };
    print!("{label} [{suffix}]: ");
    io::stdout().flush().context("flushing setup confirmation")?;
    let mut value = String::new();
    io::stdin().read_line(&mut value).context("reading setup confirmation")?;
    match value.trim().to_ascii_lowercase().as_str() {
        "" => Ok(default),
        "y" | "yes" => Ok(true),
        "n" | "no" => Ok(false),
        _ => anyhow::bail!("answer y/yes or n/no to {label}"),
    }
}
