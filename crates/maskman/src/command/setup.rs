use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};

use crate::{cli::SetupArgs, output::Output};

pub fn run(config: Option<&Path>, args: SetupArgs, output: Output) -> Result<()> {
    let output_path = args
        .output
        .or_else(|| config.map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from(format!("config.{}", args.format.extension())));
    match output_path.extension().and_then(|value| value.to_str()) {
        Some(extension) if extension == args.format.extension() => {}
        Some(_extension) => anyhow::bail!(
            "output {} does not match --format {}; choose a .{} path or change --format",
            output_path.display(),
            args.format.extension(),
            args.format.extension()
        ),
        None => anyhow::bail!(
            "output {} must end in .{}",
            output_path.display(),
            args.format.extension()
        ),
    }
    if output_path.exists() && !args.yes {
        if args.non_interactive {
            anyhow::bail!(
                "{} already exists in non-interactive mode; pass --yes to replace it",
                output_path.display()
            );
        }
        anyhow::bail!("{} already exists; pass --yes to replace it", output_path.display());
    }
    let mut document = maskman_config::ConfigDocument::default();
    if !args.development {
        document.tls.certificate_file = "tls/fullchain.pem".into();
        document.tls.private_key_file = "tls/private-key.pem".into();
    }
    let mut secret = [0u8; 32];
    OsRng.fill_bytes(&mut secret);
    let token_secret = URL_SAFE_NO_PAD.encode(secret);
    let token_id = "tok_initial";
    let token_value = format!("mm_{token_id}_{token_secret}");
    let digest = Sha256::digest(token_secret.as_bytes());
    let digest_hex = digest.iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    document.auth.principals.push(maskman_config::model::PrincipalConfig {
        id: "admin".into(),
        roles: vec!["default".into()],
        certificate_sha256: Vec::new(),
    });
    document.auth.bearer_tokens.push(maskman_config::model::BearerTokenConfig {
        id: token_id.into(),
        principal: "admin".into(),
        secret_sha256: digest_hex,
        expires_at: None,
        enabled: true,
    });
    document.policy.roles.push(maskman_config::model::RoleConfig {
        name: "default".into(),
        capabilities: vec!["connect-udp".into(), "connect-ip".into()],
        allow_destinations: vec!["0.0.0.0/0".into(), "::/0".into()],
        deny_destinations: Vec::new(),
        deny_private: true,
        allowed_ip_protocols: vec!["*".into()],
        limits: maskman_config::model::LimitsConfig::default(),
    });
    maskman_config::validate(&document).context("validating generated configuration")?;
    write_config(&output_path, &document, args.format.into_format())?;
    output.success(format!("wrote {}", output_path.display()));
    println!("Bearer token (shown once): {token_value}");
    if !args.development {
        output.warning("TLS files are placeholders; provide certificate_file and private_key_file before serving");
    }
    Ok(())
}

fn write_config(
    path: &Path,
    document: &maskman_config::ConfigDocument,
    format: maskman_config::ConfigFormat,
) -> Result<()> {
    let parent = path.parent().filter(|parent| !parent.as_os_str().is_empty());
    if let Some(parent) = parent {
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }
    let rendered = maskman_config::render(document, format)?;
    let file_name = path.file_name().and_then(|value| value.to_str()).unwrap_or("config");
    let temporary = path.with_file_name(format!(".{file_name}.tmp-{}", std::process::id()));
    let mut file = fs::File::create(&temporary)
        .with_context(|| format!("creating {}", temporary.display()))?;
    file.write_all(rendered.as_bytes())?;
    file.sync_all()?;
    fs::rename(&temporary, path).with_context(|| format!("installing {}", path.display()))?;
    Ok(())
}
