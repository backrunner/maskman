mod auth;
mod completions;
mod config;
mod lifecycle;
mod setup;
mod update_service;

use anyhow::Result;

use crate::{
    cli::{Cli, Command},
    output::Output,
};

pub async fn run(cli: Cli, output: Output) -> Result<()> {
    match cli.command {
        Command::Setup(args) => setup::run(cli.config.as_deref(), args, output),
        Command::Config(command) => config::run(cli.config.as_deref(), command, output),
        Command::Auth(auth_command) => match auth_command {
            crate::cli::AuthCommand::Token(token_command) => {
                auth::run(cli.config.as_deref(), token_command, output).await
            }
        },
        Command::Completions(args) => {
            completions::run(args, output);
            Ok(())
        }
        Command::Serve => lifecycle::serve(cli.config.as_deref(), output).await,
        Command::Status(args) => lifecycle::status(cli.config.as_deref(), args, output).await,
        Command::Install(args) => lifecycle::action("install", cli.config.as_deref(), args, output),
        Command::Uninstall(args) => {
            lifecycle::action("uninstall", cli.config.as_deref(), args, output)
        }
        Command::Cleanup(args) => lifecycle::cleanup(cli.config.as_deref(), args, output).await,
        Command::Start(args) => lifecycle::action("start", cli.config.as_deref(), args, output),
        Command::Stop(args) => lifecycle::action("stop", cli.config.as_deref(), args, output),
        Command::Reload(args) => lifecycle::reload(cli.config.as_deref(), args, output).await,
        Command::Update(args) => lifecycle::update(cli.config.as_deref(), args, output),
        Command::Version => {
            println!("maskman {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Command::Worker => lifecycle::worker(cli.config.as_deref()).await,
    }
}

/// Print a copy-paste Surge MASQUE declaration for a freshly created bearer
/// token. The token secret is only available at creation time, so this is the
/// single convenient channel to capture the credentials Surge needs.
fn print_surge_credentials(document: &maskman_config::ConfigDocument, token: &str) {
    if let Some(line) = surge_credential_line(document, token) {
        println!("Surge (shown once): {line}");
        println!(
            "Development TLS: append `, skip-cert-verify=true` until a trusted certificate is deployed"
        );
    }
}

/// Render the Surge declaration, or `None` when the token does not match a
/// configured token id (which cannot happen for a token just written to
/// `document`).
fn surge_credential_line(document: &maskman_config::ConfigDocument, token: &str) -> Option<String> {
    let rest = token.strip_prefix("mm_")?;
    let (id, secret) = document.auth.bearer_tokens.iter().find_map(|value| {
        let suffix = rest.strip_prefix(value.id.as_str())?;
        suffix.strip_prefix('_').map(|secret| (value.id.as_str(), secret))
    })?;
    let listen = document.server.listen.first()?;
    let (host, port) = listen.rsplit_once(':')?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let host = match host {
        "" | "0.0.0.0" | "::" => "<server-address>",
        other => other,
    };
    Some(format!("maskman = masque, {host}, {port}, username={id}, password={secret}"))
}

#[cfg(test)]
mod tests {
    use super::surge_credential_line;

    fn document(listen: &str) -> maskman_config::ConfigDocument {
        let mut document = maskman_config::ConfigDocument::default();
        document.server.listen = vec![listen.into()];
        document.auth.bearer_tokens.push(maskman_config::model::BearerTokenConfig {
            id: "tok_ab".into(),
            principal: "client".into(),
            secret_sha256: String::new(),
            expires_at: None,
            enabled: true,
        });
        document
    }

    #[test]
    fn surge_line_renders_basic_credentials_with_wildcard_host() {
        let line = surge_credential_line(&document("0.0.0.0:443"), "mm_tok_ab_s3cr-et_x")
            .unwrap_or_else(|| panic!("surge line"));
        assert_eq!(
            line,
            "maskman = masque, <server-address>, 443, username=tok_ab, password=s3cr-et_x"
        );
    }

    #[test]
    fn surge_line_preserves_configured_host() {
        let line = surge_credential_line(&document("proxy.example.com:8443"), "mm_tok_ab_secret")
            .unwrap_or_else(|| panic!("surge line"));
        assert_eq!(
            line,
            "maskman = masque, proxy.example.com, 8443, username=tok_ab, password=secret"
        );
    }

    #[test]
    fn surge_line_rejects_unknown_token() {
        assert!(surge_credential_line(&document("0.0.0.0:443"), "mm_other_secret").is_none());
    }
}
