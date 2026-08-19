use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

#[derive(Debug, Parser)]
#[command(name = "maskman", version, about = "High-performance MASQUE proxy daemon")]
pub struct Cli {
    #[arg(long, global = true, env = "MASKMAN_CONFIG")]
    pub config: Option<PathBuf>,
    #[arg(long, global = true, value_enum, default_value_t = ColorChoice::Auto)]
    pub color: ColorChoice,
    #[arg(short, long, global = true)]
    pub verbose: bool,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum ColorChoice {
    Auto,
    Always,
    Never,
}

#[derive(Debug, Subcommand)]
#[allow(clippy::large_enum_variant)]
pub enum Command {
    Setup(SetupArgs),
    #[command(subcommand)]
    Config(ConfigCommand),
    #[command(subcommand)]
    Auth(AuthCommand),
    Completions(CompletionsArgs),
    Serve,
    Status(StatusArgs),
    Install(ActionArgs),
    Uninstall(ActionArgs),
    Cleanup(ActionArgs),
    Start(ActionArgs),
    Stop(ActionArgs),
    Reload(ActionArgs),
    Update(UpdateArgs),
    Version,
}

#[derive(Debug, Args)]
pub struct SetupArgs {
    #[arg(long, value_enum, default_value_t = ConfigFormatArg::Toml)]
    pub format: ConfigFormatArg,
    #[arg(long)]
    pub output: Option<PathBuf>,
    #[arg(long)]
    pub non_interactive: bool,
    #[arg(long)]
    pub development: bool,
    #[arg(long)]
    pub yes: bool,
    #[arg(long = "listen", value_name = "ADDR")]
    pub listen: Vec<String>,
    #[arg(long)]
    pub base_path: Option<String>,
    #[arg(long)]
    pub state_dir: Option<String>,
    #[arg(long)]
    pub certificate_file: Option<String>,
    #[arg(long)]
    pub private_key_file: Option<String>,
    #[arg(long)]
    pub client_ca_file: Option<String>,
    #[arg(long = "certificate-sha256", value_name = "HEX")]
    pub certificate_sha256: Vec<String>,
    #[arg(long, value_enum, default_value_t = AuthModeArg::Bearer)]
    pub auth_mode: AuthModeArg,
    #[arg(long, default_value = "admin")]
    pub principal_id: String,
    #[arg(long, default_value = "tok_initial")]
    pub token_id: String,
    #[arg(long)]
    pub enable_udp: bool,
    #[arg(long)]
    pub enable_ip: bool,
    #[arg(long)]
    pub ipv4_pool: Option<String>,
    #[arg(long)]
    pub ipv6_pool: Option<String>,
    #[arg(long = "advertise-route", value_name = "CIDR")]
    pub advertise_routes: Vec<String>,
    #[arg(long, value_enum, default_value_t = NatModeArg::Disabled)]
    pub nat_mode: NatModeArg,
}

#[derive(Debug, Subcommand)]
pub enum ConfigCommand {
    Validate {
        #[arg(long)]
        check_system: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum AuthCommand {
    #[command(subcommand)]
    Token(TokenCommand),
}

#[derive(Debug, Subcommand)]
pub enum TokenCommand {
    Create(TokenCreateArgs),
    Revoke(TokenRevokeArgs),
    List(TokenListArgs),
}

#[derive(Debug, Args)]
pub struct TokenCreateArgs {
    #[arg(long)]
    pub id: Option<String>,
    #[arg(long)]
    pub principal: Option<String>,
    #[arg(long)]
    pub expires_at: Option<String>,
    #[arg(long)]
    pub yes: bool,
    #[arg(long)]
    pub reload: bool,
}

#[derive(Debug, Args)]
pub struct TokenRevokeArgs {
    pub id: String,
    #[arg(long)]
    pub yes: bool,
    #[arg(long)]
    pub reload: bool,
}

#[derive(Debug, Args)]
pub struct TokenListArgs {
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct CompletionsArgs {
    #[arg(value_enum)]
    pub shell: clap_complete::Shell,
}

#[derive(Debug, Args)]
pub struct StatusArgs {
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct ActionArgs {
    #[arg(long)]
    pub yes: bool,
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Debug, Args)]
pub struct UpdateArgs {
    #[arg(long)]
    pub check: bool,
    #[arg(long)]
    pub yes: bool,
    #[arg(long)]
    pub version: Option<String>,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum ConfigFormatArg {
    Toml,
    Json,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum AuthModeArg {
    Bearer,
    Mtls,
    #[value(name = "bearer-or-mtls")]
    BearerOrMtls,
    None,
}

impl AuthModeArg {
    pub fn into_model(self) -> maskman_config::AuthMode {
        match self {
            Self::Bearer => maskman_config::AuthMode::Bearer,
            Self::Mtls => maskman_config::AuthMode::Mtls,
            Self::BearerOrMtls => maskman_config::AuthMode::BearerOrMtls,
            Self::None => maskman_config::AuthMode::None,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum NatModeArg {
    Disabled,
    Managed,
}

impl NatModeArg {
    pub fn into_model(self) -> maskman_config::model::NatMode {
        match self {
            Self::Disabled => maskman_config::model::NatMode::Disabled,
            Self::Managed => maskman_config::model::NatMode::Managed,
        }
    }
}

impl ConfigFormatArg {
    pub fn extension(self) -> &'static str {
        match self {
            Self::Toml => "toml",
            Self::Json => "json",
        }
    }

    pub fn into_format(self) -> maskman_config::ConfigFormat {
        match self {
            Self::Toml => maskman_config::ConfigFormat::Toml,
            Self::Json => maskman_config::ConfigFormat::Json,
        }
    }
}
