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
pub enum Command {
    Setup(SetupArgs),
    #[command(subcommand)]
    Config(ConfigCommand),
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
}

#[derive(Debug, Subcommand)]
pub enum ConfigCommand {
    Validate {
        #[arg(long)]
        check_system: bool,
    },
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
