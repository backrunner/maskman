mod config;
mod lifecycle;
mod setup;

use anyhow::Result;

use crate::{
    cli::{Cli, Command},
    output::Output,
};

pub async fn run(cli: Cli, output: Output) -> Result<()> {
    match cli.command {
        Command::Setup(args) => setup::run(cli.config.as_deref(), args, output),
        Command::Config(command) => config::run(cli.config.as_deref(), command, output),
        Command::Serve => lifecycle::serve(cli.config.as_deref(), output).await,
        Command::Status(args) => lifecycle::status(cli.config.as_deref(), args, output),
        Command::Install(args) => lifecycle::action("install", cli.config.as_deref(), args, output),
        Command::Uninstall(args) => {
            lifecycle::action("uninstall", cli.config.as_deref(), args, output)
        }
        Command::Cleanup(args) => lifecycle::cleanup(cli.config.as_deref(), args, output).await,
        Command::Start(args) => lifecycle::action("start", cli.config.as_deref(), args, output),
        Command::Stop(args) => lifecycle::action("stop", cli.config.as_deref(), args, output),
        Command::Reload(args) => lifecycle::action("reload", cli.config.as_deref(), args, output),
        Command::Update(args) => lifecycle::update(args, output),
        Command::Version => {
            println!("maskman {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
    }
}
