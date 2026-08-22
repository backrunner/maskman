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
