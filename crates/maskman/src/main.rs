mod cli;
mod command;
mod exit;
mod output;

use clap::Parser;

#[tokio::main]
async fn main() {
    let cli = cli::Cli::parse();
    let output = output::Output::new(cli.color, cli.verbose);
    if let Err(error) = command::run(cli, output).await {
        eprintln!("error: {error:#}");
        std::process::exit(exit::code(&error));
    }
}
