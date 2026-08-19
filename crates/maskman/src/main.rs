mod cli;
mod command;
mod output;

use anyhow::Result;
use clap::Parser;

fn main() -> Result<()> {
    let cli = cli::Cli::parse();
    let output = output::Output::new(cli.color, cli.verbose);
    command::run(cli, output)
}
