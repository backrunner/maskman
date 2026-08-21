#![forbid(unsafe_code)]

mod cli;
mod command;
mod exit;
mod output;

use clap::Parser;

fn main() {
    let cli = cli::Cli::parse();
    let output = output::Output::new(cli.color, cli.verbose);
    let supervisor = std::env::var("MASKMAN_ROLE").as_deref() == Ok("supervisor");
    let mut runtime = if supervisor {
        tokio::runtime::Builder::new_current_thread()
    } else {
        tokio::runtime::Builder::new_multi_thread()
    };
    let runtime = match runtime.enable_all().build() {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("error: failed to build Tokio runtime: {error}");
            std::process::exit(6);
        }
    };
    if let Err(error) = runtime.block_on(command::run(cli, output)) {
        eprintln!("error: {error:#}");
        std::process::exit(exit::code(&error));
    }
}
