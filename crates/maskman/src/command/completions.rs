use std::io;

use clap::CommandFactory;
use clap_complete::generate;

use crate::{
    cli::{Cli, CompletionsArgs},
    output::Output,
};

pub fn run(args: CompletionsArgs, _output: Output) {
    let mut command = Cli::command();
    generate(args.shell, &mut command, "maskman", &mut io::stdout());
}
