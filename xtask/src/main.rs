#![forbid(unsafe_code)]

mod benchmark;
mod compliance;

use std::process::ExitCode;

fn main() -> ExitCode {
    match command() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

fn command() -> Result<(), String> {
    let mut arguments = std::env::args().skip(1);
    match arguments.next().as_deref() {
        Some("compliance") => {
            let check_only = arguments.next().as_deref() == Some("--check-only");
            if arguments.next().is_some() {
                return Err("usage: cargo xtask compliance [--check-only]".into());
            }
            compliance::run(check_only).map_err(|error| error.to_string())
        }
        Some("benchmark") => {
            let iterations = match arguments.next().as_deref() {
                None => 100_000,
                Some("--iterations") => arguments
                    .next()
                    .ok_or_else(|| "benchmark requires a value after --iterations".to_owned())?
                    .parse::<u64>()
                    .map_err(|_| "benchmark iterations must be an integer".to_owned())?,
                Some(value) if value.starts_with("--iterations=") => value[13..]
                    .parse::<u64>()
                    .map_err(|_| "benchmark iterations must be an integer".to_owned())?,
                Some(_) => return Err("usage: cargo xtask benchmark [--iterations N]".into()),
            };
            if arguments.next().is_some() {
                return Err("usage: cargo xtask benchmark [--iterations N]".into());
            }
            benchmark::run(iterations)
        }
        _ => Err("usage: cargo xtask <compliance|benchmark>".into()),
    }
}
