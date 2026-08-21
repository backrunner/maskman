#![forbid(unsafe_code)]

mod benchmark;
mod compliance;

use std::{path::PathBuf, process::ExitCode};

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
            let mut iterations = 100_000;
            let mut payloads = None;
            let mut profiles = "mixed".to_owned();
            let mut output = None;
            while let Some(argument) = arguments.next() {
                let (flag, inline_value) = argument
                    .split_once('=')
                    .map_or((argument.as_str(), None), |(flag, value)| (flag, Some(value)));
                match flag {
                    "--iterations" => {
                        iterations = inline_value
                            .map(str::to_owned)
                            .or_else(|| arguments.next())
                            .ok_or_else(|| {
                                "benchmark requires a value after --iterations".to_owned()
                            })?
                            .parse::<u64>()
                            .map_err(|_| "benchmark iterations must be an integer".to_owned())?;
                    }
                    "--payloads" => {
                        payloads = Some(
                            inline_value
                                .map(str::to_owned)
                                .or_else(|| arguments.next())
                                .ok_or_else(|| {
                                    "benchmark requires a value after --payloads".to_owned()
                                })?,
                        );
                    }
                    "--profiles" | "--profile" => {
                        profiles = inline_value
                            .map(str::to_owned)
                            .or_else(|| arguments.next())
                            .ok_or_else(|| {
                                "benchmark requires a value after --profiles".to_owned()
                            })?;
                    }
                    "--output" => {
                        output = Some(PathBuf::from(
                            inline_value
                                .map(str::to_owned)
                                .or_else(|| arguments.next())
                                .ok_or_else(|| {
                                    "benchmark requires a value after --output".to_owned()
                                })?,
                        ));
                    }
                    _ => return Err(benchmark_usage().into()),
                }
            }
            benchmark::run(iterations, payloads.as_deref(), &profiles, output.as_deref())
        }
        _ => Err("usage: cargo xtask <compliance|benchmark>".into()),
    }
}

fn benchmark_usage() -> &'static str {
    "usage: cargo xtask benchmark [--iterations N] [--profiles http,video,mixed] [--payloads B[,B...]] [--output FILE]"
}
