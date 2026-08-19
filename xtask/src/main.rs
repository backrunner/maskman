#![forbid(unsafe_code)]

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

fn command() -> Result<(), compliance::ComplianceError> {
    let mut arguments = std::env::args().skip(1);
    match arguments.next().as_deref() {
        Some("compliance") => {
            let check_only = arguments.next().as_deref() == Some("--check-only");
            if arguments.next().is_some() {
                return Err(compliance::ComplianceError::Usage);
            }
            compliance::run(check_only)
        }
        _ => Err(compliance::ComplianceError::Usage),
    }
}
