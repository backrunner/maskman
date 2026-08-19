use std::io::IsTerminal;

use crate::cli::ColorChoice;

#[derive(Debug, Clone, Copy)]
pub struct Output {
    color: bool,
    verbose: bool,
}

impl Output {
    pub fn new(choice: ColorChoice, verbose: bool) -> Self {
        let color = match choice {
            ColorChoice::Always => true,
            ColorChoice::Never => false,
            ColorChoice::Auto => {
                std::env::var_os("NO_COLOR").is_none()
                    && std::io::stdout().is_terminal()
                    && std::env::var("TERM").map_or(true, |term| term != "dumb")
            }
        };
        Self { color, verbose }
    }

    pub fn success(&self, message: impl AsRef<str>) {
        if self.color {
            println!("\x1b[32mOK\x1b[0m {}", message.as_ref());
        } else {
            println!("OK {}", message.as_ref());
        }
    }

    pub fn warning(&self, message: impl AsRef<str>) {
        if self.color {
            eprintln!("\x1b[33mWARN\x1b[0m {}", message.as_ref());
        } else {
            eprintln!("WARN {}", message.as_ref());
        }
    }

    pub fn info(&self, message: impl AsRef<str>) {
        if self.verbose {
            println!("{}", message.as_ref());
        }
    }
}
