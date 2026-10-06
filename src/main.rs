mod cli;
mod config;
#[cfg(test)]
mod fake;
mod hook;
mod init;
mod scrub;
mod settings;
mod stats;

use std::process::ExitCode;

fn main() -> ExitCode {
    cli::run()
}
