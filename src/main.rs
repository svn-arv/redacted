//! redacted: a Claude Code hook that scrubs secrets from tool output.
//! This file lists the modules and hands the exit code back to the OS.

mod cli;
mod config;
#[cfg(test)]
mod fake_secrets;
mod hook;
mod init;
mod scrub;
mod settings;
mod stats;
mod verify;

use std::process::ExitCode;

fn main() -> ExitCode {
    cli::run()
}
