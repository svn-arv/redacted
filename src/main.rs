//! redacted: a Claude Code hook that scrubs secrets from tool output.
//! This file lists the modules and hands the exit code back to the OS.

mod cli;
mod config;
mod hook;
mod init;
mod opencode;
mod pre_hook;
mod settings;
mod stats;
mod stream;
mod verify;

use std::process::ExitCode;

fn main() -> ExitCode {
    cli::run()
}
