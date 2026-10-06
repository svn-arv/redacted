//! Argument parsing, the scrub and stats commands, and the one place that
//! turns a command error into exit code 1.

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{CommandFactory, Parser, Subcommand};
use serde_json::Value;

use crate::config;
use crate::scrub::Scrubber;
use crate::{hook, init, stats, verify};

#[derive(Parser)]
#[command(
    name = "redacted",
    about = "A hook that redacts secrets from tool output before your AI assistant sees them",
    disable_version_flag = true
)]
struct Cli {
    /// Print the version
    #[arg(long)]
    version: bool,
    #[command(subcommand)]
    command: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Scrub secrets from a hook payload (stdin -> stdout)
    Scrub,
    /// Check that redacted is installed and working
    Verify,
    /// Show how often each pattern has redacted secrets
    Stats,
    /// Learn secrets from a .env file and install the hook
    Init {
        /// Env file to learn from (skips the .env* search in this directory)
        #[arg(long)]
        env: Option<PathBuf>,
        /// Install to .claude/settings.local.json (this project only)
        #[arg(long)]
        local: bool,
    },
    /// Remove the redacted hook from Claude Code settings (keeps the config)
    Uninstall {
        /// Remove from .claude/settings.local.json only
        #[arg(long)]
        local: bool,
    },
}

/// Runs the CLI. Commands return `Err(message)` on failure; this is the one
/// place that prints it and turns it into exit code 1.
pub fn run() -> ExitCode {
    let cli = Cli::parse();
    if cli.version {
        println!("redacted version {}", env!("CARGO_PKG_VERSION"));
        return ExitCode::SUCCESS;
    }
    let result = match cli.command {
        Some(Cmd::Scrub) => scrub(),
        Some(Cmd::Verify) => verify::run(),
        Some(Cmd::Stats) => show_stats(),
        Some(Cmd::Init { env, local }) => init::run(env, local),
        Some(Cmd::Uninstall { local }) => init::uninstall(local),
        None => {
            let _ = Cli::command().print_help();
            Ok(())
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("{message}");
            ExitCode::FAILURE
        }
    }
}

/// Once stdin is read, hook mode always succeeds, so Claude Code never sees a
/// failed hook; only raw-text mode, run by hand, can still fail.
fn scrub() -> Result<(), String> {
    let mut data = Vec::new();
    io::stdin()
        .read_to_end(&mut data)
        .map_err(|e| format!("scrub: read stdin: {e}"))?;
    let payload_mode = looks_like_hook_payload(&data);
    let header: Value = serde_json::from_slice(&data).unwrap_or(Value::Null);
    let field = |k: &str| {
        header
            .get(k)
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string()
    };
    let cwd = field("cwd");
    let home_dir = config::home();
    let cfg = config::load(home_dir.as_deref(), &cwd);
    let scrubber = Scrubber::new(&cfg, &config::load_engine(home_dir.as_deref(), &cwd));

    // Test mode: anything but a JSON object is scrubbed as raw text.
    if !payload_mode {
        let scrubber = scrubber.map_err(|e| format!("scrub: {e}"))?;
        scrub_raw_text(&data, &scrubber);
        return Ok(());
    }

    // Only a well-formed non-Bash name skips; anything else goes on to fail closed.
    let named_non_bash = matches!(header.get("tool_name"), Some(Value::String(t)) if t != "Bash");
    if cfg.ignore_internal_tools && named_non_bash {
        return Ok(());
    }
    let (mut out, by_pattern) = match scrubber {
        Ok(s) => hook::process_safely(&data, &|t| s.scrub(t)),
        Err(_) => (hook::withheld(), BTreeMap::new()),
    };
    record(&field("tool_name"), &by_pattern);
    // A global config without `version` is a Go 0.7 install that has no learned secrets.
    let is_pre_v2_config = cfg.version == 0
        && home_dir
            .as_deref()
            .is_some_and(|home| config::global_path(home).exists());
    if is_pre_v2_config && !out.is_empty() && first_notice(&field("session_id")) {
        out = hook::prepend_reason(&out, PRE_V2_NOTICE);
    }
    let _ = io::stdout().write_all(&out);
    Ok(())
}

/// Prints the scrubbed text, and the hit count on stderr, for a person testing by hand.
fn scrub_raw_text(data: &[u8], scrubber: &Scrubber) {
    let result = scrubber.scrub(&String::from_utf8_lossy(data));
    let _ = io::stdout().write_all(result.text.as_bytes());
    if result.redacted() {
        eprintln!("[redacted] {} secret(s) scrubbed", result.count);
    }
}

const PRE_V2_NOTICE: &str = "[redacted] config is v1: run `redacted init` to learn your secrets.";

/// Stamps `session` in a file next to the stats file; true if it was not there yet.
/// A missing or unreadable file means notify.
fn first_notice(session: &str) -> bool {
    let Some(path) = stats::file_path().map(|p| p.with_file_name("notified.txt")) else {
        return true;
    };
    let seen = fs::read_to_string(&path).unwrap_or_default();
    if seen.lines().any(|l| l == session) {
        return false;
    }
    let file = fs::OpenOptions::new().append(true).create(true).open(&path);
    if let Ok(mut f) = file {
        let _ = writeln!(f, "{session}");
    }
    true
}

fn record(tool: &str, by_pattern: &BTreeMap<String, usize>) {
    if let Some(path) = stats::file_path() {
        stats::record(&path, tool, by_pattern);
    }
}

/// A JSON object is the shape of every hook payload. A leading `{` alone is not
/// enough: Ruby/PHP hash literals start with it too.
fn looks_like_hook_payload(data: &[u8]) -> bool {
    // Not `trim_ascii_start`: it also strips form feed, which JSON does not allow as
    // whitespace, so a payload starting with `\x0C` would wrongly switch to hook mode.
    let start = data
        .iter()
        .position(|c| !matches!(c, b' ' | b'\t' | b'\r' | b'\n'))
        .unwrap_or(data.len());
    let trimmed = &data[start..];
    if trimmed.first() != Some(&b'{') {
        return false;
    }
    // Go has no depth limit, so a too-deep payload is still a payload (and fails closed).
    match serde_json::from_slice::<serde::de::IgnoredAny>(trimmed) {
        Ok(_) => true,
        Err(e) => e.to_string().starts_with("recursion limit exceeded"),
    }
}

fn show_stats() -> Result<(), String> {
    let path = stats::file_path().ok_or("stats: cannot determine home directory".to_string())?;
    let summary = stats::aggregate(&path).map_err(|e| format!("stats: {e}"))?;
    print!("{}", stats::render(&summary));
    Ok(())
}
