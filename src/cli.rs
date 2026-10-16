//! Argument parsing, the scrub and stats commands, and the one place that
//! turns a command error into exit code 1.

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Read, Write};
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use clap::{CommandFactory, Parser, Subcommand};
use serde_json::Value;

use crate::config::{self, Config, ConfigError, EngineConfig};
use crate::scrub::Scrubber;
use crate::{hook, init, stats, stream, verify};

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
    command: Option<CliCommand>,
}

#[derive(Subcommand)]
enum CliCommand {
    /// Scrub secrets from a hook payload (stdin -> stdout)
    Scrub {
        /// Scrub and print each line as it arrives, never reading stdin as a hook payload
        #[arg(long)]
        stream: bool,
        /// Also read the project config in DIR (stream mode only)
        #[arg(long, value_name = "DIR", requires = "stream")]
        cwd: Option<PathBuf>,
    },
    /// Check that redacted is installed and working
    Verify,
    /// Show how often each pattern has redacted secrets
    Stats,
    /// Learn secrets from a .env file and install the hook
    Init {
        /// Env file to learn from (skips the .env* search in this directory)
        #[arg(long = "env", value_name = "ENV")]
        env_file: Option<PathBuf>,
        /// Install to .claude/settings.local.json (this project only)
        #[arg(long)]
        local: bool,
    },
    /// Print the global config, or open it in the editor with --edit
    Config {
        /// Open ~/.config/redacted/config.yaml in $VISUAL, $EDITOR or vi, then check it
        #[arg(long)]
        edit: bool,
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
        Some(CliCommand::Scrub { stream: true, cwd }) => stream::run(cwd.as_deref()),
        Some(CliCommand::Scrub { .. }) => run_scrub(),
        Some(CliCommand::Verify) => verify::run(),
        Some(CliCommand::Stats) => show_stats(),
        Some(CliCommand::Init { env_file, local }) => init::run(env_file, local),
        Some(CliCommand::Uninstall { local }) => init::uninstall(local),
        Some(CliCommand::Config { edit: true }) => edit_global_config(),
        Some(CliCommand::Config { edit: false }) => show_global_config(),
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
fn run_scrub() -> Result<(), String> {
    let mut stdin_bytes = Vec::new();
    io::stdin()
        .read_to_end(&mut stdin_bytes)
        .map_err(|e| format!("scrub: read stdin: {e}"))?;
    let is_hook_payload = looks_like_hook_payload(&stdin_bytes);
    let payload: Value = serde_json::from_slice(&stdin_bytes).unwrap_or(Value::Null);
    // An absent or empty cwd reads no project config, not one under the process cwd.
    let cwd = payload
        .get("cwd")
        .and_then(Value::as_str)
        .filter(|c| !c.is_empty())
        .map(Path::new);
    let home_dir = config::home_dir();
    // as_deref() turns `Option<PathBuf>` into the borrowed `Option<&Path>`.
    let home_dir = home_dir.as_deref();
    let loaded = config::load(home_dir, cwd)
        .and_then(|config| Ok((config, config::load_engine(home_dir, cwd)?)));

    // Test mode: anything but a JSON object is scrubbed as raw text.
    if !is_hook_payload {
        let scrubber = loaded
            .map_err(String::from)
            .and_then(|(config, engine_config)| Scrubber::new(&config, &engine_config))
            .map_err(|e| format!("scrub: {e}"))?;
        scrub_raw_text(&stdin_bytes, &scrubber);
        return Ok(());
    }
    respond_to_hook(&stdin_bytes, &payload, home_dir, loaded);
    Ok(())
}

/// Writes the hook's answer to stdout: nothing for clean output, else the block
/// or withheld envelope.
fn respond_to_hook(
    stdin_bytes: &[u8],
    payload: &Value,
    home_dir: Option<&Path>,
    loaded: Result<(Config, EngineConfig), ConfigError>,
) {
    // A config that does not parse withholds before it can skip a tool or add the v1 notice.
    // The model reads the reason, so it names the file only; the serde message, which
    // can quote the file, goes to stderr.
    let (config, engine_config) = match loaded {
        Ok(loaded) => loaded,
        Err(error) => {
            eprintln!("{error}");
            let notice = format!(
                "[redacted] config file does not parse: {}; run redacted verify",
                error.path.display()
            );
            let out = hook::prepend_reason(&hook::withheld_output(stdin_bytes), &notice);
            let _ = io::stdout().write_all(&out);
            return;
        }
    };
    let scrubber = Scrubber::new(&config, &engine_config);

    // Only a well-formed non-Bash name skips; anything else goes on to fail closed.
    let is_named_non_bash_tool =
        matches!(payload.get("tool_name"), Some(Value::String(tool)) if tool != "Bash");
    if config.ignore_internal_tools && is_named_non_bash_tool {
        return;
    }
    let (mut out, counts_by_pattern) = match scrubber {
        Ok(scrubber) => hook::scrub_payload_or_withhold(stdin_bytes, &|text| scrubber.scrub(text)),
        Err(_) => (hook::withheld_output(stdin_bytes), BTreeMap::new()),
    };
    record_stats(&payload_string(payload, "tool_name"), &counts_by_pattern);
    // A global config without `version` is a Go 0.7 install that has no learned secrets.
    let is_pre_v2_config = config.version == 0
        && home_dir.is_some_and(|home| config::global_config_path(home).exists());
    if is_pre_v2_config
        && !out.is_empty()
        && mark_session_notified(&payload_string(payload, "session_id"))
    {
        out = hook::prepend_reason(&out, PRE_V2_NOTICE);
    }
    let _ = io::stdout().write_all(&out);
}

/// The string at `key`, or "" when it is absent or not a string.
fn payload_string(payload: &Value, key: &str) -> String {
    payload
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string()
}

/// Prints the scrubbed text, and the redaction count on stderr, for a person testing by hand.
fn scrub_raw_text(data: &[u8], scrubber: &Scrubber) {
    let result = scrubber.scrub(&String::from_utf8_lossy(data));
    let _ = io::stdout().write_all(result.text.as_bytes());
    if result.has_redactions() {
        eprintln!("[redacted] {} secret(s) scrubbed", result.count);
    }
}

const PRE_V2_NOTICE: &str = "[redacted] config is v1: run `redacted init` to learn your secrets.";

/// Stamps `session` in a file next to the stats file; true if it was not there yet.
/// A missing or unreadable file means notify.
fn mark_session_notified(session: &str) -> bool {
    let Some(path) = stats::file_path().map(|p| p.with_file_name("notified.txt")) else {
        return true;
    };
    let notified_sessions = fs::read_to_string(&path).unwrap_or_default();
    if notified_sessions.lines().any(|line| line == session) {
        return false;
    }
    let opened = fs::OpenOptions::new().append(true).create(true).open(&path);
    if let Ok(mut file) = opened {
        let _ = writeln!(file, "{session}");
    }
    true
}

fn record_stats(tool: &str, counts_by_pattern: &BTreeMap<String, usize>) {
    if let Some(path) = stats::file_path() {
        stats::record(&path, tool, counts_by_pattern);
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

/// Prints the global config as written, comments included.
fn show_global_config() -> Result<(), String> {
    let home_dir = config::home_dir().ok_or("config: cannot determine home directory")?;
    let path = config::global_config_path(&home_dir);
    let shown = path.display();
    let text = match fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return Err(format!("config: no file at {shown}; run redacted init"));
        }
        Err(e) => return Err(format!("config: {shown}: {e}")),
    };
    print!("{text}");
    Ok(())
}

/// Opens the global config in the user's editor, then compiles its patterns, so a
/// broken edit shows now instead of withholding the next hook output.
fn edit_global_config() -> Result<(), String> {
    let home_dir = config::home_dir().ok_or("config: cannot determine home directory")?;
    let path = config::global_config_path(&home_dir);
    let shown = path.display();
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).map_err(|e| format!("config: create {}: {e}", dir.display()))?;
    }
    // Append mode creates a missing file and leaves an existing one untouched.
    let mut options = fs::OpenOptions::new();
    options.append(true).create(true);
    #[cfg(unix)]
    options.mode(0o600);
    options
        .open(&path)
        .map_err(|e| format!("config: create {shown}: {e}"))?;

    // VISUAL is the full-screen editor, EDITOR the older fallback, vi is on every Unix.
    let editor = ["VISUAL", "EDITOR"]
        .iter()
        .filter_map(|name| std::env::var(name).ok())
        .find(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "vi".to_string());
    // "code --wait" is a program plus its flags.
    let mut words = editor.split_whitespace();
    let program = words.next().unwrap_or("vi");
    Command::new(program)
        .args(words)
        .arg(&path)
        .status()
        .map_err(|e| format!("config: cannot start editor {editor}: {e}"))?;
    // An editor that saves through a new file drops the mode; the file holds secret hashes.
    #[cfg(unix)]
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("config: restore mode 0600 on {shown}: {e}"))?;

    // The hook skips a file that does not parse, dropping learned secrets without a word.
    let cwd = std::env::current_dir().ok();
    let config =
        config::load(Some(&home_dir), cwd.as_deref()).map_err(|e| format!("config: {e}"))?;
    let engine_config =
        config::load_engine(Some(&home_dir), cwd.as_deref()).map_err(|e| format!("config: {e}"))?;
    verify::compile_patterns(&config, &engine_config).map_err(|e| format!("patterns load: {e}"))?;
    println!("patterns load: PASS");
    Ok(())
}

fn show_stats() -> Result<(), String> {
    let path = stats::file_path().ok_or("stats: cannot determine home directory".to_string())?;
    let summary = stats::aggregate(&path).map_err(|e| format!("stats: {e}"))?;
    print!("{}", stats::render(&summary));
    Ok(())
}
