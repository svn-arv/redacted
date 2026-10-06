//! Commands: scrub, verify, stats, init, uninstall.

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{CommandFactory, Parser, Subcommand};
use serde_json::Value;

use crate::config::{self, Config, EngineConfig};
use crate::scrub::Scrubber;
use crate::{hook, init, settings, stats};

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
        Some(Cmd::Verify) => verify(),
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

fn home() -> String {
    std::env::var("HOME").unwrap_or_default()
}

/// Hook mode always succeeds, so Claude Code never sees a failed hook; only
/// raw-text mode, run by hand, can fail.
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
    let cfg = config::load(&home(), &cwd);
    let scrubber = Scrubber::new(&cfg, &config::load_engine(&home(), &cwd));

    // Test mode: anything but a JSON object is scrubbed as raw text.
    if !payload_mode {
        let scrubber = scrubber.map_err(|e| format!("scrub: {e}"))?;
        let result = scrubber.scrub(&String::from_utf8_lossy(&data));
        let _ = io::stdout().write_all(result.text.as_bytes());
        if result.redacted() {
            eprintln!("[redacted] {} secret(s) scrubbed", result.count);
        }
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
        && Path::new(&home())
            .join(".config/redacted/config.yaml")
            .exists();
    if is_pre_v2_config && !out.is_empty() && first_notice(&field("session_id")) {
        out = hook::prepend_reason(&out, PRE_V2_NOTICE);
    }
    let _ = io::stdout().write_all(&out);
    Ok(())
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

#[derive(Clone, Copy, PartialEq)]
enum Status {
    Pass,
    Fail,
    Skip,
    Warn,
}

struct Check {
    name: &'static str,
    status: Status,
    detail: String,
}

/// `impl Into<String>` takes a `&str` or a `String`, so callers skip `.to_string()`.
fn check(name: &'static str, status: Status, detail: impl Into<String>) -> Check {
    Check {
        name,
        status,
        detail: detail.into(),
    }
}

fn verify() -> Result<(), String> {
    let cwd = std::env::current_dir()
        .map(|p| p.display().to_string())
        .unwrap_or_default();
    let mut checks = vec![check_binary()];
    checks.extend(check_hooks(&cwd));
    checks.push(check_config(&cwd));
    checks.push(check_patterns(&cwd));
    checks.push(check_scrub());
    checks.extend(check_learned(&cwd));

    let (mut passed, mut failed) = (0, 0);
    for c in &checks {
        let tag = match c.status {
            Status::Pass => {
                passed += 1;
                "PASS"
            }
            Status::Fail => {
                failed += 1;
                "FAIL"
            }
            Status::Skip => "SKIP",
            Status::Warn => "WARN",
        };
        if c.detail.is_empty() {
            println!("  [{tag}] {}", c.name);
        } else {
            println!("  [{tag}] {} - {}", c.name, c.detail);
        }
    }
    println!("\n{passed} passed, {failed} failed");
    if failed > 0 {
        return Err(format!("Error: {failed} check(s) failed"));
    }
    Ok(())
}

fn check_binary() -> Check {
    match std::env::current_exe() {
        Ok(p) => check("binary in PATH", Status::Pass, p.display().to_string()),
        Err(_) => check(
            "binary in PATH",
            Status::Fail,
            "not found, reinstall redacted",
        ),
    }
}

fn check_hooks(cwd: &str) -> Vec<Check> {
    let global_path = Path::new(&home()).join(".claude/settings.json");
    let local_path = Path::new(cwd).join(".claude/settings.local.json");
    let mut global = check_settings_file(&global_path, "global hook");
    let mut local = check_settings_file(&local_path, "local hook");

    // One registration is enough; the missing other is a skip, not a failure.
    if global.status == Status::Pass && local.status == Status::Fail {
        local.status = Status::Skip;
    }
    if local.status == Status::Pass && global.status == Status::Fail {
        global.status = Status::Skip;
    }
    let none = global.status != Status::Pass && local.status != Status::Pass;
    let mut out = vec![global, local];
    if none {
        out.push(check(
            "hook registered",
            Status::Fail,
            "not found in either settings file, run: redacted init",
        ));
    }
    out
}

fn check_settings_file(path: &Path, label: &'static str) -> Check {
    let shown = path.display();
    let data = match fs::read(path) {
        Ok(d) => d,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return check(label, Status::Fail, format!("file not found: {shown}"))
        }
        Err(e) => return check(label, Status::Fail, format!("cannot read {shown}: {e}")),
    };
    let settings: Value = match serde_json::from_slice(&data) {
        Ok(s) => s,
        Err(e) => {
            return check(
                label,
                Status::Fail,
                format!("{shown} contains invalid JSON: {e}"),
            )
        }
    };
    if settings::post_tool_use(&settings).is_empty() {
        return check(
            label,
            Status::Fail,
            format!("no PostToolUse hooks in {shown}, run: redacted init"),
        );
    }
    let Some(entry) = settings::find_ours(&settings) else {
        return check(
            label,
            Status::Fail,
            "PostToolUse exists but has no redacted entry, run: redacted init",
        );
    };
    // The entry exists; make sure the binary it points to still does.
    for command in settings::our_commands(entry) {
        let bin = command.trim_end_matches(" scrub");
        if fs::metadata(bin).is_err() {
            return check(label, Status::Fail, format!(
                "hook command references {bin} but that binary doesn't exist, reinstall or run: redacted init"
            ));
        }
    }
    check(label, Status::Pass, shown.to_string())
}

fn check_config(cwd: &str) -> Check {
    let home_dir = home();
    let files = [
        (
            "global config",
            Path::new(&home_dir).join(".config/redacted/config.yaml"),
        ),
        ("project config", Path::new(cwd).join(".redacted.yaml")),
        (
            "global engine",
            Path::new(&home_dir).join(".config/redacted/engine.yml"),
        ),
        (
            "project engine",
            Path::new(cwd).join(".redacted.engine.yml"),
        ),
    ];
    let sources: Vec<&str> = files
        .iter()
        .filter(|(_, p)| p.exists())
        .map(|(label, _)| *label)
        .collect();
    if sources.is_empty() {
        return check(
            "config files",
            Status::Pass,
            "none found (using built-in defaults)",
        );
    }
    let cfg = config::load(&home_dir, cwd);
    let eng = config::load_engine(&home_dir, cwd);
    let mut detail = format!("{} loaded", sources.join(", "));
    let extras: Vec<String> = [
        (cfg.whitelist.len(), "whitelisted"),
        (cfg.allow.len(), "allowed vars"),
        (eng.patterns.len(), "custom patterns"),
    ]
    .iter()
    .filter(|(n, _)| *n > 0)
    .map(|(n, what)| format!("{n} {what}"))
    .collect();
    if !extras.is_empty() {
        detail += &format!(" ({})", extras.join(", "));
    }
    check("config files", Status::Pass, detail)
}

// Includes user patterns: a bad one now withholds every hook output, so say so here.
fn check_patterns(cwd: &str) -> Check {
    let cfg = config::load(&home(), cwd);
    match Scrubber::new(&cfg, &config::load_engine(&home(), cwd)) {
        Ok(_) => check("patterns load", Status::Pass, "all patterns compiled"),
        Err(e) => check(
            "patterns load",
            Status::Fail,
            format!("failed to compile patterns: {e}"),
        ),
    }
}

fn check_learned(cwd: &str) -> Vec<Check> {
    let cfg = config::load(&home(), cwd);
    let heuristic = if cfg.heuristic.enabled {
        "enabled"
    } else {
        "disabled"
    };
    let detail = format!(
        "config version {}, {} learned, heuristic {heuristic}",
        cfg.version.max(1),
        cfg.learned.len()
    );
    let mut out = vec![check("learned secrets", Status::Pass, detail)];
    if config::vendor_only(&cfg) {
        out.push(check(
            "protection",
            Status::Warn,
            config::VENDOR_ONLY_NOTICE,
        ));
    }
    let n = config::project_learned_count(cwd);
    if n > 0 {
        let entries = if n == 1 { "entry" } else { "entries" };
        out.push(check("project learned", Status::Warn, format!(
            ".redacted.yaml has {n} learned {entries}, ignored: learned secrets belong in ~/.config/redacted/config.yaml"
        )));
    }
    out
}

fn check_scrub() -> Check {
    let result = Scrubber::new(&Config::default(), &EngineConfig::default())
        .map(|s| s.scrub("DATABASE_URL=postgres://user:Xk7Pq9mW2vB8@host:5432/db"));
    match result {
        Ok(r) if r.redacted() && r.text.contains("[REDACTED") => check(
            "test scrub",
            Status::Pass,
            format!("caught {} secret(s) in test input", r.count),
        ),
        _ => check(
            "test scrub",
            Status::Fail,
            "scrubber did not detect a database URL, patterns may be broken",
        ),
    }
}
