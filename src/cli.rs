//! Commands: scrub, verify, stats (ported from cmd/).

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Read, Write};
use std::path::Path;

use clap::{CommandFactory, Parser, Subcommand};
use serde::Deserialize;
use serde_json::Value;

use crate::config::{self, Config, EngineConfig};
use crate::scrub::Scrubber;
use crate::{hook, stats};

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
}

/// Runs the CLI and returns the process exit code.
pub fn run() -> i32 {
    let cli = Cli::parse();
    if cli.version {
        println!("redacted version {}", env!("CARGO_PKG_VERSION"));
        return 0;
    }
    match cli.command {
        Some(Cmd::Scrub) => scrub(),
        Some(Cmd::Verify) => verify(),
        Some(Cmd::Stats) => show_stats(),
        None => {
            let _ = Cli::command().print_help();
            0
        }
    }
}

fn home() -> String {
    std::env::var("HOME").unwrap_or_default()
}

fn scrub() -> i32 {
    let mut data = Vec::new();
    if let Err(e) = io::stdin().read_to_end(&mut data) {
        eprintln!("scrub: read stdin: {e}");
        return 1;
    }
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
        let scrubber = match scrubber {
            Ok(s) => s,
            Err(e) => {
                eprintln!("scrub: {e}");
                return 1;
            }
        };
        let result = scrubber.scrub(&String::from_utf8_lossy(&data));
        let _ = io::stdout().write_all(result.text.as_bytes());
        if result.redacted() {
            eprintln!("[redacted] {} secret(s) scrubbed", result.count);
        }
        return 0;
    }

    if cfg.ignore_internal_tools && field("tool_name") != "Bash" {
        return 0;
    }
    let out = match scrubber {
        Ok(s) => hook::process_safely(&data, &|t| s.scrub(t), &mut record),
        Err(_) => hook::withheld(),
    };
    let _ = io::stdout().write_all(&out);
    0
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

fn show_stats() -> i32 {
    let Some(path) = stats::file_path() else {
        eprintln!("stats: cannot determine home directory");
        return 1;
    };
    match stats::aggregate(&path) {
        Ok(s) => {
            print!("{}", stats::render(&s));
            0
        }
        Err(e) => {
            eprintln!("stats: {e}");
            1
        }
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Status {
    Pass,
    Fail,
    Skip,
}

struct Check {
    name: &'static str,
    status: Status,
    detail: String,
}

fn check(name: &'static str, status: Status, detail: impl Into<String>) -> Check {
    Check {
        name,
        status,
        detail: detail.into(),
    }
}

fn verify() -> i32 {
    let cwd = std::env::current_dir()
        .map(|p| p.display().to_string())
        .unwrap_or_default();
    let mut checks = vec![check_binary()];
    checks.extend(check_hooks(&cwd));
    checks.push(check_config(&cwd));
    checks.push(check_patterns(&cwd));
    checks.push(check_scrub());

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
        };
        if c.detail.is_empty() {
            println!("  [{tag}] {}", c.name);
        } else {
            println!("  [{tag}] {} - {}", c.name, c.detail);
        }
    }
    println!("\n{passed} passed, {failed} failed");
    if failed > 0 {
        eprintln!("Error: {failed} check(s) failed");
        return 1;
    }
    0
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

#[derive(Deserialize, Default)]
#[serde(default)]
struct Settings {
    hooks: Hooks,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Hooks {
    #[serde(rename = "PostToolUse")]
    post_tool_use: Vec<HookEntry>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct HookEntry {
    hooks: Vec<HookCommand>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct HookCommand {
    command: String,
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
    let settings: Settings = match serde_json::from_slice(&data) {
        Ok(s) => s,
        Err(e) => {
            return check(
                label,
                Status::Fail,
                format!("{shown} contains invalid JSON: {e}"),
            )
        }
    };
    if settings.hooks.post_tool_use.is_empty() {
        return check(
            label,
            Status::Fail,
            format!("no PostToolUse hooks in {shown}, run: redacted init"),
        );
    }
    let is_ours = |h: &HookCommand| h.command.ends_with("redacted scrub");
    let Some(entry) = settings
        .hooks
        .post_tool_use
        .iter()
        .find(|e| e.hooks.iter().any(is_ours))
    else {
        return check(
            label,
            Status::Fail,
            "PostToolUse exists but has no redacted entry, run: redacted init",
        );
    };
    // The entry exists; make sure the binary it points to still does.
    for h in entry.hooks.iter().filter(|h| is_ours(h)) {
        let bin = h.command.trim_end_matches(" scrub");
        if fs::metadata(bin).is_err() {
            return check(label, Status::Fail, format!(
                "hook command references {bin} but that binary doesn't exist, reinstall or run: redacted init"
            ));
        }
    }
    check(label, Status::Pass, shown.to_string())
}

fn check_config(cwd: &str) -> Check {
    let home = home();
    let files = [
        (
            "global config",
            Path::new(&home).join(".config/redacted/config.yaml"),
        ),
        ("project config", Path::new(cwd).join(".redacted.yaml")),
        (
            "global engine",
            Path::new(&home).join(".config/redacted/engine.yml"),
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
    let cfg = config::load(&home, cwd);
    let eng = config::load_engine(&home, cwd);
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
