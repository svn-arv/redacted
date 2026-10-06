//! `redacted verify`: install and config health checks, one line each.

use std::fs;
use std::io;
use std::path::Path;

use serde_json::Value;

use crate::config::{self, Config, EngineConfig};
use crate::scrub::Scrubber;
use crate::settings;

#[derive(Clone, Copy, PartialEq)]
enum Status {
    Pass,
    Fail,
    Skip,
    Warn,
}

impl Status {
    fn label(self) -> &'static str {
        match self {
            Status::Pass => "PASS",
            Status::Fail => "FAIL",
            Status::Skip => "SKIP",
            Status::Warn => "WARN",
        }
    }
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

/// `redacted verify`: prints one line per check and fails if any check failed.
pub fn run() -> Result<(), String> {
    let home_dir = config::home();
    // as_deref() turns `Option<PathBuf>` into the borrowed `Option<&Path>`.
    let home_dir = home_dir.as_deref();
    let cwd = std::env::current_dir().ok();
    let cwd = cwd.as_deref();
    let cfg = config::load(home_dir, cwd);
    let eng = config::load_engine(home_dir, cwd);
    let mut checks = vec![check_binary()];
    checks.extend(check_hooks(home_dir, cwd));
    checks.push(check_config(home_dir, cwd, &cfg, &eng));
    checks.push(check_patterns(&cfg, &eng));
    checks.push(check_scrub());
    checks.extend(check_learned(cwd, &cfg));

    for c in &checks {
        let tag = c.status.label();
        if c.detail.is_empty() {
            println!("  [{tag}] {}", c.name);
        } else {
            println!("  [{tag}] {} - {}", c.name, c.detail);
        }
    }
    let count = |status| checks.iter().filter(|c| c.status == status).count();
    let (passed, failed) = (count(Status::Pass), count(Status::Fail));
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

fn check_hooks(home_dir: Option<&Path>, cwd: Option<&Path>) -> Vec<Check> {
    let mut global = match home_dir {
        Some(home) => check_settings_file(&home.join(".claude/settings.json"), "global hook"),
        None => check(
            "global hook",
            Status::Fail,
            "cannot determine home directory",
        ),
    };
    let mut local = match cwd {
        Some(dir) => check_settings_file(&dir.join(".claude/settings.local.json"), "local hook"),
        None => check(
            "local hook",
            Status::Fail,
            "cannot determine working directory",
        ),
    };

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
    let fail = |detail: String| check(label, Status::Fail, detail);
    let data = match fs::read(path) {
        Ok(d) => d,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return fail(format!("file not found: {shown}"))
        }
        Err(e) => return fail(format!("cannot read {shown}: {e}")),
    };
    let settings: Value = match serde_json::from_slice(&data) {
        Ok(s) => s,
        Err(e) => return fail(format!("{shown} contains invalid JSON: {e}")),
    };
    if settings::post_tool_use(&settings).is_empty() {
        return fail(format!(
            "no PostToolUse hooks in {shown}, run: redacted init"
        ));
    }
    let Some(entry) = settings::find_ours(&settings) else {
        return fail("PostToolUse exists but has no redacted entry, run: redacted init".into());
    };
    // The entry exists; make sure the binary it points to still does.
    for command in settings::our_commands(entry) {
        let bin = command.trim_end_matches(" scrub");
        if fs::metadata(bin).is_err() {
            return fail(format!(
                "hook command references {bin} but that binary doesn't exist, reinstall or run: redacted init"
            ));
        }
    }
    check(label, Status::Pass, shown.to_string())
}

fn check_config(
    home_dir: Option<&Path>,
    cwd: Option<&Path>,
    cfg: &Config,
    eng: &EngineConfig,
) -> Check {
    let files = [
        ("global config", home_dir.map(config::global_path)),
        ("project config", cwd.map(|c| c.join(".redacted.yaml"))),
        (
            "global engine",
            home_dir.map(|h| h.join(".config/redacted/engine.yml")),
        ),
        (
            "project engine",
            cwd.map(|c| c.join(".redacted.engine.yml")),
        ),
    ];
    // A path is None without a HOME or working directory, which counts as not found.
    let sources: Vec<&str> = files
        .iter()
        .filter(|(_, path)| path.as_deref().is_some_and(Path::exists))
        .map(|(label, _)| *label)
        .collect();
    if sources.is_empty() {
        return check(
            "config files",
            Status::Pass,
            "none found (using built-in defaults)",
        );
    }
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
fn check_patterns(cfg: &Config, eng: &EngineConfig) -> Check {
    match Scrubber::new(cfg, eng) {
        Ok(_) => check("patterns load", Status::Pass, "all patterns compiled"),
        Err(e) => check(
            "patterns load",
            Status::Fail,
            format!("failed to compile patterns: {e}"),
        ),
    }
}

fn check_learned(cwd: Option<&Path>, cfg: &Config) -> Vec<Check> {
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
    if config::vendor_only(cfg) {
        out.push(check(
            "protection",
            Status::Warn,
            config::VENDOR_ONLY_NOTICE,
        ));
    }
    let n = cwd.map_or(0, config::project_learned_count);
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
