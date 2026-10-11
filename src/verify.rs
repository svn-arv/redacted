//! `redacted verify`: install and config health checks, one line each.

use std::fs;
use std::io;
use std::path::Path;

use serde_json::Value;

use crate::config::{self, Config, EngineConfig};
use crate::scrub::Scrubber;
use crate::settings;

#[derive(Clone, Copy, PartialEq)]
enum CheckStatus {
    Pass,
    Fail,
    Skip,
    Warn,
}

impl CheckStatus {
    fn label(self) -> &'static str {
        match self {
            CheckStatus::Pass => "PASS",
            CheckStatus::Fail => "FAIL",
            CheckStatus::Skip => "SKIP",
            CheckStatus::Warn => "WARN",
        }
    }
}

struct Check {
    name: &'static str,
    status: CheckStatus,
    detail: String,
}

impl Check {
    /// `impl Into<String>` takes a `&str` or a `String`, so callers skip `.to_string()`.
    fn new(name: &'static str, status: CheckStatus, detail: impl Into<String>) -> Check {
        Check {
            name,
            status,
            detail: detail.into(),
        }
    }
}

/// `redacted verify`: prints one line per check and fails if any check failed.
pub fn run() -> Result<(), String> {
    let home_dir = config::home_dir();
    // as_deref() turns `Option<PathBuf>` into the borrowed `Option<&Path>`.
    let home_dir = home_dir.as_deref();
    let cwd = std::env::current_dir().ok();
    let cwd = cwd.as_deref();
    let config = config::load(home_dir, cwd);
    let engine_config = config::load_engine(home_dir, cwd);
    let mut checks = vec![check_binary()];
    checks.extend(check_hooks(home_dir, cwd));
    checks.push(check_config_files(home_dir, cwd, &config, &engine_config));
    checks.push(check_patterns(&config, &engine_config));
    checks.push(check_test_scrub());
    checks.extend(check_learned(cwd, &config));

    for check in &checks {
        let label = check.status.label();
        if check.detail.is_empty() {
            println!("  [{label}] {}", check.name);
        } else {
            println!("  [{label}] {} - {}", check.name, check.detail);
        }
    }
    let count = |status| checks.iter().filter(|check| check.status == status).count();
    let (passed, failed) = (count(CheckStatus::Pass), count(CheckStatus::Fail));
    println!("\n{passed} passed, {failed} failed");
    if failed > 0 {
        return Err(format!("Error: {failed} check(s) failed"));
    }
    Ok(())
}

fn check_binary() -> Check {
    match std::env::current_exe() {
        Ok(p) => Check::new("binary", CheckStatus::Pass, p.display().to_string()),
        Err(_) => Check::new("binary", CheckStatus::Fail, "not found, reinstall redacted"),
    }
}

fn check_hooks(home_dir: Option<&Path>, cwd: Option<&Path>) -> Vec<Check> {
    let mut global = match home_dir {
        Some(home) => check_settings_file(&home.join(".claude/settings.json"), "global hook"),
        None => Check::new(
            "global hook",
            CheckStatus::Fail,
            "cannot determine home directory",
        ),
    };
    let mut local = match cwd {
        Some(dir) => check_settings_file(&dir.join(".claude/settings.local.json"), "local hook"),
        None => Check::new(
            "local hook",
            CheckStatus::Fail,
            "cannot determine working directory",
        ),
    };

    // One registration is enough; the missing other is a skip, not a failure.
    if global.status == CheckStatus::Pass && local.status == CheckStatus::Fail {
        local.status = CheckStatus::Skip;
    }
    if local.status == CheckStatus::Pass && global.status == CheckStatus::Fail {
        global.status = CheckStatus::Skip;
    }
    let no_hook_registered =
        global.status != CheckStatus::Pass && local.status != CheckStatus::Pass;
    let mut out = vec![global, local];
    if no_hook_registered {
        out.push(Check::new(
            "hook registered",
            CheckStatus::Fail,
            "not found in either settings file, run: redacted init",
        ));
    }
    out
}

fn check_settings_file(path: &Path, label: &'static str) -> Check {
    let shown = path.display();
    let fail = |detail: String| Check::new(label, CheckStatus::Fail, detail);
    let data = match fs::read(path) {
        Ok(data) => data,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return fail(format!("file not found: {shown}"));
        }
        Err(e) => return fail(format!("cannot read {shown}: {e}")),
    };
    let settings: Value = match serde_json::from_slice(&data) {
        Ok(settings) => settings,
        Err(e) => return fail(format!("{shown} contains invalid JSON: {e}")),
    };
    if settings::post_tool_use_entries(&settings).is_empty() {
        return fail(format!(
            "no PostToolUse hooks in {shown}, run: redacted init"
        ));
    }
    let Some(entry) = settings::find_redacted_entry(&settings) else {
        return fail("PostToolUse exists but has no redacted entry, run: redacted init".into());
    };
    // The entry exists; make sure the binary it points to still does.
    for command in settings::redacted_commands(entry) {
        let bin = command.trim_end_matches(" scrub");
        if fs::metadata(bin).is_err() {
            return fail(format!(
                "hook command references {bin} but that binary doesn't exist, reinstall or run: redacted init"
            ));
        }
    }
    Check::new(label, CheckStatus::Pass, shown.to_string())
}

fn check_config_files(
    home_dir: Option<&Path>,
    cwd: Option<&Path>,
    config: &Config,
    engine_config: &EngineConfig,
) -> Check {
    let files = [
        ("global config", home_dir.map(config::global_config_path)),
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
        return Check::new(
            "config files",
            CheckStatus::Pass,
            "none found (using built-in defaults)",
        );
    }
    let mut detail = format!("{} loaded", sources.join(", "));
    let extras: Vec<String> = [
        (config.disabled_patterns.len(), "whitelisted"),
        (config.allowed_keys.len(), "allowed vars"),
        (engine_config.patterns.len(), "custom patterns"),
    ]
    .iter()
    .filter(|(n, _)| *n > 0)
    .map(|(n, what)| format!("{n} {what}"))
    .collect();
    if !extras.is_empty() {
        detail += &format!(" ({})", extras.join(", "));
    }
    Check::new("config files", CheckStatus::Pass, detail)
}

// Includes user patterns: a bad one now withholds every hook output, so say so here.
fn check_patterns(config: &Config, engine_config: &EngineConfig) -> Check {
    match Scrubber::new(config, engine_config) {
        Ok(_) => Check::new("patterns load", CheckStatus::Pass, "all patterns compiled"),
        Err(e) => Check::new(
            "patterns load",
            CheckStatus::Fail,
            format!("failed to compile patterns: {e}"),
        ),
    }
}

fn check_learned(cwd: Option<&Path>, config: &Config) -> Vec<Check> {
    let heuristic = if config.heuristic.enabled {
        "enabled"
    } else {
        "disabled"
    };
    let detail = format!(
        "config version {}, {} learned, heuristic {heuristic}",
        config.version.max(1),
        config.learned.len()
    );
    let mut out = vec![Check::new("learned secrets", CheckStatus::Pass, detail)];
    if config::is_vendor_only(config) {
        out.push(Check::new(
            "protection",
            CheckStatus::Warn,
            config::VENDOR_ONLY_NOTICE,
        ));
    }
    let project_learned = cwd.map_or(0, config::project_learned_count);
    if project_learned > 0 {
        let entries = if project_learned == 1 {
            "entry"
        } else {
            "entries"
        };
        out.push(Check::new("project learned", CheckStatus::Warn, format!(
            ".redacted.yaml has {project_learned} learned {entries}, ignored: learned secrets belong in ~/.config/redacted/config.yaml"
        )));
    }
    out
}

fn check_test_scrub() -> Check {
    let result = Scrubber::new(&Config::default(), &EngineConfig::default())
        .map(|s| s.scrub("DATABASE_URL=postgres://user:Xk7Pq9mW2vB8@host:5432/db"));
    match result {
        Ok(r) if r.has_redactions() && r.text.contains("[REDACTED") => Check::new(
            "test scrub",
            CheckStatus::Pass,
            format!("caught {} secret(s) in test input", r.count),
        ),
        _ => Check::new(
            "test scrub",
            CheckStatus::Fail,
            "scrubber did not detect a database URL, patterns may be broken",
        ),
    }
}
