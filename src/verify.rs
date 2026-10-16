//! `redacted verify`: install and config health checks, one line each.

use std::fs;
use std::io;
use std::path::Path;

use serde_json::Value;

use crate::cli::Format;
use crate::config::{self, Config, EngineConfig};
use crate::scrub::Scrubber;
use crate::{opencode, settings};

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
pub fn run(format: Format) -> Result<(), String> {
    let home_dir = config::home_dir();
    // as_deref() turns `Option<PathBuf>` into the borrowed `Option<&Path>`.
    let home_dir = home_dir.as_deref();
    let cwd = std::env::current_dir().ok();
    let cwd = cwd.as_deref();
    let loaded = config::load(home_dir, cwd)
        .and_then(|config| Ok((config, config::load_engine(home_dir, cwd)?)));
    // A file that does not parse fails its own check; the rest still report, on defaults.
    let (config, engine_config, config_files) = match loaded {
        Ok((config, engine_config)) => {
            let check = check_config_files(home_dir, cwd, &config, &engine_config);
            (config, engine_config, check)
        }
        Err(e) => {
            let detail = format!("{e}; other checks use built-in defaults");
            let check = Check::new("config files", CheckStatus::Fail, detail);
            (Config::default(), EngineConfig::default(), check)
        }
    };
    let mut checks = vec![check_binary()];
    checks.extend(check_registration(format, home_dir, cwd));
    checks.push(config_files);
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

/// Where `format` registers the hook; its own function to keep `run` under the line limit.
fn check_registration(format: Format, home_dir: Option<&Path>, cwd: Option<&Path>) -> Vec<Check> {
    match format {
        Format::Claude => {
            let mut checks = check_hooks(home_dir, cwd);
            checks.push(check_monitor_hook(home_dir, cwd));
            checks
        }
        Format::Opencode => check_opencode_plugins(home_dir, cwd),
    }
}

fn check_hooks(home_dir: Option<&Path>, cwd: Option<&Path>) -> Vec<Check> {
    let global = match home_dir {
        Some(home) => check_settings_file(&home.join(".claude/settings.json"), "global hook"),
        None => Check::new(
            "global hook",
            CheckStatus::Fail,
            "cannot determine home directory",
        ),
    };
    let local = match cwd {
        Some(dir) => check_settings_file(&dir.join(".claude/settings.local.json"), "local hook"),
        None => Check::new(
            "local hook",
            CheckStatus::Fail,
            "cannot determine working directory",
        ),
    };
    let missing = Check::new(
        "hook registered",
        CheckStatus::Fail,
        "not found in either settings file, run: redacted init",
    );
    one_scope_is_enough(global, local, missing)
}

/// OpenCode loads every file in either plugin folder, so one of ours is enough.
fn check_opencode_plugins(home_dir: Option<&Path>, cwd: Option<&Path>) -> Vec<Check> {
    let global = match home_dir {
        Some(home) => check_plugin_file(&opencode::global_plugin_path(home), "global plugin"),
        None => Check::new(
            "global plugin",
            CheckStatus::Fail,
            "cannot determine home directory",
        ),
    };
    let local = match cwd {
        Some(dir) => check_plugin_file(&opencode::local_plugin_path(dir), "local plugin"),
        None => Check::new(
            "local plugin",
            CheckStatus::Fail,
            "cannot determine working directory",
        ),
    };
    let missing = Check::new(
        "plugin registered",
        CheckStatus::Fail,
        "not found in either plugin folder, run: redacted init --format opencode",
    );
    one_scope_is_enough(global, local, missing)
}

fn check_plugin_file(path: &Path, label: &'static str) -> Check {
    let shown = path.display();
    if !path.exists() {
        return Check::new(label, CheckStatus::Fail, format!("file not found: {shown}"));
    }
    if !opencode::is_our_plugin(path) {
        let detail =
            format!("{shown} is not the redacted plugin, run: redacted init --format opencode");
        return Check::new(label, CheckStatus::Fail, detail);
    }
    Check::new(label, CheckStatus::Pass, shown.to_string())
}

/// One registration is enough; the missing other is a skip, not a failure.
/// `missing` is added when neither scope passed.
fn one_scope_is_enough(mut global: Check, mut local: Check, missing: Check) -> Vec<Check> {
    if global.status == CheckStatus::Pass && local.status == CheckStatus::Fail {
        local.status = CheckStatus::Skip;
    }
    if local.status == CheckStatus::Pass && global.status == CheckStatus::Fail {
        global.status = CheckStatus::Skip;
    }
    let is_registered = global.status == CheckStatus::Pass || local.status == CheckStatus::Pass;
    let mut out = vec![global, local];
    if !is_registered {
        out.push(missing);
    }
    out
}

/// Monitor events skip PostToolUse, so an install from before the PreToolUse
/// hook leaks them until `redacted init` runs again.
fn check_monitor_hook(home_dir: Option<&Path>, cwd: Option<&Path>) -> Check {
    let files = [
        home_dir.map(|home| home.join(".claude/settings.json")),
        cwd.map(|dir| dir.join(".claude/settings.local.json")),
    ];
    let is_registered = files.iter().flatten().any(|path| {
        matches!(settings::read(path), Ok(Some(found))
            if settings::find_redacted_entry(&found, "PreToolUse").is_some())
    });
    if is_registered {
        Check::new(
            "monitor hook",
            CheckStatus::Pass,
            "PreToolUse Monitor entry found",
        )
    } else {
        Check::new(
            "monitor hook",
            CheckStatus::Fail,
            "no PreToolUse Monitor entry in either settings file, run: redacted init",
        )
    }
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
    if settings::hook_entries(&settings, "PostToolUse").is_empty() {
        return fail(format!(
            "no PostToolUse hooks in {shown}, run: redacted init"
        ));
    }
    let Some(entry) = settings::find_redacted_entry(&settings, "PostToolUse") else {
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
    match compile_patterns(config, engine_config) {
        Ok(()) => Check::new("patterns load", CheckStatus::Pass, "all patterns compiled"),
        Err(e) => Check::new("patterns load", CheckStatus::Fail, e),
    }
}

/// The `patterns load` check without the report line; `redacted config` runs it after an edit.
pub fn compile_patterns(config: &Config, engine_config: &EngineConfig) -> Result<(), String> {
    Scrubber::new(config, engine_config)
        .map(|_| ())
        .map_err(|e| format!("failed to compile patterns: {e}"))
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
