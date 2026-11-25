//! Reading and merging config from disk: app policy (config.yaml / .redacted.yaml)
//! and engine overrides (engine.yml / .redacted.engine.yml). The data types
//! themselves live in `redacted_core::config` and are re-exported here so callers
//! keep writing `config::Config`, `config::load`, and so on.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

pub use redacted_core::config::{
    Config, ConfigError, EngineConfig, LearnedSecret, VENDOR_ONLY_NOTICE, is_vendor_only,
};
use redacted_core::config::{HeuristicConfig, PiiConfig};

/// Generic over the file's type: `DeserializeOwned` means "can be built from
/// text without borrowing it", so one reader serves Config and EngineConfig.
/// A missing file is `Ok(None)`; one that exists but does not read or parse is an
/// error naming it, because running on defaults would drop what it holds unseen.
fn read_yaml<T: serde::de::DeserializeOwned>(path: &Path) -> Result<Option<T>, ConfigError> {
    let config_error = |message: String| ConfigError {
        path: path.to_path_buf(),
        message,
    };
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(config_error(e.to_string())),
    };
    serde_yaml::from_str(&text)
        .map(Some)
        .map_err(|e| config_error(e.to_string()))
}

/// $HOME, or None when it is unset or empty, so no path is built under the cwd.
pub fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .filter(|home| !home.is_empty())
        .map(PathBuf::from)
}

/// ~/.config/redacted/config.yaml, the only file that holds learned secrets.
pub fn global_config_path(home: &Path) -> PathBuf {
    home.join(".config/redacted/config.yaml")
}

fn global_and_project_paths(
    home: Option<&Path>,
    cwd: Option<&Path>,
    global_file: &str,
    project_file: &str,
) -> (Option<PathBuf>, Option<PathBuf>) {
    let global_path = home.map(|home| home.join(".config/redacted").join(global_file));
    let project_path = cwd.map(|cwd| cwd.join(project_file));
    (global_path, project_path)
}

/// Global ~/.config/redacted/config.yaml merged with <cwd>/.redacted.yaml;
/// a project `override: true` drops the global file. A missing file is skipped;
/// a malformed one is an error.
pub fn load(home: Option<&Path>, cwd: Option<&Path>) -> Result<Config, ConfigError> {
    let (global_path, project_path) =
        global_and_project_paths(home, cwd, "config.yaml", ".redacted.yaml");
    // as_deref() lends the PathBuf inside the Option as a `&Path` for `read_yaml` to borrow.
    let global: Option<Config> = global_path.as_deref().map_or(Ok(None), read_yaml)?;
    let project: Option<Config> = project_path.as_deref().map_or(Ok(None), read_yaml)?;
    // Learned hashes, the heuristic and PII are global only, even under a project override.
    let (version, learned, heuristic, pii) = match &global {
        Some(global) => (
            global.version,
            global.learned.clone(),
            global.heuristic.clone(),
            global.pii.clone(),
        ),
        None => (
            0,
            Vec::new(),
            HeuristicConfig::default(),
            PiiConfig::default(),
        ),
    };
    // Matching on the pair covers every combination; `if` guards pick the override case.
    let merged = match (global, project) {
        (None, None) => Config::default(),
        (Some(global), None) => global,
        (None, Some(project)) => project,
        (Some(_), Some(project)) if project.project_override => project,
        (Some(global), Some(project)) => Config {
            disabled_patterns: [global.disabled_patterns, project.disabled_patterns].concat(),
            allowed_keys: [global.allowed_keys, project.allowed_keys].concat(),
            ignore_internal_tools: global.ignore_internal_tools || project.ignore_internal_tools,
            ..Default::default()
        },
    };
    // Struct update: the four named fields, everything else taken from `merged`.
    Ok(Config {
        version,
        learned,
        heuristic,
        pii,
        ..merged
    })
}

/// Learned entries in <cwd>/.redacted.yaml, which `load` ignores; verify warns on them.
pub fn project_learned_count(cwd: &Path) -> usize {
    // A malformed file counts 0 here: verify's `config files` check already fails on it.
    let project: Option<Config> = read_yaml(&cwd.join(".redacted.yaml")).ok().flatten();
    project.map_or(0, |project| project.learned.len())
}

/// Global engine.yml merged with <cwd>/.redacted.engine.yml, same override rule.
pub fn load_engine(home: Option<&Path>, cwd: Option<&Path>) -> Result<EngineConfig, ConfigError> {
    let (global_path, project_path) =
        global_and_project_paths(home, cwd, "engine.yml", ".redacted.engine.yml");
    let global: Option<EngineConfig> = global_path.as_deref().map_or(Ok(None), read_yaml)?;
    let project: Option<EngineConfig> = project_path.as_deref().map_or(Ok(None), read_yaml)?;
    let merged = match (global, project) {
        (None, None) => EngineConfig::default(),
        (Some(global), None) => global,
        (None, Some(project)) => project,
        (Some(_), Some(project)) if project.project_override => project,
        (Some(global), Some(project)) => EngineConfig {
            allow_values: [global.allow_values, project.allow_values].concat(),
            patterns: [global.patterns, project.patterns].concat(),
            ..global
        },
    };
    Ok(merged)
}

#[cfg(test)]
mod tests;
