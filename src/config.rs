//! App policy (config.yaml / .redacted.yaml) and engine overrides
//! (engine.yml / .redacted.engine.yml).

use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct Config {
    #[serde(rename = "override")]
    pub project_override: bool,
    #[serde(rename = "whitelist")]
    pub disabled_patterns: Vec<String>,
    #[serde(rename = "allow")]
    pub allowed_keys: Vec<String>,
    pub ignore_internal_tools: bool,
    pub version: u32,
    pub learned: Vec<LearnedSecret>,
    pub heuristic: HeuristicConfig,
    pub pii: PiiConfig,
}

/// A secret learned by `init`: its hash and byte length, never the value.
#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct LearnedSecret {
    pub name: String,
    pub sha256: String,
    #[serde(rename = "len")]
    pub byte_len: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shape: Option<String>,
}

// Default heuristic thresholds. The includes_key guards in scrub/guards.rs use
// DEFAULT_MIN_CHAR_CLASSES and DEFAULT_MIN_ENTROPY as fixed values on purpose,
// whatever the config says, to tell a random segment from an identifier.
pub const DEFAULT_MIN_LENGTH: usize = 16;
pub const DEFAULT_MAX_LENGTH: usize = 128;
pub const DEFAULT_MIN_CHAR_CLASSES: usize = 3;
pub const DEFAULT_MIN_ENTROPY: f64 = 3.5;

/// Opt-in entropy tier. Each absent threshold takes its default; an explicit
/// value, zero included, is used as written.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct HeuristicConfig {
    pub enabled: bool,
    // serde calls the named function when the key is missing.
    #[serde(default = "default_min_length")]
    pub min_length: usize,
    #[serde(default = "default_max_length")]
    pub max_length: usize,
    #[serde(default = "default_min_char_classes")]
    pub min_char_classes: usize,
    #[serde(default = "default_min_entropy")]
    pub min_entropy: f64,
}

// Written by hand, not derived: a derived Default would give zero thresholds.
impl Default for HeuristicConfig {
    fn default() -> Self {
        HeuristicConfig {
            enabled: false,
            min_length: DEFAULT_MIN_LENGTH,
            max_length: DEFAULT_MAX_LENGTH,
            min_char_classes: DEFAULT_MIN_CHAR_CLASSES,
            min_entropy: DEFAULT_MIN_ENTROPY,
        }
    }
}

fn default_min_length() -> usize {
    DEFAULT_MIN_LENGTH
}

fn default_max_length() -> usize {
    DEFAULT_MAX_LENGTH
}

fn default_min_char_classes() -> usize {
    DEFAULT_MIN_CHAR_CLASSES
}

fn default_min_entropy() -> f64 {
    DEFAULT_MIN_ENTROPY
}

/// Opt-in PII tier: each toggle turns on the engine.yml row of the same name.
#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub struct PiiConfig {
    pub email: bool,
    pub phone: bool,
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub struct CustomPattern {
    pub name: String,
    pub regex: String,
}

/// An engine.yml from 0.7 still loads: serde skips its retired `keywords`,
/// `heuristic` and `value_safe_char` keys like any other unknown key.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct EngineConfig {
    #[serde(rename = "override")]
    pub project_override: bool,
    pub allow_values: Vec<String>,
    pub patterns: Vec<CustomPattern>,
}

/// A config file that exists but does not read or parse. Path and message stay
/// apart because the message can quote the file, which hook mode keeps from the model.
#[derive(Debug)]
pub struct ConfigError {
    pub path: PathBuf,
    pub message: String,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "{}: {}", self.path.display(), self.message)
    }
}

/// Lets `?` hand a ConfigError to the commands, which all fail with a String.
impl From<ConfigError> for String {
    fn from(error: ConfigError) -> String {
        error.to_string()
    }
}

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

pub const VENDOR_ONLY_NOTICE: &str = "vendor signatures only, no learned secrets, heuristic off; run `redacted init --env PATH` to learn yours";

/// Only the vendor tier is active: nothing catches a secret without a known prefix.
pub fn is_vendor_only(config: &Config) -> bool {
    config.learned.is_empty() && !config.heuristic.enabled
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
