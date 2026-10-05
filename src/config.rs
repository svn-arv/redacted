//! App policy (config.yaml / .redacted.yaml) and engine overrides
//! (engine.yml / .redacted.engine.yml), mirroring internal/config/config.go.

use serde::Deserialize;

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct Config {
    pub r#override: bool,
    pub whitelist: Vec<String>,
    pub allow: Vec<String>,
    pub ignore_internal_tools: bool,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct CustomPattern {
    pub name: String,
    pub regex: String,
}

/// `keywords`, `heuristic` and `value_safe_char` are still parsed so old
/// files load, but the tiers that used them are gone.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct EngineConfig {
    pub r#override: bool,
    pub value_safe_char: String,
    pub heuristic: serde_yaml::Value,
    pub keywords: Vec<String>,
    pub allow_values: Vec<String>,
    pub patterns: Vec<CustomPattern>,
}
