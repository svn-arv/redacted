//! App policy (config.yaml / .redacted.yaml) and engine overrides
//! (engine.yml / .redacted.engine.yml), mirroring internal/config/config.go.

use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct Config {
    pub r#override: bool,
    pub whitelist: Vec<String>,
    pub allow: Vec<String>,
    pub ignore_internal_tools: bool,
}

#[derive(Debug, Default, Clone, Deserialize)]
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
    #[allow(dead_code)]
    pub value_safe_char: String,
    #[allow(dead_code)]
    pub heuristic: serde_yaml::Value,
    #[allow(dead_code)]
    pub keywords: Vec<String>,
    pub allow_values: Vec<String>,
    pub patterns: Vec<CustomPattern>,
}

fn read<T: serde::de::DeserializeOwned>(path: PathBuf) -> Option<T> {
    serde_yaml::from_str(&fs::read_to_string(path).ok()?).ok()
}

fn paths(home: &str, cwd: &str, global: &str, project: &str) -> (Option<PathBuf>, Option<PathBuf>) {
    let g = (!home.is_empty()).then(|| Path::new(home).join(".config/redacted").join(global));
    let p = (!cwd.is_empty()).then(|| Path::new(cwd).join(project));
    (g, p)
}

/// Global ~/.config/redacted/config.yaml merged with <cwd>/.redacted.yaml;
/// a project `override: true` drops the global file. Unreadable files are skipped.
pub fn load(home: &str, cwd: &str) -> Config {
    let (g, p) = paths(home, cwd, "config.yaml", ".redacted.yaml");
    let global: Option<Config> = g.and_then(read);
    let project: Option<Config> = p.and_then(read);
    match (global, project) {
        (None, None) => Config::default(),
        (Some(g), None) => g,
        (None, Some(p)) => p,
        (Some(_), Some(p)) if p.r#override => p,
        (Some(g), Some(p)) => Config {
            r#override: false,
            whitelist: [g.whitelist, p.whitelist].concat(),
            allow: [g.allow, p.allow].concat(),
            ignore_internal_tools: g.ignore_internal_tools || p.ignore_internal_tools,
        },
    }
}

/// Global engine.yml merged with <cwd>/.redacted.engine.yml, same override rule.
pub fn load_engine(home: &str, cwd: &str) -> EngineConfig {
    let (g, p) = paths(home, cwd, "engine.yml", ".redacted.engine.yml");
    let global: Option<EngineConfig> = g.and_then(read);
    let project: Option<EngineConfig> = p.and_then(read);
    match (global, project) {
        (None, None) => EngineConfig::default(),
        (Some(g), None) => g,
        (None, Some(p)) => p,
        (Some(_), Some(p)) if p.r#override => p,
        (Some(g), Some(p)) => EngineConfig {
            allow_values: [g.allow_values, p.allow_values].concat(),
            patterns: [g.patterns, p.patterns].concat(),
            keywords: [g.keywords, p.keywords].concat(),
            ..g
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fresh (home, project) pair of temp dirs.
    fn dirs(tag: &str) -> (PathBuf, PathBuf) {
        let root = std::env::temp_dir().join(format!("redacted-cfg-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let (home, cwd) = (root.join("home"), root.join("proj"));
        fs::create_dir_all(home.join(".config/redacted")).unwrap();
        fs::create_dir_all(&cwd).unwrap();
        (home, cwd)
    }

    fn s(p: &std::path::Path) -> &str {
        p.to_str().unwrap()
    }

    #[test]
    fn missing_files_give_defaults() {
        let (home, cwd) = dirs("none");
        let cfg = load(s(&home), s(&cwd));
        assert!(cfg.whitelist.is_empty() && cfg.allow.is_empty() && !cfg.ignore_internal_tools);
        assert!(load_engine(s(&home), s(&cwd)).patterns.is_empty());
    }

    #[test]
    fn project_merges_over_global() {
        let (home, cwd) = dirs("merge");
        fs::write(
            home.join(".config/redacted/config.yaml"),
            "whitelist: [jwt]\nallow: [A]\n",
        )
        .unwrap();
        fs::write(
            cwd.join(".redacted.yaml"),
            "allow: [B]\nignore_internal_tools: true\n",
        )
        .unwrap();
        let cfg = load(s(&home), s(&cwd));
        assert_eq!(cfg.whitelist, ["jwt"]);
        assert_eq!(cfg.allow, ["A", "B"]);
        assert!(cfg.ignore_internal_tools);
    }

    #[test]
    fn project_override_drops_global() {
        let (home, cwd) = dirs("override");
        fs::write(
            home.join(".config/redacted/config.yaml"),
            "whitelist: [jwt]\n",
        )
        .unwrap();
        fs::write(cwd.join(".redacted.yaml"), "override: true\nallow: [B]\n").unwrap();
        let cfg = load(s(&home), s(&cwd));
        assert!(cfg.whitelist.is_empty());
        assert_eq!(cfg.allow, ["B"]);
    }

    #[test]
    fn malformed_file_is_ignored() {
        let (home, cwd) = dirs("bad");
        fs::write(
            home.join(".config/redacted/config.yaml"),
            "whitelist: [jwt]\n",
        )
        .unwrap();
        fs::write(cwd.join(".redacted.yaml"), "whitelist: {not: a list}\n").unwrap();
        assert_eq!(load(s(&home), s(&cwd)).whitelist, ["jwt"]);
    }

    #[test]
    fn engine_patterns_and_allow_values_merge() {
        let (home, cwd) = dirs("engine");
        fs::write(
            home.join(".config/redacted/engine.yml"),
            "keywords: [FOO]\nheuristic: {min_length: 20}\npatterns: [{name: g, regex: 'g_x'}]\n",
        )
        .unwrap();
        fs::write(
            cwd.join(".redacted.engine.yml"),
            "allow_values: ['^ok']\npatterns: [{name: p, regex: 'p_x'}]\n",
        )
        .unwrap();
        let eng = load_engine(s(&home), s(&cwd));
        let names: Vec<_> = eng.patterns.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, ["g", "p"]);
        assert_eq!(eng.allow_values, ["^ok"]);

        fs::write(
            cwd.join(".redacted.engine.yml"),
            "override: true\npatterns: [{name: p, regex: 'p_x'}]\n",
        )
        .unwrap();
        assert_eq!(load_engine(s(&home), s(&cwd)).patterns.len(), 1);
    }
}
