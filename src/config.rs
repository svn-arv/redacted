//! App policy (config.yaml / .redacted.yaml) and engine overrides
//! (engine.yml / .redacted.engine.yml).

use std::fs;
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

/// Generic over the file's type: `DeserializeOwned` means "can be built from
/// text without borrowing it", so one reader serves Config and EngineConfig.
fn read_yaml<T: serde::de::DeserializeOwned>(path: &Path) -> Option<T> {
    serde_yaml::from_str(&fs::read_to_string(path).ok()?).ok()
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
/// a project `override: true` drops the global file. Unreadable files are skipped.
pub fn load(home: Option<&Path>, cwd: Option<&Path>) -> Config {
    let (global_path, project_path) =
        global_and_project_paths(home, cwd, "config.yaml", ".redacted.yaml");
    // as_deref() lends the PathBuf inside the Option as a `&Path` for `read_yaml` to borrow.
    let global: Option<Config> = global_path.as_deref().and_then(read_yaml);
    let project: Option<Config> = project_path.as_deref().and_then(read_yaml);
    // Learned hashes and the heuristic are global only, even under a project override.
    let (version, learned, heuristic) = match &global {
        Some(global) => (
            global.version,
            global.learned.clone(),
            global.heuristic.clone(),
        ),
        None => (0, Vec::new(), HeuristicConfig::default()),
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
    // Struct update: the three named fields, everything else taken from `merged`.
    Config {
        version,
        learned,
        heuristic,
        ..merged
    }
}

pub const VENDOR_ONLY_NOTICE: &str = "vendor signatures only, no learned secrets, heuristic off; run `redacted init --env PATH` to learn yours";

/// Only the vendor tier is active: nothing catches a secret without a known prefix.
pub fn is_vendor_only(config: &Config) -> bool {
    config.learned.is_empty() && !config.heuristic.enabled
}

/// Learned entries in <cwd>/.redacted.yaml, which `load` ignores; verify warns on them.
pub fn project_learned_count(cwd: &Path) -> usize {
    let project: Option<Config> = read_yaml(&cwd.join(".redacted.yaml"));
    project.map_or(0, |project| project.learned.len())
}

/// Global engine.yml merged with <cwd>/.redacted.engine.yml, same override rule.
pub fn load_engine(home: Option<&Path>, cwd: Option<&Path>) -> EngineConfig {
    let (global_path, project_path) =
        global_and_project_paths(home, cwd, "engine.yml", ".redacted.engine.yml");
    let global: Option<EngineConfig> = global_path.as_deref().and_then(read_yaml);
    let project: Option<EngineConfig> = project_path.as_deref().and_then(read_yaml);
    match (global, project) {
        (None, None) => EngineConfig::default(),
        (Some(global), None) => global,
        (None, Some(project)) => project,
        (Some(_), Some(project)) if project.project_override => project,
        (Some(global), Some(project)) => EngineConfig {
            allow_values: [global.allow_values, project.allow_values].concat(),
            patterns: [global.patterns, project.patterns].concat(),
            ..global
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fresh (home, project) pair of temp dirs.
    fn temp_home_and_project(tag: &str) -> (PathBuf, PathBuf) {
        let root =
            std::env::temp_dir().join(format!("redacted-config-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let (home, cwd) = (root.join("home"), root.join("proj"));
        fs::create_dir_all(home.join(".config/redacted")).unwrap();
        fs::create_dir_all(&cwd).unwrap();
        (home, cwd)
    }

    #[test]
    fn missing_files_give_defaults() {
        let (home, cwd) = temp_home_and_project("none");
        let config = load(Some(&home), Some(&cwd));
        assert!(
            config.disabled_patterns.is_empty()
                && config.allowed_keys.is_empty()
                && !config.ignore_internal_tools
        );
        assert!(load_engine(Some(&home), Some(&cwd)).patterns.is_empty());
    }

    #[test]
    fn project_merges_over_global() {
        let (home, cwd) = temp_home_and_project("merge");
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
        let config = load(Some(&home), Some(&cwd));
        assert_eq!(config.disabled_patterns, ["jwt"]);
        assert_eq!(config.allowed_keys, ["A", "B"]);
        assert!(config.ignore_internal_tools);
    }

    #[test]
    fn project_override_drops_global() {
        let (home, cwd) = temp_home_and_project("override");
        fs::write(
            home.join(".config/redacted/config.yaml"),
            "whitelist: [jwt]\n",
        )
        .unwrap();
        fs::write(cwd.join(".redacted.yaml"), "override: true\nallow: [B]\n").unwrap();
        let config = load(Some(&home), Some(&cwd));
        assert!(config.disabled_patterns.is_empty());
        assert_eq!(config.allowed_keys, ["B"]);
    }

    #[test]
    fn malformed_file_is_ignored() {
        let (home, cwd) = temp_home_and_project("bad");
        fs::write(
            home.join(".config/redacted/config.yaml"),
            "whitelist: [jwt]\n",
        )
        .unwrap();
        fs::write(cwd.join(".redacted.yaml"), "whitelist: {not: a list}\n").unwrap();
        assert_eq!(load(Some(&home), Some(&cwd)).disabled_patterns, ["jwt"]);
    }

    #[test]
    fn v1_file_loads_with_no_learned_and_heuristic_off() {
        let (home, cwd) = temp_home_and_project("v1");
        fs::write(
            home.join(".config/redacted/config.yaml"),
            "whitelist: [jwt]\n",
        )
        .unwrap();
        let config = load(Some(&home), Some(&cwd));
        assert_eq!(config.version, 0);
        assert!(config.learned.is_empty() && !config.heuristic.enabled);
        assert_eq!(config.disabled_patterns, ["jwt"]);
    }

    const V2: &str = "version: 2\nlearned:\n- {name: stripe_key, sha256: ab12, len: 32, shape: 'x'}\n- {name: db_pass, sha256: cd34, len: 9}\nheuristic: {enabled: true, min_length: 20, max_length: 64, min_char_classes: 2, min_entropy: 3.0}\n";

    #[test]
    fn v2_global_file_loads_learned_and_heuristic() {
        let (home, cwd) = temp_home_and_project("v2");
        fs::write(home.join(".config/redacted/config.yaml"), V2).unwrap();
        let config = load(Some(&home), Some(&cwd));
        assert_eq!(config.version, 2);
        assert_eq!(
            config.learned[0],
            LearnedSecret {
                name: "stripe_key".into(),
                sha256: "ab12".into(),
                byte_len: 32,
                shape: Some("x".into())
            }
        );
        assert_eq!(config.learned[1].shape, None);
        let heuristic = &config.heuristic;
        assert!(heuristic.enabled);
        assert_eq!(heuristic.min_length, 20);
        assert_eq!((heuristic.max_length, heuristic.min_char_classes), (64, 2));
        assert_eq!(heuristic.min_entropy, 3.0);
    }

    #[test]
    fn heuristic_thresholds_default_per_field_and_explicit_values_win() {
        let heuristic: HeuristicConfig = serde_yaml::from_str("{enabled: true}").unwrap();
        assert!(heuristic.enabled);
        let defaults = (
            heuristic.min_length,
            heuristic.max_length,
            heuristic.min_char_classes,
            heuristic.min_entropy,
        );
        assert_eq!(defaults, (16, 128, 3, 3.5));

        let yaml = "{min_length: 20, max_length: 64, min_char_classes: 2, min_entropy: 3.0}";
        let heuristic: HeuristicConfig = serde_yaml::from_str(yaml).unwrap();
        let explicit = (
            heuristic.min_length,
            heuristic.max_length,
            heuristic.min_char_classes,
            heuristic.min_entropy,
        );
        assert_eq!(explicit, (20, 64, 2, 3.0));
    }

    #[test]
    fn learned_and_heuristic_come_from_the_global_file_only() {
        // A committed project file must not carry hashes, and must not drop them via override.
        let (home, cwd) = temp_home_and_project("learned-global");
        fs::write(home.join(".config/redacted/config.yaml"), V2).unwrap();
        let project = "learned: [{name: leak, sha256: ff, len: 2}]\nheuristic: {enabled: false}\n";
        fs::write(cwd.join(".redacted.yaml"), project).unwrap();
        let config = load(Some(&home), Some(&cwd));
        let names: Vec<_> = config.learned.iter().map(|l| l.name.as_str()).collect();
        assert_eq!(names, ["stripe_key", "db_pass"]);
        assert!(config.heuristic.enabled);
        assert_eq!(project_learned_count(&cwd), 1);

        fs::write(
            cwd.join(".redacted.yaml"),
            format!("override: true\n{project}"),
        )
        .unwrap();
        let config = load(Some(&home), Some(&cwd));
        assert_eq!(config.learned.len(), 2);
        assert!(config.heuristic.enabled);

        fs::remove_file(home.join(".config/redacted/config.yaml")).unwrap();
        assert!(load(Some(&home), Some(&cwd)).learned.is_empty());
    }

    #[test]
    fn vendor_only_means_no_learned_entries_and_heuristic_off() {
        let one = LearnedSecret::default();
        let heuristic_on = HeuristicConfig {
            enabled: true,
            ..Default::default()
        };
        assert!(is_vendor_only(&Config::default()));
        assert!(!is_vendor_only(&Config {
            learned: vec![one],
            ..Default::default()
        }));
        assert!(!is_vendor_only(&Config {
            heuristic: heuristic_on,
            ..Default::default()
        }));
        assert!(VENDOR_ONLY_NOTICE.contains("redacted init --env PATH"));
    }

    #[test]
    fn engine_yml_from_0_7_with_keywords_and_heuristic_still_loads() {
        // Upgraders keep their old engine.yml; the retired keys must not drop their patterns.
        let (home, cwd) = temp_home_and_project("engine-v1");
        let old = "heuristic:\n  min_length: 16\n  min_entropy: 3.5\nkeywords:\n  - MONGO\nvalue_safe_char: '[^\\s]'\nallow_values: ['^svc_']\npatterns:\n  - {name: g, regex: 'g_x'}\n";
        fs::write(home.join(".config/redacted/engine.yml"), old).unwrap();
        let engine_config = load_engine(Some(&home), Some(&cwd));
        assert_eq!(engine_config.patterns.len(), 1);
        assert_eq!(engine_config.allow_values, ["^svc_"]);
        let scrubber = crate::scrub::Scrubber::new(&Config::default(), &engine_config).unwrap();
        assert_eq!(scrubber.scrub("MONGO_URI_PART=plainvalue").count, 0);
    }

    #[test]
    fn engine_lists_concatenate_and_project_override_drops_global() {
        let (home, cwd) = temp_home_and_project("engine");
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
        let engine_config = load_engine(Some(&home), Some(&cwd));
        let names: Vec<_> = engine_config
            .patterns
            .iter()
            .map(|p| p.name.as_str())
            .collect();
        assert_eq!(names, ["g", "p"]);
        assert_eq!(engine_config.allow_values, ["^ok"]);

        fs::write(
            cwd.join(".redacted.engine.yml"),
            "override: true\npatterns: [{name: p, regex: 'p_x'}]\n",
        )
        .unwrap();
        assert_eq!(load_engine(Some(&home), Some(&cwd)).patterns.len(), 1);
    }
}
