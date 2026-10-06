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
    pub whitelist: Vec<String>,
    pub allow: Vec<String>,
    pub ignore_internal_tools: bool,
    pub version: u32,
    pub learned: Vec<Learned>,
    pub heuristic: Heuristic,
}

/// A secret learned by `init`: its hash and byte length, never the value.
#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Learned {
    pub name: String,
    pub sha256: String,
    pub len: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shape: Option<String>,
}

// Built-in heuristic thresholds. The includes_key guards in scrub/skip.rs use
// MIN_CHAR_CLASSES and MIN_ENTROPY as fixed values on purpose, whatever the
// config says, to tell a random segment from an identifier.
pub const MIN_LENGTH: usize = 16;
pub const MAX_LENGTH: usize = 128;
pub const MIN_CHAR_CLASSES: usize = 3;
pub const MIN_ENTROPY: f64 = 3.5;

/// Opt-in entropy tier. Each absent threshold takes its default; an explicit
/// value, zero included, is used as written.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Heuristic {
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
impl Default for Heuristic {
    fn default() -> Self {
        Heuristic {
            enabled: false,
            min_length: MIN_LENGTH,
            max_length: MAX_LENGTH,
            min_char_classes: MIN_CHAR_CLASSES,
            min_entropy: MIN_ENTROPY,
        }
    }
}

fn default_min_length() -> usize {
    MIN_LENGTH
}

fn default_max_length() -> usize {
    MAX_LENGTH
}

fn default_min_char_classes() -> usize {
    MIN_CHAR_CLASSES
}

fn default_min_entropy() -> f64 {
    MIN_ENTROPY
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
fn read<T: serde::de::DeserializeOwned>(path: &Path) -> Option<T> {
    serde_yaml::from_str(&fs::read_to_string(path).ok()?).ok()
}

/// $HOME, or None when it is unset or empty, so no path is built under the cwd.
pub fn home() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .filter(|h| !h.is_empty())
        .map(PathBuf::from)
}

/// ~/.config/redacted/config.yaml, the only file that holds learned secrets.
pub fn global_path(home: &Path) -> PathBuf {
    home.join(".config/redacted/config.yaml")
}

fn paths(
    home: Option<&Path>,
    cwd: Option<&Path>,
    global: &str,
    project: &str,
) -> (Option<PathBuf>, Option<PathBuf>) {
    let g = home.map(|h| h.join(".config/redacted").join(global));
    let p = cwd.map(|c| c.join(project));
    (g, p)
}

/// Global ~/.config/redacted/config.yaml merged with <cwd>/.redacted.yaml;
/// a project `override: true` drops the global file. Unreadable files are skipped.
pub fn load(home: Option<&Path>, cwd: Option<&Path>) -> Config {
    let (g, p) = paths(home, cwd, "config.yaml", ".redacted.yaml");
    // as_deref() lends the PathBuf inside the Option as a `&Path` for `read` to borrow.
    let global: Option<Config> = g.as_deref().and_then(read);
    let project: Option<Config> = p.as_deref().and_then(read);
    // Learned hashes and the heuristic are global only, even under a project override.
    let (version, learned, heuristic) = match &global {
        Some(g) => (g.version, g.learned.clone(), g.heuristic.clone()),
        None => (0, Vec::new(), Heuristic::default()),
    };
    // Matching on the pair covers every combination; `if` guards pick the override case.
    let cfg = match (global, project) {
        (None, None) => Config::default(),
        (Some(g), None) => g,
        (None, Some(p)) => p,
        (Some(_), Some(p)) if p.project_override => p,
        (Some(g), Some(p)) => Config {
            whitelist: [g.whitelist, p.whitelist].concat(),
            allow: [g.allow, p.allow].concat(),
            ignore_internal_tools: g.ignore_internal_tools || p.ignore_internal_tools,
            ..Default::default()
        },
    };
    // Struct update: the three named fields, everything else taken from `cfg`.
    Config {
        version,
        learned,
        heuristic,
        ..cfg
    }
}

pub const VENDOR_ONLY_NOTICE: &str = "vendor signatures only, no learned secrets, heuristic off; run `redacted init --env PATH` to learn yours";

/// Only the vendor tier is active: nothing catches a secret without a known prefix.
pub fn vendor_only(cfg: &Config) -> bool {
    cfg.learned.is_empty() && !cfg.heuristic.enabled
}

/// Learned entries in <cwd>/.redacted.yaml, which `load` ignores; verify warns on them.
pub fn project_learned_count(cwd: &Path) -> usize {
    let project: Option<Config> = read(&cwd.join(".redacted.yaml"));
    project.map_or(0, |c| c.learned.len())
}

/// Global engine.yml merged with <cwd>/.redacted.engine.yml, same override rule.
pub fn load_engine(home: Option<&Path>, cwd: Option<&Path>) -> EngineConfig {
    let (g, p) = paths(home, cwd, "engine.yml", ".redacted.engine.yml");
    let global: Option<EngineConfig> = g.as_deref().and_then(read);
    let project: Option<EngineConfig> = p.as_deref().and_then(read);
    match (global, project) {
        (None, None) => EngineConfig::default(),
        (Some(g), None) => g,
        (None, Some(p)) => p,
        (Some(_), Some(p)) if p.project_override => p,
        (Some(g), Some(p)) => EngineConfig {
            allow_values: [g.allow_values, p.allow_values].concat(),
            patterns: [g.patterns, p.patterns].concat(),
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

    #[test]
    fn missing_files_give_defaults() {
        let (home, cwd) = dirs("none");
        let cfg = load(Some(&home), Some(&cwd));
        assert!(cfg.whitelist.is_empty() && cfg.allow.is_empty() && !cfg.ignore_internal_tools);
        assert!(load_engine(Some(&home), Some(&cwd)).patterns.is_empty());
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
        let cfg = load(Some(&home), Some(&cwd));
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
        let cfg = load(Some(&home), Some(&cwd));
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
        assert_eq!(load(Some(&home), Some(&cwd)).whitelist, ["jwt"]);
    }

    #[test]
    fn v1_file_loads_with_no_learned_and_heuristic_off() {
        let (home, cwd) = dirs("v1");
        fs::write(
            home.join(".config/redacted/config.yaml"),
            "whitelist: [jwt]\n",
        )
        .unwrap();
        let cfg = load(Some(&home), Some(&cwd));
        assert_eq!(cfg.version, 0);
        assert!(cfg.learned.is_empty() && !cfg.heuristic.enabled);
        assert_eq!(cfg.whitelist, ["jwt"]);
    }

    const V2: &str = "version: 2\nlearned:\n- {name: stripe_key, sha256: ab12, len: 32, shape: 'x'}\n- {name: db_pass, sha256: cd34, len: 9}\nheuristic: {enabled: true, min_length: 20, max_length: 64, min_char_classes: 2, min_entropy: 3.0}\n";

    #[test]
    fn v2_global_file_loads_learned_and_heuristic() {
        let (home, cwd) = dirs("v2");
        fs::write(home.join(".config/redacted/config.yaml"), V2).unwrap();
        let cfg = load(Some(&home), Some(&cwd));
        assert_eq!(cfg.version, 2);
        assert_eq!(
            cfg.learned[0],
            Learned {
                name: "stripe_key".into(),
                sha256: "ab12".into(),
                len: 32,
                shape: Some("x".into())
            }
        );
        assert_eq!(cfg.learned[1].shape, None);
        let h = &cfg.heuristic;
        assert!(h.enabled);
        assert_eq!(h.min_length, 20);
        assert_eq!((h.max_length, h.min_char_classes), (64, 2));
        assert_eq!(h.min_entropy, 3.0);
    }

    #[test]
    fn heuristic_thresholds_default_per_field_and_explicit_values_win() {
        let h: Heuristic = serde_yaml::from_str("{enabled: true}").unwrap();
        assert!(h.enabled);
        let defaults = (
            h.min_length,
            h.max_length,
            h.min_char_classes,
            h.min_entropy,
        );
        assert_eq!(defaults, (16, 128, 3, 3.5));

        let yaml = "{min_length: 20, max_length: 64, min_char_classes: 2, min_entropy: 3.0}";
        let h: Heuristic = serde_yaml::from_str(yaml).unwrap();
        let explicit = (
            h.min_length,
            h.max_length,
            h.min_char_classes,
            h.min_entropy,
        );
        assert_eq!(explicit, (20, 64, 2, 3.0));
    }

    #[test]
    fn learned_and_heuristic_come_from_the_global_file_only() {
        // A committed project file must not carry hashes, and must not drop them via override.
        let (home, cwd) = dirs("learned-global");
        fs::write(home.join(".config/redacted/config.yaml"), V2).unwrap();
        let project = "learned: [{name: leak, sha256: ff, len: 2}]\nheuristic: {enabled: false}\n";
        fs::write(cwd.join(".redacted.yaml"), project).unwrap();
        let cfg = load(Some(&home), Some(&cwd));
        let names: Vec<_> = cfg.learned.iter().map(|l| l.name.as_str()).collect();
        assert_eq!(names, ["stripe_key", "db_pass"]);
        assert!(cfg.heuristic.enabled);
        assert_eq!(project_learned_count(&cwd), 1);

        fs::write(
            cwd.join(".redacted.yaml"),
            format!("override: true\n{project}"),
        )
        .unwrap();
        let cfg = load(Some(&home), Some(&cwd));
        assert_eq!(cfg.learned.len(), 2);
        assert!(cfg.heuristic.enabled);

        fs::remove_file(home.join(".config/redacted/config.yaml")).unwrap();
        assert!(load(Some(&home), Some(&cwd)).learned.is_empty());
    }

    #[test]
    fn vendor_only_means_no_learned_entries_and_heuristic_off() {
        let one = Learned::default();
        let heuristic_on = Heuristic {
            enabled: true,
            ..Default::default()
        };
        assert!(vendor_only(&Config::default()));
        assert!(!vendor_only(&Config {
            learned: vec![one],
            ..Default::default()
        }));
        assert!(!vendor_only(&Config {
            heuristic: heuristic_on,
            ..Default::default()
        }));
        assert!(VENDOR_ONLY_NOTICE.contains("redacted init --env PATH"));
    }

    #[test]
    fn engine_yml_from_0_7_with_keywords_and_heuristic_still_loads() {
        // Upgraders keep their old engine.yml; the retired keys must not drop their patterns.
        let (home, cwd) = dirs("engine-v1");
        let old = "heuristic:\n  min_length: 16\n  min_entropy: 3.5\nkeywords:\n  - MONGO\nvalue_safe_char: '[^\\s]'\nallow_values: ['^svc_']\npatterns:\n  - {name: g, regex: 'g_x'}\n";
        fs::write(home.join(".config/redacted/engine.yml"), old).unwrap();
        let eng = load_engine(Some(&home), Some(&cwd));
        assert_eq!(eng.patterns.len(), 1);
        assert_eq!(eng.allow_values, ["^svc_"]);
        let scrubber = crate::scrub::Scrubber::new(&Config::default(), &eng).unwrap();
        assert_eq!(scrubber.scrub("MONGO_URI_PART=plainvalue").count, 0);
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
        let eng = load_engine(Some(&home), Some(&cwd));
        let names: Vec<_> = eng.patterns.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, ["g", "p"]);
        assert_eq!(eng.allow_values, ["^ok"]);

        fs::write(
            cwd.join(".redacted.engine.yml"),
            "override: true\npatterns: [{name: p, regex: 'p_x'}]\n",
        )
        .unwrap();
        assert_eq!(load_engine(Some(&home), Some(&cwd)).patterns.len(), 1);
    }
}
