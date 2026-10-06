//! App policy (config.yaml / .redacted.yaml) and engine overrides
//! (engine.yml / .redacted.engine.yml).

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct Config {
    pub r#override: bool,
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

/// Opt-in entropy tier; zero thresholds fall back to the built-in defaults.
#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub struct Heuristic {
    pub enabled: bool,
    pub min_length: usize,
    pub max_length: usize,
    pub min_char_classes: usize,
    pub min_entropy: f64,
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub struct CustomPattern {
    pub name: String,
    pub regex: String,
}

/// A Go 0.7 engine.yml still loads: serde skips its retired `keywords`,
/// `heuristic` and `value_safe_char` keys like any other unknown key.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct EngineConfig {
    pub r#override: bool,
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
    let mut global: Option<Config> = g.and_then(read);
    let project: Option<Config> = p.and_then(read);
    // Learned hashes and the heuristic are global only, even under a project override.
    let (version, learned, heuristic) = global
        .as_mut()
        .map(|g| {
            (
                g.version,
                std::mem::take(&mut g.learned),
                g.heuristic.clone(),
            )
        })
        .unwrap_or_default();
    let cfg = match (global, project) {
        (None, None) => Config::default(),
        (Some(g), None) => g,
        (None, Some(p)) => p,
        (Some(_), Some(p)) if p.r#override => p,
        (Some(g), Some(p)) => Config {
            whitelist: [g.whitelist, p.whitelist].concat(),
            allow: [g.allow, p.allow].concat(),
            ignore_internal_tools: g.ignore_internal_tools || p.ignore_internal_tools,
            ..Default::default()
        },
    };
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
pub fn project_learned_count(cwd: &str) -> usize {
    let (_, p) = paths("", cwd, "", ".redacted.yaml");
    p.and_then(read::<Config>).map_or(0, |c| c.learned.len())
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
    fn v1_file_loads_with_no_learned_and_heuristic_off() {
        let (home, cwd) = dirs("v1");
        fs::write(
            home.join(".config/redacted/config.yaml"),
            "whitelist: [jwt]\n",
        )
        .unwrap();
        let cfg = load(s(&home), s(&cwd));
        assert_eq!(cfg.version, 0);
        assert!(cfg.learned.is_empty() && !cfg.heuristic.enabled);
        assert_eq!(cfg.whitelist, ["jwt"]);
    }

    const V2: &str = "version: 2\nlearned:\n- {name: stripe_key, sha256: ab12, len: 32, shape: 'x'}\n- {name: db_pass, sha256: cd34, len: 9}\nheuristic: {enabled: true, min_length: 20, max_length: 64, min_char_classes: 2, min_entropy: 3.0}\n";

    #[test]
    fn v2_global_file_loads_learned_and_heuristic() {
        let (home, cwd) = dirs("v2");
        fs::write(home.join(".config/redacted/config.yaml"), V2).unwrap();
        let cfg = load(s(&home), s(&cwd));
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
        assert_eq!(
            (h.min_length, h.max_length, h.min_char_classes),
            (20, 64, 2)
        );
        assert_eq!(h.min_entropy, 3.0);
    }

    #[test]
    fn learned_and_heuristic_come_from_the_global_file_only() {
        // A committed project file must not carry hashes, and must not drop them via override.
        let (home, cwd) = dirs("learned-global");
        fs::write(home.join(".config/redacted/config.yaml"), V2).unwrap();
        let project = "learned: [{name: leak, sha256: ff, len: 2}]\nheuristic: {enabled: false}\n";
        fs::write(cwd.join(".redacted.yaml"), project).unwrap();
        let cfg = load(s(&home), s(&cwd));
        let names: Vec<_> = cfg.learned.iter().map(|l| l.name.as_str()).collect();
        assert_eq!(names, ["stripe_key", "db_pass"]);
        assert!(cfg.heuristic.enabled);
        assert_eq!(project_learned_count(s(&cwd)), 1);

        fs::write(
            cwd.join(".redacted.yaml"),
            format!("override: true\n{project}"),
        )
        .unwrap();
        let cfg = load(s(&home), s(&cwd));
        assert_eq!(cfg.learned.len(), 2);
        assert!(cfg.heuristic.enabled);

        fs::remove_file(home.join(".config/redacted/config.yaml")).unwrap();
        assert!(load(s(&home), s(&cwd)).learned.is_empty());
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
        let eng = load_engine(s(&home), s(&cwd));
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
