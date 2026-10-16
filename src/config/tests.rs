//! Unit tests for config loading and merging.

use super::*;

/// A fresh (home, project) pair of temp dirs.
fn temp_home_and_project(tag: &str) -> (PathBuf, PathBuf) {
    let root = std::env::temp_dir().join(format!("redacted-config-{tag}-{}", std::process::id()));
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
fn pii_toggles_are_off_unless_the_global_file_turns_each_one_on() {
    // A committed project file must not switch PII scrubbing on or off for everyone.
    let (home, cwd) = temp_home_and_project("pii-global");
    let config = load(Some(&home), Some(&cwd));
    assert!(!config.pii.email && !config.pii.phone);

    fs::write(
        home.join(".config/redacted/config.yaml"),
        "pii: {email: true}\n",
    )
    .unwrap();
    fs::write(
        cwd.join(".redacted.yaml"),
        "pii: {email: false, phone: true}\n",
    )
    .unwrap();
    let config = load(Some(&home), Some(&cwd));
    assert!(config.pii.email && !config.pii.phone);
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
