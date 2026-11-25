//! Unit tests for `redacted init`.

use super::*;
use crate::config::LearnedSecret;
use std::fs;
use std::path::PathBuf;

fn fresh_temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("redacted-init-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn parse_dotenv_handles_export_quotes_and_comments() {
    let text = "# comment\n\nexport A=1\nB = \"two words\" # trailing\nC='single'\nD=bare # note\nEMPTY=\nQUOTED_EMPTY=\"\"\nnot a pair\n  E=x=y\n";
    let got = parse_dotenv(text);
    let want: Vec<(String, String)> = [
        ("A", "1"),
        ("B", "two words"),
        ("C", "single"),
        ("D", "bare"),
        ("E", "x=y"),
    ]
    .iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect();
    assert_eq!(got, want);
}

#[test]
fn parse_dotenv_keeps_commented_out_assignments_because_they_leak_too() {
    let text = "# OLD_KEY=abc12345XYZ\n#export TOKEN='t0k3n-value'\n## DOUBLE=hash-hash\n# set your key here\n# a note with = sign in prose\n";
    let got = parse_dotenv(text);
    let want: Vec<(String, String)> = [
        ("OLD_KEY", "abc12345XYZ"),
        ("TOKEN", "t0k3n-value"),
        ("DOUBLE", "hash-hash"),
    ]
    .iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect();
    assert_eq!(got, want);
}

#[test]
fn url_password_reads_the_password_from_the_userinfo() {
    for (value, want) in [
        (
            "postgres://admin:Tr0ub4dor-99@db.example.com/prod",
            Some("Tr0ub4dor-99"),
        ),
        ("postgres://db.example.com:5432/prod", None),
        ("postgres://admin@db.example.com/prod", None),
        ("postgres://admin:@db.example.com/prod", None),
        ("redis://:P%40ss%2Fw0rd@cache:6379", Some("P@ss/w0rd")),
        ("postgres://admin:p@ss@db.example.com/prod", Some("p@ss")),
        ("postgres://host:5432?opt=a@b", None),
        ("not a url user:pw@host", None),
        ("sk_live_Ab1Ab1Ab1", None),
    ] {
        assert_eq!(url_password(value).as_deref(), want, "{value}");
    }
}

#[test]
fn url_password_keeps_an_encoding_that_is_not_utf8() {
    assert_eq!(
        url_password("postgres://u:Pw%FFxyz12@h/db").as_deref(),
        Some("Pw%FFxyz12")
    );
}

#[test]
fn with_url_passwords_puts_the_password_right_after_its_url() {
    let pairs: Vec<(String, String)> = [
        ("DATABASE_URL", "postgres://admin:Tr0ub4dor-99@db/prod"),
        ("PORT", "3000"),
    ]
    .iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect();
    let keys: Vec<String> = with_url_passwords(pairs.clone())
        .into_iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect();
    assert_eq!(
        keys,
        [
            "DATABASE_URL=postgres://admin:Tr0ub4dor-99@db/prod",
            "DATABASE_URL_PASSWORD=Tr0ub4dor-99",
            "PORT=3000",
        ]
    );
    let learned = learn("DATABASE_URL_PASSWORD", "Tr0ub4dor-99").unwrap();
    assert_eq!(learned.name, "database_url_password");
}

#[test]
fn find_env_files_skips_examples_and_sorts() {
    let dir = fresh_temp_dir("find");
    for name in [
        ".env",
        ".env.local",
        ".env.example",
        ".env.sample",
        ".env.template",
        "env",
        "README",
    ] {
        fs::write(dir.join(name), "A=1\n").unwrap();
    }
    fs::create_dir_all(dir.join(".env.d")).unwrap();
    let names: Vec<_> = find_env_files(&dir)
        .iter()
        .map(|p| p.file_name().unwrap().to_str().unwrap().to_string())
        .collect();
    assert_eq!(names, [".env", ".env.local"]);
}

#[test]
fn only_values_with_two_character_classes_are_preselected() {
    // Listed in the picker, just not ticked by default.
    assert!(learn("NODE_ENV", "development").is_ok());
    let hex = "9f86d081884c7d659a2feaa0c55ad015";
    for (v, want) in [
        ("development", false),
        ("DEVELOPMENT", false),
        ("2024010112", false),
        ("P@ssw0rd2024", true),
        (hex, true),
    ] {
        assert_eq!(
            should_preselect(&learn("K", v).unwrap(), v, &[]),
            want,
            "{v}"
        );
    }
}

// A value with one character class: ticked only because the config knows it.
const WEAK_VALUE: &str = "developmentdb";

#[test]
fn a_value_already_in_the_config_is_ticked_and_says_learned() {
    let entry = learn("DB_PASSWORD", WEAK_VALUE).unwrap();
    let known = [entry.clone()];
    let row = picker_row("DB_PASSWORD", WEAK_VALUE, &Ok(entry.clone()), &known);
    assert_eq!(row, "DB_PASSWORD  learned");
    assert!(should_preselect(&entry, WEAK_VALUE, &known));
}

#[test]
fn the_same_value_under_another_key_names_the_entry_that_already_redacts_it() {
    let known = [learn("DB_PASSWORD", WEAK_VALUE).unwrap()];
    let entry = learn("REDIS_PASSWORD", WEAK_VALUE).unwrap();
    let row = picker_row("REDIS_PASSWORD", WEAK_VALUE, &Ok(entry.clone()), &known);
    assert_eq!(row, "REDIS_PASSWORD  learned as db_password");
    assert!(should_preselect(&entry, WEAK_VALUE, &known));
}

#[test]
fn a_changed_value_shows_the_suffixed_name_it_will_be_written_under() {
    let known = [learn("DB_PASSWORD", "old-Value-123").unwrap()];
    let entry = learn("DB_PASSWORD", WEAK_VALUE).unwrap();
    let row = picker_row("DB_PASSWORD", WEAK_VALUE, &Ok(entry.clone()), &known);
    assert_eq!(row, "DB_PASSWORD  new value, kept as db_password_2");
    assert!(should_preselect(&entry, WEAK_VALUE, &known));
    // The label shown is the label written.
    let existing = format!(
        "learned:\n- {{name: db_password, sha256: {}, len: 13}}\n",
        known[0].sha256
    );
    let names = learned_names_after_merge(&existing, &[entry]);
    assert_eq!(names, ["db_password", "db_password_2"]);
}

#[test]
fn without_a_config_rows_and_ticks_are_as_before() {
    let entry = learn("DB_PASSWORD", WEAK_VALUE).unwrap();
    let row = picker_row("DB_PASSWORD", WEAK_VALUE, &Ok(entry.clone()), &[]);
    assert!(!row.contains("learned"), "{row}");
    assert!(!should_preselect(&entry, WEAK_VALUE, &[]));
}

#[test]
fn picker_row_shows_key_and_hint_never_the_prefix_or_value() {
    let value = "Kopi-Susu-2026-x9";
    let row = picker_row("DB_PASS", value, &learn("DB_PASS", value), &[]);
    assert_eq!(row, "DB_PASS  ...6-x9");
    let short = picker_row("PIN", "Pw9xQz7k", &learn("PIN", "Pw9xQz7k"), &[]);
    assert_eq!(short, "PIN  (short)");
}

#[test]
fn rotated_key_row_shows_the_exact_prefix_a_shape_would_store() {
    let value = "Kopi-Susu-2026-x9";
    assert_eq!(
        rotated_key_row("DB_PASS", value).as_deref(),
        Some(r#"DB_PASS  stores "Kopi-Susu-" in plain text"#)
    );
    assert_eq!(rotated_key_row("DB_PASS", "Pw9xQz7k"), None);
}

#[test]
fn merge_learned_into_config_keeps_other_fields_and_every_learned_value() {
    let existing = "whitelist: [jwt]\nfuture_field: {a: 1}\nlearned:\n- {name: keep, sha256: aa, len: 1}\n- {name: stripe_key, sha256: old, len: 1}\n";
    let new = LearnedSecret {
        name: "stripe_key".into(),
        sha256: "new".into(),
        byte_len: 32,
        shape: Some("s".into()),
    };
    let added = LearnedSecret {
        name: "db_pass".into(),
        sha256: "bb".into(),
        byte_len: 9,
        shape: None,
    };
    let out = merge_learned_into_config(existing, &[new.clone(), added.clone()]).unwrap();
    let doc: serde_yaml::Value = serde_yaml::from_str(&out).unwrap();
    assert_eq!(doc["version"], serde_yaml::Value::from(2));
    assert_eq!(doc["whitelist"][0], serde_yaml::Value::from("jwt"));
    assert_eq!(doc["future_field"]["a"], serde_yaml::Value::from(1));
    let learned: Vec<LearnedSecret> = serde_yaml::from_value(doc["learned"].clone()).unwrap();
    let names: Vec<_> = learned.iter().map(|entry| entry.name.as_str()).collect();
    assert_eq!(names, ["keep", "stripe_key", "stripe_key_2", "db_pass"]);
    assert_eq!(learned[1].sha256, "old");
    assert_eq!(
        learned[2],
        LearnedSecret {
            name: "stripe_key_2".into(),
            ..new
        }
    );
    assert!(
        !out.contains("shape: null"),
        "absent shape is omitted:\n{out}"
    );

    assert!(
        merge_learned_into_config("", &[added])
            .unwrap()
            .starts_with("version: 2\n")
    );
}

fn learned_names_after_merge(existing: &str, entries: &[LearnedSecret]) -> Vec<String> {
    let out = merge_learned_into_config(existing, entries).unwrap();
    let doc: serde_yaml::Value = serde_yaml::from_str(&out).unwrap();
    let learned: Vec<LearnedSecret> = serde_yaml::from_value(doc["learned"].clone()).unwrap();
    learned.into_iter().map(|entry| entry.name).collect()
}

fn db_password(sha256: &str) -> LearnedSecret {
    LearnedSecret {
        name: "db_password".into(),
        sha256: sha256.into(),
        byte_len: 12,
        shape: None,
    }
}

#[test]
fn two_values_under_one_name_both_stay_redacted() {
    // DB_PASSWORD in .env and in .env.production: dropping either leaks it.
    let names = learned_names_after_merge("", &[db_password("aa"), db_password("bb")]);
    assert_eq!(names, ["db_password", "db_password_2"]);
}

#[test]
fn a_suffix_never_takes_a_name_the_user_already_chose() {
    let existing = "learned:\n- {name: db_password, sha256: aa, len: 12}\n- {name: db_password_2, sha256: hand, len: 12}\n";
    let names = learned_names_after_merge(existing, &[db_password("cc")]);
    assert_eq!(names, ["db_password", "db_password_2", "db_password_3"]);
}

#[test]
fn rerunning_init_on_an_already_suffixed_value_adds_nothing() {
    // A value already in the file is never added again, so re-runs pile up no copies.
    let existing = "learned:\n- {name: db_password, sha256: aa, len: 12}\n- {name: db_password_2, sha256: bb, len: 12}\n";
    let names = learned_names_after_merge(existing, &[db_password("aa"), db_password("bb")]);
    assert_eq!(names, ["db_password", "db_password_2"]);
}

#[test]
fn a_value_already_learned_under_another_key_adds_nothing() {
    // The scrubber carries one label per value, so a second name would be dead data.
    let redis_password = LearnedSecret {
        name: "redis_password".into(),
        ..db_password("aa")
    };
    let existing = "learned:\n- {name: db_password, sha256: aa, len: 12}\n";
    let names = learned_names_after_merge(existing, &[redis_password]);
    assert_eq!(names, ["db_password"]);
}

#[test]
fn merge_learned_into_config_rejects_a_non_mapping() {
    // Rewriting a list or scalar as a mapping would drop what the user wrote.
    assert!(merge_learned_into_config("[not, a, map]", &[]).is_err());
}

#[cfg(unix)]
#[test]
fn write_config_is_owner_only_even_over_an_existing_file() {
    use std::os::unix::fs::PermissionsExt;
    let dir = fresh_temp_dir("write");
    let path = dir.join("nested/config.yaml");
    write_config(&path, "a: 1\n").unwrap();
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    write_config(&path, "a: 2\n").unwrap();
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(fs::read_to_string(&path).unwrap(), "a: 2\n");
}

#[test]
fn this_executable_path_is_not_a_path_lookup() {
    // A writable PATH directory must not get its own binary registered as the hook.
    // Not canonicalized: a Homebrew symlink must stay, its Cellar target goes on upgrade.
    let want = std::path::absolute(std::env::current_exe().unwrap()).unwrap();
    assert_eq!(this_executable_path().unwrap(), want.display().to_string());
}

#[test]
fn install_stops_on_a_malformed_config_before_writing_settings_so_no_hook_withholds_every_output() {
    let home = fresh_temp_dir("install-bad-config");
    let config_path = config::global_config_path(&home);
    fs::create_dir_all(config_path.parent().unwrap()).unwrap();
    fs::write(&config_path, "learned: [\n").unwrap();
    let error = install(Format::Claude, false, &home, &home).unwrap_err();
    assert!(
        error.starts_with(&format!("{}: ", config_path.display())),
        "{error}"
    );
    assert!(!home.join(".claude/settings.json").exists());
}

#[test]
fn install_for_opencode_writes_the_plugin_in_either_scope_and_never_touches_claude_settings() {
    let dir = fresh_temp_dir("install-opencode");
    let (home, cwd) = (dir.join("home"), dir.join("proj"));
    install(Format::Opencode, false, &cwd, &home).unwrap();
    install(Format::Opencode, true, &cwd, &home).unwrap();
    for plugin in [
        home.join(".config/opencode/plugins/redacted.ts"),
        cwd.join(".opencode/plugins/redacted.ts"),
    ] {
        let written = fs::read_to_string(&plugin).unwrap();
        assert!(
            written.starts_with(opencode::PLUGIN_MARKER),
            "{}",
            plugin.display()
        );
    }
    assert!(!home.join(".claude").exists() && !cwd.join(".claude").exists());
}

#[test]
fn install_for_opencode_pins_this_binary_so_a_writable_path_directory_cannot_swap_the_scrubber() {
    let dir = fresh_temp_dir("install-opencode-pinned");
    let (home, cwd) = (dir.join("home"), dir.join("proj"));
    install(Format::Opencode, false, &cwd, &home).unwrap();
    let written = fs::read_to_string(home.join(".config/opencode/plugins/redacted.ts")).unwrap();
    let pinned = serde_json::Value::from(this_executable_path().unwrap()).to_string();
    assert!(
        written.contains(&format!("process.env.REDACTED_BIN || {pinned}")),
        "REDACTED_BIN still overrides the pinned path:\n{written}"
    );
    assert!(!written.contains(r#"|| "redacted""#), "{written}");
}
