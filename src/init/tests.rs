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
fn derive_shape_needs_a_short_separated_prefix() {
    let stripe = format!("sk_live_{}", "Ab1".repeat(8));
    let gh = format!("ghp_{}", "aB3".repeat(12));
    let slack = format!("xoxb-{}-{}", "1".repeat(12), "2".repeat(12));
    // Built at runtime so no secret-shaped literal sits in the source.
    let hubspot = format!(
        "pat-na1-{}-{}",
        "0a1b-".repeat(4).trim_end_matches('-'),
        "0a1b2c3d4e5f"
    );
    let aws = format!("AKIA{}", "Q7".repeat(8));
    let lang = format!("lsv2_pt_{}", "Zz9".repeat(10));
    for (sample, want) in [
        (stripe.as_str(), Some(r"\bsk_live_[a-zA-Z0-9]{20,28}\b")),
        (&gh, Some(r"\bghp_[a-zA-Z0-9]{32,40}\b")),
        (&slack, Some(r"\bxoxb\-[0-9-]{21,29}\b")),
        (&hubspot, Some(r"\bpat\-na1\-[a-z0-9-]{28,36}\b")),
        (&lang, Some(r"\blsv2_pt_[a-zA-Z0-9]{26,34}\b")),
        ("abc_xy", Some(r"\babc_[a-z]{1,6}\b")),
        // No separator: exact hash only (AKIA keys land here).
        (&aws, None),
        // Separator past the 12th character.
        ("abcdefghijklm_nopqrstu", None),
        // Prefix shorter than 3 characters.
        ("a_bcdefghijk", None),
        // Characters outside the shape charset: a band would match a truncated prefix.
        ("key_abc/def+ghi=", None),
        ("abc_", None),
    ] {
        assert_eq!(derive_shape(sample).as_deref(), want, "{sample}");
    }
}

#[test]
fn derived_shapes_compile_and_match_their_sample() {
    let sample = format!("pat-na1-{}", "0a1b2c3d-".repeat(4));
    let shape = derive_shape(sample.trim_end_matches('-')).unwrap();
    let re = regex::Regex::new(&shape).unwrap();
    assert!(re.is_match(sample.trim_end_matches('-')));
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
fn learn_hashes_the_value_and_lowercases_the_name() {
    let value = format!("sk_live_{}", "Ab1".repeat(8));
    let learned = learn("STRIPE_KEY", &value).unwrap();
    assert_eq!(learned.name, "stripe_key");
    assert_eq!(learned.sha256, crate::scrub::sha256_hex(&value));
    assert_eq!(learned.byte_len, value.len());
    assert_eq!(learned.shape, derive_shape(&value));
}

#[test]
fn learn_rejects_values_under_eight_characters() {
    // Learned values redact everywhere, so `PORT=3000` would hide every 3000 in output.
    for v in ["3000", "true", "Pw9xQz7"] {
        assert_eq!(learn("K", v).unwrap_err(), "too short", "{v}");
    }
    assert!(learn("K", "Pw9xQz7k").is_ok());
    assert!(picker_row("PORT", "3000", &learn("PORT", "3000"), &[]).contains("too short"));
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

#[test]
fn learn_rejects_a_value_with_spaces() {
    // Candidates never span whitespace, so such a value could never be redacted.
    assert_eq!(
        learn("GREETING", "hello there world").unwrap_err(),
        "cannot match (contains spaces)"
    );
    let row = picker_row(
        "GREETING",
        "hello there world",
        &learn("GREETING", "hello there world"),
        &[],
    );
    assert!(
        row.contains("cannot match (contains spaces)") && !row.contains("hello"),
        "{row}"
    );
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
    assert!(
        !row.contains("learned") && row.contains("exact only"),
        "{row}"
    );
    assert!(!should_preselect(&entry, WEAK_VALUE, &[]));
}

#[test]
fn picker_row_shows_key_hint_and_shape_never_the_value() {
    let value = format!("sk_live_{}", "Ab1".repeat(8));
    let row = picker_row("STRIPE_KEY", &value, &learn("STRIPE_KEY", &value), &[]);
    assert!(
        row.contains("STRIPE_KEY") && row.contains("...",) && row.contains("Ab1"),
        "{row}"
    );
    assert!(
        row.contains(r"\bsk_live_") && !row.contains(&value),
        "{row}"
    );
    let short = picker_row("PIN", "Pw9xQz7k", &learn("PIN", "Pw9xQz7k"), &[]);
    assert!(
        short.contains("exact only") && !short.contains("Qz7k"),
        "{short}"
    );
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
        assert_eq!(
            fs::read_to_string(&plugin).unwrap(),
            opencode::PLUGIN_SOURCE,
            "{}",
            plugin.display()
        );
    }
    assert!(!home.join(".claude").exists() && !cwd.join(".claude").exists());
}
