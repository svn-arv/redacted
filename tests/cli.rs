//! End-to-end checks of the binary: raw-text mode, payload mode, config, stats.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

/// Built at runtime so no secret-shaped literal sits in the source.
fn fake_aws_access_key() -> String {
    format!("AKIA{}", "Q7".repeat(8))
}

fn sandbox(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("redacted-cli-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(dir.join("home/.config/redacted")).unwrap();
    fs::create_dir_all(dir.join("proj")).unwrap();
    dir
}

fn run_redacted(dir: &Path, args: &[&str], stdin: &str) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_redacted"))
        .args(args)
        .current_dir(dir.join("proj"))
        .env("HOME", dir.join("home"))
        .env("REDACTED_STATS_FILE", dir.join("stats.jsonl"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

#[test]
fn raw_mode_scrubs_text_and_reports_on_stderr() {
    let dir = sandbox("raw");
    let output = run_redacted(
        &dir,
        &["scrub"],
        &format!("key {}\n", fake_aws_access_key()),
    );
    assert!(output.status.success());
    assert_eq!(stdout(&output), "key [REDACTED:aws_access_key ...Q7Q7]\n");
    assert_eq!(
        String::from_utf8_lossy(&output.stderr),
        "[redacted] 1 secret(s) scrubbed\n"
    );
    assert!(
        !dir.join("stats.jsonl").exists(),
        "raw mode is manual testing, not a hook run"
    );
}

#[test]
fn raw_mode_passes_clean_text_through_unchanged() {
    let dir = sandbox("clean");
    let input = "{\"SID\"=>\"not json\"}\nplain\r\n";
    let output = run_redacted(&dir, &["scrub"], input);
    assert!(output.status.success());
    assert_eq!(stdout(&output), input);
    assert!(output.stderr.is_empty());
}

#[test]
fn payload_mode_blocks_and_records_stats() {
    let dir = sandbox("payload");
    let payload = format!(
        r#"{{"tool_name":"Bash","tool_response":{{"stdout":"k {}","stderr":""}}}}"#,
        fake_aws_access_key()
    );
    let output = run_redacted(&dir, &["scrub"], &payload);
    assert!(output.status.success());
    assert!(stdout(&output).contains(
        r#""updatedToolOutput":{"stderr":"","stdout":"k [REDACTED:aws_access_key ...Q7Q7]"}"#
    ));
    let stats = fs::read_to_string(dir.join("stats.jsonl")).unwrap();
    assert!(stats.ends_with("\"tool\":\"Bash\",\"by\":{\"aws_access_key\":1}}\n"));

    let output = run_redacted(&dir, &["stats"], "");
    assert_eq!(
        stdout(&output),
        "Redactions: 1 across 1 hook runs\n\nBy pattern:\n  aws_access_key         1\n"
    );
}

#[test]
fn clean_payload_prints_nothing_so_the_original_output_stands() {
    let dir = sandbox("payload-clean");
    let output = run_redacted(
        &dir,
        &["scrub"],
        r#"{"tool_name":"Read","tool_response":"fine"}"#,
    );
    assert!(output.status.success());
    assert!(output.stdout.is_empty());
}

#[test]
fn ignore_internal_tools_from_the_payload_cwd_skips_non_bash() {
    let dir = sandbox("ignore");
    fs::write(
        dir.join("proj/.redacted.yaml"),
        "ignore_internal_tools: true\n",
    )
    .unwrap();
    let cwd = dir.join("proj");
    let payload = format!(
        r#"{{"cwd":{:?},"tool_name":"Read","tool_response":"k {}"}}"#,
        cwd.to_str().unwrap(),
        fake_aws_access_key()
    );
    assert!(run_redacted(&dir, &["scrub"], &payload).stdout.is_empty());
}

#[test]
fn an_empty_or_missing_payload_cwd_never_reads_the_process_cwd_config() {
    // The process runs in proj/, so a cwd read as "" would find this file.
    let dir = sandbox("no-cwd");
    fs::write(
        dir.join("proj/.redacted.yaml"),
        "ignore_internal_tools: true\n",
    )
    .unwrap();
    for cwd in [r#""cwd":"","#, ""] {
        let payload = format!(
            r#"{{{cwd}"tool_name":"Read","tool_response":"k {}"}}"#,
            fake_aws_access_key()
        );
        let out = stdout(&run_redacted(&dir, &["scrub"], &payload));
        assert!(out.contains("[REDACTED:aws_access_key"), "{cwd}: {out}");
    }
}

#[test]
fn ignore_internal_tools_never_skips_a_missing_or_bad_tool_name() {
    let dir = sandbox("ignore-bad");
    fs::write(
        dir.join("home/.config/redacted/config.yaml"),
        "ignore_internal_tools: true\n",
    )
    .unwrap();
    let bad = format!(
        r#"{{"tool_name":5,"tool_response":"k {}"}}"#,
        fake_aws_access_key()
    );
    assert!(stdout(&run_redacted(&dir, &["scrub"], &bad)).contains("tool output withheld"));

    let missing = format!(r#"{{"tool_response":"k {}"}}"#, fake_aws_access_key());
    let out = stdout(&run_redacted(&dir, &["scrub"], &missing));
    assert!(out.contains("[REDACTED:aws_access_key"), "{out}");
    assert!(!out.contains(&fake_aws_access_key()));
}

#[test]
fn bad_user_regex_fails_closed() {
    let dir = sandbox("badregex");
    fs::write(
        dir.join("home/.config/redacted/engine.yml"),
        "patterns: [{name: bad, regex: '('}]\n",
    )
    .unwrap();
    let output = run_redacted(
        &dir,
        &["scrub"],
        r#"{"tool_name":"Read","tool_response":"anything"}"#,
    );
    assert!(
        stdout(&output).contains("tool output withheld"),
        "{}",
        stdout(&output)
    );

    let output = run_redacted(&dir, &["scrub"], "anything");
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
}

#[test]
fn deeply_nested_payload_is_withheld_not_treated_as_text() {
    let dir = sandbox("deep");
    let payload = format!(
        r#"{{"tool_name":"Read","tool_response":{}"k {}"{}}}"#,
        "[".repeat(200),
        fake_aws_access_key(),
        "]".repeat(200)
    );
    assert!(stdout(&run_redacted(&dir, &["scrub"], &payload)).contains("tool output withheld"));
}

#[test]
fn version_flag_prints_the_cargo_version() {
    let dir = sandbox("version");
    let output = run_redacted(&dir, &["--version"], "");
    // The release tag must match Cargo.toml; v1.0.0 is the Rust cutover.
    assert_eq!(stdout(&output), "redacted version 1.0.0\n");
}

#[test]
fn verify_reports_checks_and_fails_without_a_hook() {
    let dir = sandbox("verify");
    // A PostToolUse that is not a list holds no hooks; it is not a JSON error.
    let settings = dir.join("home/.claude/settings.json");
    fs::create_dir_all(settings.parent().unwrap()).unwrap();
    fs::write(&settings, r#"{"hooks":{"PostToolUse":{}}}"#).unwrap();
    let output = run_redacted(&dir, &["verify"], "");
    let out = stdout(&output);
    assert!(!output.status.success());
    let no_hooks = format!(
        "[FAIL] global hook - no PostToolUse hooks in {}, run: redacted init",
        settings.display()
    );
    for line in [
        no_hooks.as_str(),
        "[PASS] binary - ",
        "[FAIL] hook registered",
        "[PASS] config files - none found (using built-in defaults)",
        "[PASS] patterns load - all patterns compiled",
        "[PASS] test scrub - caught 1 secret(s) in test input",
        "[PASS] learned secrets - config version 1, 0 learned, heuristic disabled",
        "[WARN] protection - vendor signatures only, no learned secrets, heuristic off; run `redacted init --env PATH` to learn yours",
        "5 passed, 3 failed",
    ] {
        assert!(out.contains(line), "missing {line:?} in:\n{out}");
    }
}

#[test]
fn verify_summary_says_check_s_failed_in_plain_words() {
    let dir = sandbox("verify-summary");
    let output = run_redacted(&dir, &["verify"], "");
    let err = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1));
    assert!(err.contains("3 check(s) failed"), "{err}");
}

#[test]
fn verify_reports_learned_config_and_warns_on_project_hashes() {
    let dir = sandbox("verify-learned");
    fs::write(
        dir.join("home/.config/redacted/config.yaml"),
        "version: 2\nlearned: [{name: a, sha256: ab, len: 9}, {name: b, sha256: cd, len: 9}]\nheuristic: {enabled: true}\n",
    )
    .unwrap();
    fs::write(
        dir.join("proj/.redacted.yaml"),
        "learned: [{name: c, sha256: ef, len: 9}]\n",
    )
    .unwrap();
    let out = stdout(&run_redacted(&dir, &["verify"], ""));
    assert!(!out.contains("[WARN] protection"), "{out}");
    for line in [
        "[PASS] learned secrets - config version 2, 2 learned, heuristic enabled",
        "[WARN] project learned - .redacted.yaml has 1 learned entry, ignored: learned secrets belong in ~/.config/redacted/config.yaml",
    ] {
        assert!(out.contains(line), "missing {line:?} in:\n{out}");
    }
}

#[test]
fn init_refuses_without_a_terminal_and_writes_nothing() {
    let dir = sandbox("init-notty");
    fs::write(dir.join("proj/.env"), "A=1\n").unwrap();
    let output = run_redacted(&dir, &["init", "--env", ".env", "--local"], "");
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(
        String::from_utf8_lossy(&output.stderr),
        "init needs an interactive terminal\n"
    );
    assert!(!dir.join("home/.config/redacted/config.yaml").exists());
    assert!(!dir.join("proj/.claude").exists());
}

#[test]
fn verify_passes_with_a_registered_hook() {
    let dir = sandbox("verify-ok");
    let bin = env!("CARGO_BIN_EXE_redacted");
    fs::create_dir_all(dir.join("home/.claude")).unwrap();
    fs::write(
        dir.join("home/.claude/settings.json"),
        format!(r#"{{"hooks":{{"PostToolUse":[{{"matcher":"","hooks":[{{"type":"command","command":"{bin} scrub"}}]}}]}}}}"#),
    )
    .unwrap();
    let output = run_redacted(&dir, &["verify"], "");
    let out = stdout(&output);
    assert!(output.status.success(), "{out}");
    assert!(
        out.contains("[PASS] global hook") && out.contains("[SKIP] local hook"),
        "{out}"
    );
}

#[test]
fn uninstall_removes_both_scopes_keeps_config_and_is_idempotent() {
    let dir = sandbox("uninstall");
    let ours = r#"{"hooks":[{"type":"command","command":"/opt/bin/redacted scrub"}]}"#;
    let other = r#"{"hooks":[{"type":"command","command":"/opt/bin/other-hook"}]}"#;
    let global = dir.join("home/.claude/settings.json");
    let local = dir.join("proj/.claude/settings.local.json");
    for (path, entries) in [
        (&global, format!("{ours},{other}")),
        (&local, ours.to_string()),
    ] {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(
            path,
            format!(r#"{{"hooks":{{"PostToolUse":[{entries}]}}}}"#),
        )
        .unwrap();
    }
    let config = dir.join("home/.config/redacted/config.yaml");
    fs::write(&config, "version: 2\n").unwrap();

    let output = run_redacted(&dir, &["uninstall"], "");
    let out = stdout(&output);
    assert!(output.status.success(), "{out}");
    for line in [
        format!("Removed redacted hook from {}", global.display()),
        // current_dir() is canonical (/private/var on macOS).
        format!(
            "Removed redacted hook from {}",
            local
                .parent()
                .unwrap()
                .canonicalize()
                .unwrap()
                .join("settings.local.json")
                .display()
        ),
        format!("Config kept at {}", config.display()),
    ] {
        assert!(out.contains(&line), "missing {line:?} in:\n{out}");
    }
    assert!(fs::read_to_string(&global).unwrap().contains("other-hook"));
    assert!(config.exists());

    let out = stdout(&run_redacted(&dir, &["uninstall"], ""));
    assert!(out.contains("No redacted hooks found."), "{out}");
}

#[test]
fn uninstall_local_leaves_the_global_hook() {
    let dir = sandbox("uninstall-local");
    let settings = r#"{"hooks":{"PostToolUse":[{"hooks":[{"type":"command","command":"/opt/bin/redacted scrub"}]}]}}"#;
    let global = dir.join("home/.claude/settings.json");
    let local = dir.join("proj/.claude/settings.local.json");
    for path in [&global, &local] {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, settings).unwrap();
    }
    let output = run_redacted(&dir, &["uninstall", "--local"], "");
    assert!(output.status.success());
    assert_eq!(fs::read_to_string(&global).unwrap(), settings);
    assert!(
        !fs::read_to_string(&local)
            .unwrap()
            .contains("redacted scrub")
    );
}

const PRE_V2_NOTICE: &str = "[redacted] config is v1: run `redacted init` to learn your secrets.";

fn hook_output(dir: &Path, session: &str, stdout_text: &str) -> serde_json::Value {
    let payload = serde_json::json!({
        "session_id": session,
        "tool_name": "Bash",
        "tool_response": {"stdout": stdout_text, "stderr": ""},
    });
    let output = run_redacted(dir, &["scrub"], &payload.to_string());
    serde_json::from_slice(&output.stdout).unwrap_or(serde_json::Value::Null)
}

fn reason(response: &serde_json::Value) -> &str {
    response["reason"].as_str().unwrap_or("")
}

#[test]
fn v1_config_notice_rides_the_reason_once_per_session() {
    let dir = sandbox("v1-notice");
    fs::write(
        dir.join("home/.config/redacted/config.yaml"),
        "whitelist: [jwt]\nallow: [FOO]\n",
    )
    .unwrap();
    let hit = format!("k {}", fake_aws_access_key());

    // A clean call must not use up the session's one notice.
    assert!(hook_output(&dir, "s1", "clean").is_null());
    let first = hook_output(&dir, "s1", &hit);
    assert!(
        reason(&first).starts_with(&format!("{PRE_V2_NOTICE}\n[redacted] 1 secret(s)")),
        "{first}"
    );
    let updated = first["hookSpecificOutput"]["updatedToolOutput"]["stdout"]
        .as_str()
        .unwrap();
    assert!(!updated.contains("config is v1"), "{updated}");

    let second = hook_output(&dir, "s1", &hit);
    assert!(
        reason(&second).starts_with("[redacted] 1 secret(s)"),
        "{second}"
    );
    assert!(reason(&hook_output(&dir, "s2", &hit)).starts_with(PRE_V2_NOTICE));
}

#[test]
fn an_empty_home_never_reads_config_under_the_working_directory() {
    // HOME="" once turned ~/.config/redacted/config.yaml into a path under the cwd.
    let dir = sandbox("no-home");
    fs::create_dir_all(dir.join("proj/.config/redacted")).unwrap();
    fs::write(
        dir.join("proj/.config/redacted/config.yaml"),
        "allow: [FOO]\n",
    )
    .unwrap();
    let payload = serde_json::json!({
        "tool_name": "Bash",
        "tool_response": {"stdout": format!("k {}", fake_aws_access_key()), "stderr": ""},
    });
    let mut child = Command::new(env!("CARGO_BIN_EXE_redacted"))
        .arg("scrub")
        .current_dir(dir.join("proj"))
        .env("HOME", "")
        .env("REDACTED_STATS_FILE", dir.join("stats.jsonl"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(payload.to_string().as_bytes()).unwrap();
    drop(stdin);
    let out: serde_json::Value =
        serde_json::from_slice(&child.wait_with_output().unwrap().stdout).unwrap();
    assert!(reason(&out).starts_with("[redacted] 1 secret(s)"), "{out}");
}

#[test]
fn v2_config_or_no_config_never_carries_the_notice() {
    let dir = sandbox("v2-notice");
    let hit = format!("k {}", fake_aws_access_key());
    let none = hook_output(&dir, "s1", &hit);
    assert!(
        reason(&none).starts_with("[redacted] 1 secret(s)"),
        "{none}"
    );

    fs::write(
        dir.join("home/.config/redacted/config.yaml"),
        "version: 2\n",
    )
    .unwrap();
    let v2 = hook_output(&dir, "s2", &hit);
    assert!(reason(&v2).starts_with("[redacted] 1 secret(s)"), "{v2}");
}
