//! End-to-end checks of the binary: raw-text mode, payload mode, config, stats.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

/// Built at runtime so no secret-shaped literal sits in the source.
fn aws_key() -> String {
    format!("AKIA{}", "Q7".repeat(8))
}

fn sandbox(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("redacted-cli-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(dir.join("home/.config/redacted")).unwrap();
    fs::create_dir_all(dir.join("proj")).unwrap();
    dir
}

fn run(dir: &Path, args: &[&str], stdin: &str) -> Output {
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

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

#[test]
fn raw_mode_scrubs_text_and_reports_on_stderr() {
    let dir = sandbox("raw");
    let o = run(&dir, &["scrub"], &format!("key {}\n", aws_key()));
    assert!(o.status.success());
    assert_eq!(stdout(&o), "key [REDACTED:aws_access_key ...Q7Q7]\n");
    assert_eq!(
        String::from_utf8_lossy(&o.stderr),
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
    let o = run(&dir, &["scrub"], input);
    assert!(o.status.success());
    assert_eq!(stdout(&o), input);
    assert!(o.stderr.is_empty());
}

#[test]
fn payload_mode_blocks_and_records_stats() {
    let dir = sandbox("payload");
    let payload = format!(
        r#"{{"tool_name":"Bash","tool_response":{{"stdout":"k {}","stderr":""}}}}"#,
        aws_key()
    );
    let o = run(&dir, &["scrub"], &payload);
    assert!(o.status.success());
    assert!(stdout(&o).contains(r#""updatedToolOutput":"k [REDACTED:aws_access_key ...Q7Q7]""#));
    let stats = fs::read_to_string(dir.join("stats.jsonl")).unwrap();
    assert!(stats.ends_with("\"tool\":\"Bash\",\"by\":{\"aws_access_key\":1}}\n"));

    let o = run(&dir, &["stats"], "");
    assert_eq!(
        stdout(&o),
        "Redactions: 1 across 1 hook runs\n\nBy pattern:\n  aws_access_key         1\n"
    );
}

#[test]
fn payload_clean_writes_nothing() {
    let dir = sandbox("payload-clean");
    let o = run(
        &dir,
        &["scrub"],
        r#"{"tool_name":"Read","tool_response":"fine"}"#,
    );
    assert!(o.status.success());
    assert!(o.stdout.is_empty());
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
        aws_key()
    );
    assert!(run(&dir, &["scrub"], &payload).stdout.is_empty());
}

#[test]
fn ignore_internal_tools_never_skips_a_missing_or_bad_tool_name() {
    let dir = sandbox("ignore-bad");
    fs::write(
        dir.join("home/.config/redacted/config.yaml"),
        "ignore_internal_tools: true\n",
    )
    .unwrap();
    let bad = format!(r#"{{"tool_name":5,"tool_response":"k {}"}}"#, aws_key());
    assert!(stdout(&run(&dir, &["scrub"], &bad)).contains("tool output withheld"));

    let missing = format!(r#"{{"tool_response":"k {}"}}"#, aws_key());
    let out = stdout(&run(&dir, &["scrub"], &missing));
    assert!(out.contains("[REDACTED:aws_access_key"), "{out}");
    assert!(!out.contains(&aws_key()));
}

#[test]
fn bad_user_regex_fails_closed() {
    let dir = sandbox("badregex");
    fs::write(
        dir.join("home/.config/redacted/engine.yml"),
        "patterns: [{name: bad, regex: '('}]\n",
    )
    .unwrap();
    let o = run(
        &dir,
        &["scrub"],
        r#"{"tool_name":"Read","tool_response":"anything"}"#,
    );
    assert!(
        stdout(&o).contains("tool output withheld"),
        "{}",
        stdout(&o)
    );

    let o = run(&dir, &["scrub"], "anything");
    assert!(!o.status.success());
    assert!(o.stdout.is_empty());
}

#[test]
fn deeply_nested_payload_is_withheld_not_treated_as_text() {
    let dir = sandbox("deep");
    let payload = format!(
        r#"{{"tool_name":"Read","tool_response":{}"k {}"{}}}"#,
        "[".repeat(200),
        aws_key(),
        "]".repeat(200)
    );
    assert!(stdout(&run(&dir, &["scrub"], &payload)).contains("tool output withheld"));
}

#[test]
fn version_matches_cobra_format() {
    let dir = sandbox("version");
    let o = run(&dir, &["--version"], "");
    assert_eq!(
        stdout(&o),
        format!("redacted version {}\n", env!("CARGO_PKG_VERSION"))
    );
}

#[test]
fn verify_reports_checks_and_fails_without_a_hook() {
    let dir = sandbox("verify");
    let o = run(&dir, &["verify"], "");
    let out = stdout(&o);
    assert!(!o.status.success());
    for line in [
        "[PASS] binary in PATH",
        "[FAIL] hook registered",
        "[PASS] config files - none found (using built-in defaults)",
        "[PASS] patterns load - all patterns compiled",
        "[PASS] test scrub - caught 1 secret(s) in test input",
        "[PASS] learned secrets - config version 1, 0 learned, heuristic disabled",
        "5 passed, 3 failed",
    ] {
        assert!(out.contains(line), "missing {line:?} in:\n{out}");
    }
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
    let out = stdout(&run(&dir, &["verify"], ""));
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
    let o = run(&dir, &["init", "--env", ".env", "--local"], "");
    assert_eq!(o.status.code(), Some(1));
    assert_eq!(
        String::from_utf8_lossy(&o.stderr),
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
    let o = run(&dir, &["verify"], "");
    let out = stdout(&o);
    assert!(o.status.success(), "{out}");
    assert!(
        out.contains("[PASS] global hook") && out.contains("[SKIP] local hook"),
        "{out}"
    );
}
