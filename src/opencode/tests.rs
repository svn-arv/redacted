//! Unit tests for the OpenCode `tool.execute.after` contract.

use super::*;
use crate::config::ConfigError;
use crate::fake_secrets;

/// Runs `payload` through `respond` with default config and returns stdout as JSON.
fn respond_with(config: Config, payload: &str) -> (Value, BTreeMap<String, usize>) {
    let (out, counts) = respond(payload.as_bytes(), Ok((config, EngineConfig::default())));
    let printed = String::from_utf8(out).unwrap();
    assert!(
        printed.ends_with('\n'),
        "one JSON value per line: {printed}"
    );
    (serde_json::from_str(&printed).unwrap(), counts)
}

fn aws_key_and_marker() -> (String, String) {
    let key = fake_secrets::aws_access_key();
    let marker = format!(
        "[REDACTED:aws_access_key ...{}]",
        fake_secrets::last_four_chars(&key)
    );
    (key, marker)
}

#[test]
fn a_built_in_tool_output_comes_back_whole_with_the_secret_replaced_because_the_plugin_swaps_in_every_key()
 {
    let (key, marker) = aws_key_and_marker();
    let payload = serde_json::json!({
        "tool": "bash", "sessionID": "s1", "callID": "c1", "args": {"command": "env"},
        "output": {"title": "env", "output": format!("k {key}"), "metadata": {"exit": 0}},
    });
    let (printed, counts) = respond_with(Config::default(), &payload.to_string());
    let expected = serde_json::json!({
        "title": "env", "output": format!("k {marker}"), "metadata": {"exit": 0},
    });
    assert_eq!(printed, expected);
    assert_eq!(counts, BTreeMap::from([("aws_access_key".to_string(), 1)]));
}

#[test]
fn every_string_in_a_raw_mcp_result_is_scrubbed_because_opencode_passes_it_to_the_model_as_is() {
    let (key, marker) = aws_key_and_marker();
    let payload = serde_json::json!({
        "tool": "github_get_file", "sessionID": "s1", "callID": "c1", "args": {},
        "output": {"content": [
            {"type": "text", "text": format!("a {key}")},
            {"type": "resource", "resource": {"uri": "file:///x", "text": format!("b {key}")}},
        ], "isError": false},
    });
    let (printed, counts) = respond_with(Config::default(), &payload.to_string());
    let expected = serde_json::json!({"content": [
        {"type": "text", "text": format!("a {marker}")},
        {"type": "resource", "resource": {"uri": "file:///x", "text": format!("b {marker}")}},
    ], "isError": false});
    assert_eq!(printed, expected);
    assert_eq!(counts, BTreeMap::from([("aws_access_key".to_string(), 2)]));
}

#[test]
fn clean_output_is_printed_unchanged_because_the_plugin_always_replaces_what_it_reads() {
    let output = serde_json::json!({"title": "ls", "output": "a.txt\nb.txt", "metadata": {}});
    let payload = serde_json::json!({"tool": "bash", "output": output});
    let (printed, counts) = respond_with(Config::default(), &payload.to_string());
    assert_eq!(printed, output);
    assert!(counts.is_empty());
}

#[test]
fn ignore_internal_tools_passes_a_non_bash_tool_through_but_still_scrubs_bash() {
    let (key, marker) = aws_key_and_marker();
    let ignoring_internal_tools = || Config {
        ignore_internal_tools: true,
        ..Config::default()
    };
    let read = serde_json::json!({"tool": "read", "output": {"output": format!("k {key}")}});
    let (printed, counts) = respond_with(ignoring_internal_tools(), &read.to_string());
    assert_eq!(printed, read["output"]);
    assert!(
        counts.is_empty(),
        "nothing was scrubbed, so nothing is recorded"
    );

    let bash = serde_json::json!({"tool": "bash", "output": {"output": format!("k {key}")}});
    let (printed, _) = respond_with(ignoring_internal_tools(), &bash.to_string());
    assert_eq!(printed["output"], format!("k {marker}"));
}

#[test]
fn input_that_is_not_a_payload_with_output_gets_the_bare_withheld_notice_so_nothing_raw_leaks() {
    let (key, _) = aws_key_and_marker();
    let notice = Value::String(WITHHELD.to_string());
    for payload in [
        format!("not json {key}"),
        format!(r#"["{key}"]"#),
        format!(r#"{{"tool":"bash","args":"{key}"}}"#),
        r#"{"tool":"bash","output":null}"#.to_string(),
    ] {
        let (printed, counts) = respond_with(Config::default(), &payload);
        assert_eq!(printed, notice, "{payload}");
        assert!(counts.is_empty());
    }
}

#[test]
fn a_config_that_does_not_parse_withholds_every_string_but_keeps_the_shape_the_plugin_swaps_in() {
    let payload =
        r#"{"tool":"read","output":{"title":"t","output":"clean","metadata":{"lines":3}}}"#;
    let error = ConfigError {
        path: "/home/u/.config/redacted/config.yaml".into(),
        message: "bad".into(),
    };
    let (out, counts) = respond(payload.as_bytes(), Err(error));
    let printed: Value = serde_json::from_slice(&out).unwrap();
    let expected =
        serde_json::json!({"title": WITHHELD, "output": WITHHELD, "metadata": {"lines": 3}});
    assert_eq!(printed, expected);
    assert!(counts.is_empty());
}

#[test]
fn a_user_pattern_that_does_not_compile_withholds_instead_of_scrubbing_on_fewer_patterns() {
    let engine_config: EngineConfig =
        serde_yaml::from_str("patterns: [{name: bad, regex: '('}]").unwrap();
    let payload = r#"{"tool":"bash","output":{"output":"clean"}}"#;
    let (out, _) = respond(payload.as_bytes(), Ok((Config::default(), engine_config)));
    let printed: Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(printed, serde_json::json!({"output": WITHHELD}));
}

#[test]
fn only_a_file_whose_first_line_is_the_marker_counts_as_ours_so_uninstall_never_deletes_a_user_plugin()
 {
    let dir = std::env::temp_dir().join(format!("redacted-opencode-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let ours = dir.join("ours.ts");
    let theirs = dir.join("theirs.ts");
    fs::write(&ours, PLUGIN_SOURCE).unwrap();
    fs::write(&theirs, "export const Mine = async () => ({})\n").unwrap();

    assert!(PLUGIN_SOURCE.starts_with(PLUGIN_MARKER));
    assert!(is_our_plugin(&ours));
    assert!(!is_our_plugin(&theirs));
    assert!(!is_our_plugin(&dir.join("missing.ts")));

    assert_eq!(remove_plugin(&theirs), Ok(false));
    assert!(theirs.exists());
    assert_eq!(remove_plugin(&ours), Ok(true));
    assert!(!ours.exists());
}
