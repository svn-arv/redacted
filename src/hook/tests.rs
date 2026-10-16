//! Unit tests for the PostToolUse hook protocol.

use super::*;
use crate::config::{Config, EngineConfig};
use crate::fake_secrets;
use crate::scrub::Scrubber;

fn run_hook(payload: &str) -> (String, BTreeMap<String, usize>) {
    let scrubber = Scrubber::new(&Config::default(), &EngineConfig::default()).unwrap();
    let (out, counts) = scrub_payload_or_withhold(payload.as_bytes(), &|text| scrubber.scrub(text));
    (String::from_utf8(out).unwrap(), counts)
}

fn json_string(s: &str) -> String {
    serde_json::to_string(s).unwrap()
}

/// `updated_json` is raw JSON: the replacement is a string only for a string response.
fn expected_envelope(reason: &str, updated_json: &str) -> String {
    format!(
        "{{\"decision\":\"block\",\"reason\":{},\"hookSpecificOutput\":{{\"hookEventName\":\"PostToolUse\",\"updatedToolOutput\":{}}}}}\n",
        json_string(reason),
        updated_json
    )
}

#[test]
fn bash_hit_emits_the_envelope_and_counts() {
    let key = fake_secrets::aws_access_key();
    let marker = format!(
        "[REDACTED:aws_access_key ...{}]",
        fake_secrets::last_four_chars(&key)
    );
    let payload = format!(
        r#"{{"tool_name":"Bash","tool_response":{{"stdout":"k {key}","stderr":"","exitCode":0}}}}"#
    );
    let (out, counts) = run_hook(&payload);
    let reason = format!(
        "[redacted] 1 secret(s) scrubbed from command output: aws_access_key\n\n- k {marker}"
    );
    let updated = format!(
        r#"{{"exitCode":0,"stderr":"","stdout":{}}}"#,
        json_string(&format!("k {marker}"))
    );
    assert_eq!(out, expected_envelope(&reason, &updated));
    assert_eq!(counts, BTreeMap::from([("aws_access_key".to_string(), 1)]));
}

#[test]
fn bash_replacement_keeps_clean_stderr_but_reason_does_not() {
    let key = fake_secrets::npm_token();
    let payload = format!(
        r#"{{"tool_name":"Bash","tool_response":{{"stdout":"{key}","stderr":"warning: retrying once"}}}}"#
    );
    let (out, _) = run_hook(&payload);
    let marker = format!(
        "[REDACTED:npm_token ...{}]",
        fake_secrets::last_four_chars(&key)
    );
    let reason =
        format!("[redacted] 1 secret(s) scrubbed from command output: npm_token\n\n- {marker}");
    let updated = format!(
        r#"{{"stderr":"warning: retrying once","stdout":{}}}"#,
        json_string(&marker)
    );
    assert_eq!(out, expected_envelope(&reason, &updated));
}

#[test]
fn collapsed_reason_line_names_the_most_hit_pattern_first() {
    // Claude Code shows only the first line until expanded, so it must say what was hit.
    let (npm_key, aws_key) = (fake_secrets::npm_token(), fake_secrets::aws_access_key());
    let payload = format!(
        r#"{{"tool_name":"Bash","tool_response":{{"stdout":"a {npm_key}\nclean\nb {npm_key}","stderr":"c {aws_key}"}}}}"#
    );
    let (out, _) = run_hook(&payload);
    let envelope: Value = serde_json::from_str(&out).unwrap();
    let npm_marker = format!(
        "[REDACTED:npm_token ...{}]",
        fake_secrets::last_four_chars(&npm_key)
    );
    let aws_marker = format!(
        "[REDACTED:aws_access_key ...{}]",
        fake_secrets::last_four_chars(&aws_key)
    );
    // Count before name: npm_token sorts after aws_access_key but was hit more.
    assert_eq!(
        envelope["reason"],
        format!(
            "[redacted] 3 secret(s) scrubbed from command output: npm_token ×2, aws_access_key\n\n- a {npm_marker}\n- b {npm_marker}\n- c {aws_marker}"
        )
    );
}

#[test]
fn bash_replacement_keeps_the_response_shape_so_claude_code_applies_it() {
    // Claude Code drops a replacement that does not match the tool's output schema.
    let key = fake_secrets::npm_token();
    let payload = format!(
        r#"{{"tool_name":"Bash","tool_response":{{"stdout":"{key}","interrupted":false,"isImage":false}}}}"#
    );
    let (out, _) = run_hook(&payload);
    let envelope: Value = serde_json::from_str(&out).unwrap();
    let marker = format!(
        "[REDACTED:npm_token ...{}]",
        fake_secrets::last_four_chars(&key)
    );
    // No stderr key in, none out: an invented field could break the schema match.
    assert_eq!(
        envelope["hookSpecificOutput"]["updatedToolOutput"],
        serde_json::json!({"stdout": marker, "interrupted": false, "isImage": false})
    );
}

#[test]
fn no_hit_writes_nothing_and_counts_nothing() {
    for payload in [
        r#"{"tool_name":"Bash","tool_response":{"stdout":"nothing secret","stderr":""}}"#,
        r#"{"tool_name":"Read","tool_response":"plain file"}"#,
        r#"{"tool_name":"Grep","tool_response":{"numFiles":0}}"#,
    ] {
        assert_eq!(
            run_hook(payload),
            (String::new(), BTreeMap::new()),
            "{payload}"
        );
    }
}

#[test]
fn read_string_response_replaces_with_bare_text() {
    let key = fake_secrets::jwt();
    let payload = format!(r#"{{"tool_name":"Read","tool_response":"line1\ntoken {key}"}}"#);
    let (out, counts) = run_hook(&payload);
    let marker = format!("[REDACTED:jwt ...{}]", fake_secrets::last_four_chars(&key));
    let text = format!("line1\ntoken {marker}");
    let reason =
        format!("[redacted] 1 secret(s) scrubbed from Read output: jwt\n\n- token {marker}");
    assert_eq!(out, expected_envelope(&reason, &json_string(&text)));
    assert_eq!(counts.get("jwt"), Some(&1));
}

#[test]
fn read_file_envelope_reason_lists_only_marker_lines_and_shape_is_kept() {
    let key = fake_secrets::jwt();
    let payload = format!(
        r#"{{"tool_name":"Read","tool_response":{{"type":"text","file":{{"filePath":"/a/.env","content":"A=1\nT={key}","numLines":2,"startLine":1}}}}}}"#
    );
    let (out, _) = run_hook(&payload);
    let marker = format!("[REDACTED:jwt ...{}]", fake_secrets::last_four_chars(&key));
    let reason = format!("[redacted] 1 secret(s) scrubbed from Read output: jwt\n\n- T={marker}");
    // An object, not a string of JSON: Claude Code ignores a replacement of the wrong type.
    let updated = format!(
        r#"{{"file":{{"content":{},"filePath":"/a/.env","numLines":2,"startLine":1}},"type":"text"}}"#,
        json_string(&format!("A=1\nT={marker}"))
    );
    assert_eq!(out, expected_envelope(&reason, &updated));
}

#[test]
fn grep_structured_reason_summarizes_and_replacement_keeps_shape() {
    let key = fake_secrets::jwt();
    let payload = format!(
        "{{\"tool_name\":\"Grep\",\"tool_response\":{{\"mode\":\"content\",\"numLines\":2.50,\"content\":\"<a>&b\u{2028}\\nx {key}\",\"filenames\":[\"a.txt\",null,true]}}}}"
    );
    let (out, _) = run_hook(&payload);
    let marker = format!("[REDACTED:jwt ...{}]", fake_secrets::last_four_chars(&key));
    let reason = format!("[redacted] 1 secret(s) scrubbed from Grep output: jwt\n\n- x {marker}");
    // Go escapes U+2028 even with HTML escaping off, and keeps number literals verbatim.
    let content = json_string(&format!("<a>&b\u{2028}\nx {marker}")).replace('\u{2028}', "\\u2028");
    let updated = format!(
        r#"{{"content":{content},"filenames":["a.txt",null,true],"mode":"content","numLines":2.50}}"#
    );
    let expected = expected_envelope(&reason, &updated).replace('\u{2028}', "\\u2028");
    assert_eq!(out, expected);
}

#[test]
fn read_file_envelope_secret_outside_content_is_redacted() {
    let key = fake_secrets::aws_access_key();
    let payload = format!(
        r#"{{"tool_name":"Read","tool_response":{{"type":"text","file":{{"filePath":"/a/{key}.txt","content":"clean"}}}}}}"#
    );
    let (out, counts) = run_hook(&payload);
    let marker = format!(
        "[REDACTED:aws_access_key ...{}]",
        fake_secrets::last_four_chars(&key)
    );
    let reason = format!(
        "[redacted] 1 secret(s) scrubbed from Read output: aws_access_key\n\n- /a/{marker}.txt"
    );
    let updated = format!(
        r#"{{"file":{{"content":"clean","filePath":{}}},"type":"text"}}"#,
        json_string(&format!("/a/{marker}.txt"))
    );
    assert_eq!(out, expected_envelope(&reason, &updated));
    assert_eq!(counts.get("aws_access_key"), Some(&1));
}

#[test]
fn object_keys_are_scrubbed_in_the_replacement() {
    let key = fake_secrets::aws_access_key();
    let payload = format!(
        r#"{{"tool_name":"Grep","tool_response":{{"counts":{{"{key}":1}},"mode":"count"}}}}"#
    );
    let (out, _) = run_hook(&payload);
    let marker = format!(
        "[REDACTED:aws_access_key ...{}]",
        fake_secrets::last_four_chars(&key)
    );
    let reason =
        format!("[redacted] 1 secret(s) scrubbed from Grep output: aws_access_key\n\n- {marker}");
    let updated = format!(
        r#"{{"counts":{{{}:1}},"mode":"count"}}"#,
        json_string(&marker)
    );
    assert_eq!(out, expected_envelope(&reason, &updated));
    assert!(!out.contains(&key));
}

#[test]
fn malformed_payload_withholds_the_tool_output() {
    let expected = withheld_line();
    for payload in [
        "{not json",
        r#"{"tool_name":5}"#,
        r#"{"tool_name":"Bash","tool_response":"not-an-object"}"#,
    ] {
        assert_eq!(run_hook(payload).0, expected, "{payload}");
    }
}

#[test]
fn malformed_bash_fields_are_withheld_but_the_shape_is_kept() {
    let payload = r#"{"tool_name":"Bash","tool_response":{"stdout":7,"stderr":"leak?"}}"#;
    let updated = format!(r#"{{"stderr":{},"stdout":7}}"#, json_string(WITHHELD));
    assert_eq!(run_hook(payload).0, expected_envelope(WITHHELD, &updated));
}

#[test]
fn withheld_bash_output_keeps_the_shape_so_raw_output_cannot_slip_through() {
    // A string replacement is ignored on Bash, so a failure would leak the raw output.
    let payload = r#"{"tool_name":"Bash","tool_response":{"stdout":"raw","stderr":"","interrupted":false,"isImage":false}}"#;
    let (out, _) = scrub_payload_or_withhold(payload.as_bytes(), &|_| panic!("boom"));
    let withheld = json_string(WITHHELD);
    let updated = format!(
        r#"{{"interrupted":false,"isImage":false,"stderr":{withheld},"stdout":{withheld}}}"#
    );
    assert_eq!(
        String::from_utf8(out).unwrap(),
        expected_envelope(WITHHELD, &updated)
    );
}

#[test]
fn fails_closed_on_panic() {
    let payload = r#"{"tool_name":"Read","tool_response":"anything"}"#;
    let (out, _) = scrub_payload_or_withhold(payload.as_bytes(), &|_| panic!("boom"));
    assert_eq!(String::from_utf8(out).unwrap(), withheld_line());
}

fn withheld_line() -> String {
    expected_envelope(WITHHELD, &json_string(WITHHELD))
}
