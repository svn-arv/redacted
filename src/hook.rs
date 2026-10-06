//! Claude Code PostToolUse protocol, ported from the Go 0.7 hook
//! (the updatedToolOutput envelope from fix/46).

use std::collections::BTreeMap;
use std::panic::{self, AssertUnwindSafe};

use serde::Serialize;
use serde_json::Value;

use crate::scrub::ScrubResult;

/// Printed in place of the tool output when scrubbing failed.
const WITHHELD: &str = "[redacted] tool output withheld: the scrubber errored, so raw output was suppressed to avoid leaking secrets.";

// Typed structs rather than `json!`: serde_json sorts `json!` keys, and the
// envelope's key order is pinned byte for byte. `'a` lets fields borrow strings.
#[derive(Serialize)]
struct HookOutput<'a> {
    decision: &'a str,
    reason: &'a str,
    #[serde(rename = "hookSpecificOutput")]
    hook_specific_output: HookSpecificOutput<'a>,
}

#[derive(Serialize)]
struct HookSpecificOutput<'a> {
    #[serde(rename = "hookEventName")]
    hook_event_name: &'a str,
    #[serde(rename = "updatedToolOutput", skip_serializing_if = "str::is_empty")]
    updated_tool_output: &'a str,
}

/// The bytes to print and the per-pattern hit counts to record.
type HookResult = (Vec<u8>, BTreeMap<String, usize>);

/// Scrubs the tool output in a PostToolUse payload. No hit returns no bytes so
/// the original passes through; a hit returns the block envelope.
fn scrub_payload(data: &[u8], scrub: &dyn Fn(&str) -> ScrubResult) -> Result<HookResult, String> {
    let payload: Value =
        serde_json::from_slice(data).map_err(|e| format!("parse hook payload: {e}"))?;
    let tool_name = string_field_or_empty(&payload, "tool_name")?;
    let response = payload.get("tool_response").unwrap_or(&Value::Null);
    if tool_name == "Bash" {
        scrub_bash_response(response, scrub)
    } else {
        scrub_tool_response(response, &tool_name, scrub)
    }
}

/// Fail closed: an error or panic withholds the output rather than letting
/// raw, unscrubbed bytes through.
pub fn scrub_payload_or_withhold(data: &[u8], scrub: &dyn Fn(&str) -> ScrubResult) -> HookResult {
    // catch_unwind turns a panic into an Err. AssertUnwindSafe vouches that nothing
    // the panic may have left half-written is used afterwards: it is all dropped.
    match panic::catch_unwind(AssertUnwindSafe(|| scrub_payload(data, scrub))) {
        Ok(Ok(hook_result)) => hook_result,
        _ => (withheld_output(), BTreeMap::new()),
    }
}

pub fn withheld_output() -> Vec<u8> {
    encode(&HookOutput {
        decision: "block",
        reason: WITHHELD,
        hook_specific_output: HookSpecificOutput {
            hook_event_name: "PostToolUse",
            updated_tool_output: WITHHELD,
        },
    })
    .expect("static envelope serializes")
}

/// Puts `line` above an envelope's reason; `updatedToolOutput` is left alone
/// because it stands in for the tool result the model reads.
pub fn prepend_reason(out: &[u8], line: &str) -> Vec<u8> {
    let Ok(mut envelope) = serde_json::from_slice::<Value>(out) else {
        return out.to_vec();
    };
    let Some(reason) = envelope["reason"].as_str() else {
        return out.to_vec();
    };
    envelope["reason"] = Value::String(format!("{line}\n{reason}"));
    encode(&envelope).unwrap_or_else(|_| out.to_vec())
}

// Go decodes into typed structs, so a wrong type is an error, null is "".
fn string_field_or_empty(value: &Value, key: &str) -> Result<String, String> {
    match value.get(key) {
        None | Some(Value::Null) => Ok(String::new()),
        Some(Value::String(s)) => Ok(s.clone()),
        Some(_) => Err(format!("parse hook payload: {key} is not a string")),
    }
}

fn scrub_bash_response(
    response: &Value,
    scrub: &dyn Fn(&str) -> ScrubResult,
) -> Result<HookResult, String> {
    if !(response.is_object() || response.is_null()) {
        return Err("parse hook payload: tool_response is not an object".into());
    }
    let stderr = string_field_or_empty(response, "stderr")?;
    let stdout_result = scrub(&string_field_or_empty(response, "stdout")?);
    let stderr_result = scrub(&stderr);
    if !stdout_result.has_redactions() && !stderr_result.has_redactions() {
        return Ok((Vec::new(), BTreeMap::new()));
    }

    let mut reason = stdout_result.text.clone();
    if stderr_result.has_redactions() {
        reason += &format!("\n[stderr]\n{}", stderr_result.text);
    }
    // The replacement keeps a clean stderr too: the model still needs it.
    let mut updated = stdout_result.text.clone();
    if !stderr.is_empty() {
        updated += &format!("\n[stderr]\n{}", stderr_result.text);
    }

    let block = block_output(
        stdout_result.count + stderr_result.count,
        "command",
        &reason,
        &updated,
    )?;
    let mut counts = stdout_result.counts_by_pattern;
    for (pattern, count) in stderr_result.counts_by_pattern {
        // entry() finds or inserts the key; or_default() starts a new count at 0.
        *counts.entry(pattern).or_default() += count;
    }
    Ok((block, counts))
}

fn scrub_tool_response(
    response: &Value,
    tool_name: &str,
    scrub: &dyn Fn(&str) -> ScrubResult,
) -> Result<HookResult, String> {
    let (text, structured) = text_to_scrub(response)?;
    let result = scrub(&text);
    if !result.has_redactions() {
        return Ok((Vec::new(), BTreeMap::new()));
    }

    // The hit counts every string in the response; a Read envelope's reason still shows its content.
    let content = match file_content(response) {
        Some(c) => scrub(c).text,
        None if structured => marker_lines(&result.text),
        None => result.text.clone(),
    };
    // reason may summarize, the replacement may not: it stands in for the result.
    let updated = match response {
        Value::String(_) => result.text.clone(),
        other => to_go_json(&scrub_json(other, scrub))?,
    };
    let block = block_output(result.count, tool_name, &content, &updated)?;
    Ok((block, result.counts_by_pattern))
}

/// Scrubber input plus whether it came from a structured value (summarized in reason).
fn text_to_scrub(response: &Value) -> Result<(String, bool), String> {
    if let Value::String(s) = response {
        return Ok((s.clone(), false));
    }
    let mut parts = Vec::new();
    collect_strings(response, &mut parts);
    if !parts.is_empty() {
        return Ok((parts.join("\n"), true));
    }
    match response {
        Value::Null => Ok((String::new(), true)),
        other => Ok((to_go_json(other)?, true)),
    }
}

/// `file.content` of a Read `{"type":"text","file":{...}}` envelope.
fn file_content(response: &Value) -> Option<&str> {
    if response.get("type")?.as_str()? != "text" {
        return None;
    }
    response.get("file")?.get("content")?.as_str()
}

/// Every non-empty string leaf and object key, keys in sorted order (serde_json's
/// map is sorted). Keys count: a secret can arrive as one (e.g. Grep counts).
fn collect_strings(value: &Value, strings: &mut Vec<String>) {
    match value {
        Value::String(s) if !s.is_empty() => strings.push(s.clone()),
        Value::Object(map) => {
            for (key, child) in map {
                if !key.is_empty() {
                    strings.push(key.clone());
                }
                collect_strings(child, strings);
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_strings(item, strings);
            }
        }
        _ => {}
    }
}

fn scrub_json(value: &Value, scrub: &dyn Fn(&str) -> ScrubResult) -> Value {
    match value {
        Value::String(s) => Value::String(scrub(s).text),
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(key, child)| (scrub(key).text, scrub_json(child, scrub)))
                .collect(),
        ),
        Value::Array(items) => {
            Value::Array(items.iter().map(|item| scrub_json(item, scrub)).collect())
        }
        other => other.clone(),
    }
}

fn marker_lines(scrubbed: &str) -> String {
    let lines: Vec<String> = scrubbed
        .split('\n')
        .filter(|line| line.contains("[REDACTED"))
        .map(|line| format!("- {line}"))
        .collect();
    if lines.is_empty() {
        return "Secret(s) removed from tool response.".to_string();
    }
    lines.join("\n")
}

fn block_output(
    count: usize,
    source: &str,
    reason: &str,
    updated: &str,
) -> Result<Vec<u8>, String> {
    encode(&HookOutput {
        decision: "block",
        reason: &format!("[redacted] {count} secret(s) scrubbed from {source} output.\n\n{reason}"),
        hook_specific_output: HookSpecificOutput {
            hook_event_name: "PostToolUse",
            updated_tool_output: updated,
        },
    })
}

/// Go's encoder (HTML escaping off) plus its trailing newline.
fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, String> {
    let mut out = to_go_json(value)?.into_bytes();
    out.push(b'\n');
    Ok(out)
}

// Go always escapes U+2028/U+2029; serde_json never does. Both only ever
// appear inside JSON strings, so a plain replace is safe.
fn to_go_json<T: Serialize>(value: &T) -> Result<String, String> {
    let json = serde_json::to_string(value).map_err(|e| format!("encode response: {e}"))?;
    Ok(json
        .replace('\u{2028}', "\\u2028")
        .replace('\u{2029}', "\\u2029"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, EngineConfig};
    use crate::fake_secrets;
    use crate::scrub::Scrubber;

    fn run_hook(payload: &str) -> (String, BTreeMap<String, usize>) {
        let scrubber = Scrubber::new(&Config::default(), &EngineConfig::default()).unwrap();
        let (out, counts) =
            scrub_payload_or_withhold(payload.as_bytes(), &|text| scrubber.scrub(text));
        (String::from_utf8(out).unwrap(), counts)
    }

    fn json_string(s: &str) -> String {
        serde_json::to_string(s).unwrap()
    }

    fn expected_envelope(reason: &str, updated: &str) -> String {
        format!(
            "{{\"decision\":\"block\",\"reason\":{},\"hookSpecificOutput\":{{\"hookEventName\":\"PostToolUse\",\"updatedToolOutput\":{}}}}}\n",
            json_string(reason),
            json_string(updated)
        )
    }

    #[test]
    fn bash_hit_emits_the_envelope_and_counts() {
        let key = fake_secrets::aws_access_key();
        let marker = format!("[REDACTED:aws_access_key ...{}]", fake_secrets::hint(&key));
        let payload = format!(
            r#"{{"tool_name":"Bash","tool_response":{{"stdout":"k {key}","stderr":"","exitCode":0}}}}"#
        );
        let (out, counts) = run_hook(&payload);
        let reason = format!("[redacted] 1 secret(s) scrubbed from command output.\n\nk {marker}");
        assert_eq!(out, expected_envelope(&reason, &format!("k {marker}")));
        assert_eq!(counts, BTreeMap::from([("aws_access_key".to_string(), 1)]));
    }

    #[test]
    fn bash_replacement_keeps_clean_stderr_but_reason_does_not() {
        let key = fake_secrets::npm_token();
        let payload = format!(
            r#"{{"tool_name":"Bash","tool_response":{{"stdout":"{key}","stderr":"warning: retrying once"}}}}"#
        );
        let (out, _) = run_hook(&payload);
        let marker = format!("[REDACTED:npm_token ...{}]", fake_secrets::hint(&key));
        let reason = format!("[redacted] 1 secret(s) scrubbed from command output.\n\n{marker}");
        let updated = format!("{marker}\n[stderr]\nwarning: retrying once");
        assert_eq!(out, expected_envelope(&reason, &updated));
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
        let text = format!(
            "line1\ntoken [REDACTED:jwt ...{}]",
            fake_secrets::hint(&key)
        );
        let reason = format!("[redacted] 1 secret(s) scrubbed from Read output.\n\n{text}");
        assert_eq!(out, expected_envelope(&reason, &text));
        assert_eq!(counts.get("jwt"), Some(&1));
    }

    #[test]
    fn read_file_envelope_reason_is_full_content_and_shape_is_kept() {
        let key = fake_secrets::jwt();
        let payload = format!(
            r#"{{"tool_name":"Read","tool_response":{{"type":"text","file":{{"filePath":"/a/.env","content":"A=1\nT={key}","numLines":2,"startLine":1}}}}}}"#
        );
        let (out, _) = run_hook(&payload);
        let marker = format!("[REDACTED:jwt ...{}]", fake_secrets::hint(&key));
        let reason =
            format!("[redacted] 1 secret(s) scrubbed from Read output.\n\nA=1\nT={marker}");
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
        let marker = format!("[REDACTED:jwt ...{}]", fake_secrets::hint(&key));
        let reason = format!("[redacted] 1 secret(s) scrubbed from Grep output.\n\n- x {marker}");
        // Go escapes U+2028 even with HTML escaping off, and keeps number literals verbatim.
        let content =
            json_string(&format!("<a>&b\u{2028}\nx {marker}")).replace('\u{2028}', "\\u2028");
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
        let marker = format!("[REDACTED:aws_access_key ...{}]", fake_secrets::hint(&key));
        let reason = "[redacted] 1 secret(s) scrubbed from Read output.\n\nclean";
        let updated = format!(
            r#"{{"file":{{"content":"clean","filePath":{}}},"type":"text"}}"#,
            json_string(&format!("/a/{marker}.txt"))
        );
        assert_eq!(out, expected_envelope(reason, &updated));
        assert_eq!(counts.get("aws_access_key"), Some(&1));
    }

    #[test]
    fn object_keys_are_scrubbed_in_the_replacement() {
        let key = fake_secrets::aws_access_key();
        let payload = format!(
            r#"{{"tool_name":"Grep","tool_response":{{"counts":{{"{key}":1}},"mode":"count"}}}}"#
        );
        let (out, _) = run_hook(&payload);
        let marker = format!("[REDACTED:aws_access_key ...{}]", fake_secrets::hint(&key));
        let reason = format!("[redacted] 1 secret(s) scrubbed from Grep output.\n\n- {marker}");
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
            r#"{"tool_name":"Bash","tool_response":{"stdout":7}}"#,
        ] {
            assert_eq!(run_hook(payload).0, expected, "{payload}");
        }
    }

    #[test]
    fn fails_closed_on_panic() {
        let payload = r#"{"tool_name":"Read","tool_response":"anything"}"#;
        let (out, _) = scrub_payload_or_withhold(payload.as_bytes(), &|_| panic!("boom"));
        assert_eq!(String::from_utf8(out).unwrap(), withheld_line());
    }

    fn withheld_line() -> String {
        expected_envelope(WITHHELD, WITHHELD)
    }
}
