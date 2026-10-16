//! Unit tests for the Monitor command rewrite.

use std::io;
use std::path::PathBuf;

use serde_json::json;

use super::*;

const EXE: &str = "/opt/bin/redacted";

fn respond_with_exe(payload: Value) -> String {
    String::from_utf8(respond(&payload, Ok(PathBuf::from(EXE)))).unwrap()
}

fn monitor_payload(tool_input: Value) -> Value {
    json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Monitor",
        "cwd": "/work/app",
        "tool_input": tool_input,
    })
}

#[test]
fn a_monitor_command_is_piped_through_the_stream_filter_so_each_event_is_scrubbed() {
    let payload = monitor_payload(json!({"command": "tail -f app.log"}));
    assert_eq!(
        respond_with_exe(payload),
        concat!(
            r#"{"hookSpecificOutput":{"hookEventName":"PreToolUse","updatedInput":{"#,
            r#""command":"( tail -f app.log\n) 2>&1 | '/opt/bin/redacted' scrub --stream --cwd '/work/app'"}}}"#,
            "\n"
        )
    );
}

#[test]
fn the_rewrite_keeps_every_other_tool_input_key_because_updated_input_replaces_the_whole_object() {
    let payload = monitor_payload(json!({
        "command": "tail -f app.log",
        "description": "errors in app.log",
        "timeout_ms": 40000,
        "future_field": {"kept": true},
    }));
    let out: Value = serde_json::from_str(&respond_with_exe(payload)).unwrap();
    let updated = &out["hookSpecificOutput"]["updatedInput"];
    assert_eq!(updated["description"], "errors in app.log");
    assert_eq!(updated["timeout_ms"], 40000);
    assert_eq!(updated["future_field"], json!({"kept": true}));
}

#[test]
fn a_cwd_with_a_space_and_a_quote_stays_one_shell_word_so_the_filter_reads_the_right_project() {
    let mut payload = monitor_payload(json!({"command": "tail -f app.log"}));
    payload["cwd"] = json!("/work/bob's app");
    let out: Value = serde_json::from_str(&respond_with_exe(payload)).unwrap();
    assert_eq!(
        out["hookSpecificOutput"]["updatedInput"]["command"],
        "( tail -f app.log\n) 2>&1 | '/opt/bin/redacted' scrub --stream --cwd '/work/bob'\\''s app'"
    );
}

#[test]
fn an_already_wrapped_command_prints_nothing_so_it_is_never_filtered_twice() {
    let payload = monitor_payload(json!({
        "command": "( tail -f app.log ) 2>&1 | '/opt/bin/redacted' scrub --stream --cwd '/work/app'"
    }));
    assert_eq!(respond_with_exe(payload), "");
}

#[test]
fn a_websocket_monitor_is_denied_because_its_frames_never_pass_through_a_shell() {
    let payload = monitor_payload(json!({"ws": {"url": "wss://events.example.com"}}));
    assert_eq!(
        respond_with_exe(payload),
        concat!(
            r#"{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","#,
            r#""permissionDecisionReason":"redacted cannot filter WebSocket frames; monitor a command instead"}}"#,
            "\n"
        )
    );
}

#[test]
fn a_monitor_call_that_cannot_be_wrapped_is_denied_without_quoting_the_payload() {
    let secret_looking = "tail -f app.log # token=do-not-echo";
    for (case, payload) in [
        ("tool_input not an object", {
            let mut payload = monitor_payload(json!({}));
            payload["tool_input"] = json!(secret_looking);
            payload
        }),
        (
            "command not a string",
            monitor_payload(json!({"command": [secret_looking]})),
        ),
        (
            "no command",
            monitor_payload(json!({"description": secret_looking})),
        ),
        ("no cwd", {
            let mut payload = monitor_payload(json!({"command": secret_looking}));
            payload["cwd"] = json!("");
            payload
        }),
    ] {
        let out: Value = serde_json::from_str(&respond_with_exe(payload)).unwrap();
        let decision = &out["hookSpecificOutput"];
        assert_eq!(decision["permissionDecision"], "deny", "{case}");
        let reason = decision["permissionDecisionReason"].as_str().unwrap();
        assert!(
            reason.starts_with("redacted could not wrap the Monitor command: "),
            "{case}: {reason}"
        );
        assert!(!reason.contains("do-not-echo"), "{case}: {reason}");
        assert!(decision.get("updatedInput").is_none(), "{case}");
    }
}

#[test]
fn a_missing_binary_path_denies_rather_than_letting_the_command_run_unfiltered() {
    let payload = monitor_payload(json!({"command": "tail -f app.log"}));
    let out = respond(&payload, Err(io::Error::other("gone")));
    let out: Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(out["hookSpecificOutput"]["permissionDecision"], "deny");
}

#[test]
fn a_pre_tool_use_call_for_another_tool_prints_nothing_so_it_runs_as_sent() {
    let mut payload = monitor_payload(json!({"command": "ls"}));
    payload["tool_name"] = json!("Bash");
    assert_eq!(respond_with_exe(payload), "");
}
