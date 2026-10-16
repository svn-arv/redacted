//! Claude Code PreToolUse protocol for the Monitor tool (issue #58). Monitor
//! events never reach PostToolUse, so the monitored command is rewritten to
//! pipe its output through `redacted scrub --stream` before it runs.

use std::io;
use std::panic::{self, AssertUnwindSafe};
use std::path::PathBuf;

use serde::Serialize;
use serde_json::Value;

use crate::hook;

const WEBSOCKET_DENIED: &str = "redacted cannot filter WebSocket frames; monitor a command instead";

#[derive(Serialize)]
struct PreToolUseOutput {
    #[serde(rename = "hookSpecificOutput")]
    hook_specific_output: PreToolUseDecision,
}

// No `permissionDecision` on a rewrite: a security hook must not auto-approve,
// and Claude Code applies `updatedInput` without one, then asks as usual.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PreToolUseDecision {
    hook_event_name: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    permission_decision: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    permission_decision_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    updated_input: Option<Value>,
}

/// The bytes to print for a PreToolUse payload: a rewritten Monitor command, a
/// deny, or nothing. `exe` is `current_exe()`, passed in so tests can pin it.
pub fn respond(payload: &Value, exe: io::Result<PathBuf>) -> Vec<u8> {
    if payload.get("tool_name").and_then(Value::as_str) != Some("Monitor") {
        return Vec::new();
    }
    // Fail closed: an unhandled error or panic would exit non-zero, and Claude
    // Code then runs the command unfiltered.
    let decision = match panic::catch_unwind(AssertUnwindSafe(|| wrap_monitor_call(payload, exe))) {
        Ok(Ok(decision)) => decision,
        Ok(Err(error)) => deny(format!(
            "redacted could not wrap the Monitor command: {error}"
        )),
        Err(_) => deny("redacted could not wrap the Monitor command: internal error".into()),
    };
    hook::encode(&PreToolUseOutput {
        hook_specific_output: decision,
    })
    .expect("strings and parsed Values always serialize")
}

/// The decision for one Monitor call. Error messages name fields only: the model reads them, the payload may hold secrets.
fn wrap_monitor_call(
    payload: &Value,
    exe: io::Result<PathBuf>,
) -> Result<PreToolUseDecision, String> {
    let mut tool_input = payload
        .get("tool_input")
        .and_then(Value::as_object)
        .ok_or("tool_input is not an object")?
        .clone();
    if tool_input.contains_key("ws") {
        return Ok(deny(WEBSOCKET_DENIED.into()));
    }
    let command = match tool_input.get("command") {
        Some(Value::String(command)) => command,
        Some(_) => return Err("command is not a string".into()),
        None => return Err("tool_input has no command".into()),
    };
    // An empty --cwd would read the project config of whatever directory the shell is in.
    let cwd = payload
        .get("cwd")
        .and_then(Value::as_str)
        .filter(|cwd| !cwd.is_empty())
        .ok_or("payload has no cwd")?;
    let exe = exe.map_err(|_| "cannot find the redacted binary")?;
    let exe = exe
        .to_str()
        .ok_or("the redacted binary path is not UTF-8")?;
    // 2>&1: Monitor turns only stdout into events, but stderr lands in a file the model can Read.
    // The command is one quoted word, never shell syntax: `true ); cat .env; ( true`
    // cannot close the wrapper early. bash, so bash-isms in model-written commands keep working.
    let wrapped = format!(
        "bash -c {} 2>&1 | {} scrub --stream --cwd {}",
        shell_quote(command),
        shell_quote(exe),
        shell_quote(cwd)
    );
    tool_input.insert("command".into(), Value::String(wrapped));
    Ok(PreToolUseDecision {
        hook_event_name: "PreToolUse",
        permission_decision: None,
        permission_decision_reason: None,
        updated_input: Some(Value::Object(tool_input)),
    })
}

fn deny(reason: String) -> PreToolUseDecision {
    PreToolUseDecision {
        hook_event_name: "PreToolUse",
        permission_decision: Some("deny"),
        permission_decision_reason: Some(reason),
        updated_input: None,
    }
}

/// One shell word: inside single quotes only `'` is special, so it closes the
/// quote, adds an escaped `'` and reopens.
fn shell_quote(text: &str) -> String {
    format!("'{}'", text.replace('\'', r"'\''"))
}

#[cfg(test)]
mod tests;
