//! Claude Code's settings.json: reading it, and adding or removing our
//! PostToolUse hook while every other key is written back untouched.

use std::fs;
use std::io;
use std::path::Path;

use serde_json::{Value, json};

/// A hook command ending in this is ours, wherever the binary lives.
const OUR_COMMAND_SUFFIX: &str = "redacted scrub";

/// The parsed file, or None when it does not exist. A `Value` rather than a typed
/// struct, so keys we do not know about survive a rewrite.
pub fn read(path: &Path) -> Result<Option<Value>, String> {
    let shown = path.display();
    let data = match fs::read(path) {
        Ok(data) => data,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("reading {shown}: {e}")),
    };
    let settings = serde_json::from_slice(&data).map_err(|e| format!("parsing {shown}: {e}"))?;
    Ok(Some(settings))
}

/// Pretty-printed, creating the directory if needed.
pub fn write(path: &Path, settings: &Value) -> Result<(), String> {
    let out =
        serde_json::to_string_pretty(settings).map_err(|e| format!("marshal settings: {e}"))?;
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).map_err(|e| format!("create config directory: {e}"))?;
    }
    fs::write(path, out).map_err(|e| format!("writing {}: {e}", path.display()))
}

/// Replaces any redacted entry in PostToolUse with one for `bin`; other entries
/// and settings are kept as-is.
pub fn install_hook(path: &Path, bin: &str) -> Result<(), String> {
    let mut settings = read(path)?.unwrap_or_else(|| json!({}));
    let root = settings
        .as_object_mut()
        .ok_or(format!("parsing {}: not an object", path.display()))?;
    let hooks = root.entry("hooks").or_insert_with(|| json!({}));
    if !hooks.is_object() {
        *hooks = json!({});
    }
    // take() moves the old list out and leaves null behind, so nothing is cloned.
    let mut entries = match hooks["PostToolUse"].take() {
        Value::Array(entries) => entries,
        _ => Vec::new(),
    };
    entries.retain(|e| !is_redacted_entry(e));
    entries.push(json!({"hooks": [{"type": "command", "command": format!("{bin} scrub")}]}));
    hooks["PostToolUse"] = Value::Array(entries);
    write(path, &settings)
}

/// Ok(false) when there is nothing to remove, including a missing file.
pub fn remove_hook(path: &Path) -> Result<bool, String> {
    let Some(mut settings) = read(path)? else {
        return Ok(false);
    };
    let Some(hooks) = settings.get_mut("hooks").and_then(Value::as_object_mut) else {
        return Ok(false);
    };
    let Some(entries) = hooks.get_mut("PostToolUse").and_then(Value::as_array_mut) else {
        return Ok(false);
    };
    let before = entries.len();
    entries.retain(|e| !is_redacted_entry(e));
    if entries.len() == before {
        return Ok(false);
    }
    if entries.is_empty() {
        hooks.remove("PostToolUse");
    }
    if hooks.is_empty()
        && let Some(root) = settings.as_object_mut()
    {
        root.remove("hooks");
    }
    write(path, &settings)?;
    Ok(true)
}

/// The PostToolUse entries; empty when the key is missing or not a list.
pub fn post_tool_use_entries(settings: &Value) -> &[Value] {
    // Indexing a `Value` with a missing key gives null instead of panicking.
    match settings["hooks"]["PostToolUse"].as_array() {
        Some(entries) => entries,
        None => &[],
    }
}

/// The first PostToolUse entry that runs our hook.
pub fn find_redacted_entry(settings: &Value) -> Option<&Value> {
    post_tool_use_entries(settings)
        .iter()
        .find(|entry| is_redacted_entry(entry))
}

/// Our commands inside one entry, which may also hold other tools' hooks.
pub fn redacted_commands(entry: &Value) -> Vec<&str> {
    let Some(hooks) = entry["hooks"].as_array() else {
        return Vec::new();
    };
    hooks
        .iter()
        .filter_map(|hook| hook["command"].as_str())
        .filter(|command| command.ends_with(OUR_COMMAND_SUFFIX))
        .collect()
}

fn is_redacted_entry(entry: &Value) -> bool {
    !redacted_commands(entry).is_empty()
}

#[cfg(test)]
mod tests;
