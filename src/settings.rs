//! Claude Code's settings.json: reading it, and adding or removing our
//! PostToolUse hook while every other key is written back untouched.

use std::fs;
use std::io;
use std::path::Path;

use serde_json::{json, Value};

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
    if hooks.is_empty() {
        if let Some(root) = settings.as_object_mut() {
            root.remove("hooks");
        }
    }
    write(path, &settings)?;
    Ok(true)
}

/// The PostToolUse entries; empty when the key is missing or not a list.
pub fn post_tool_use(settings: &Value) -> &[Value] {
    // Indexing a `Value` with a missing key gives null instead of panicking.
    match settings["hooks"]["PostToolUse"].as_array() {
        Some(entries) => entries,
        None => &[],
    }
}

/// The first PostToolUse entry that runs our hook.
pub fn find_ours(settings: &Value) -> Option<&Value> {
    post_tool_use(settings)
        .iter()
        .find(|entry| is_redacted_entry(entry))
}

/// Our commands inside one entry, which may also hold other tools' hooks.
pub fn our_commands(entry: &Value) -> Vec<&str> {
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
    !our_commands(entry).is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn tmp(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("redacted-settings-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn read_back(path: &Path) -> Value {
        serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
    }

    fn commands(entries: &[Value]) -> Vec<String> {
        entries
            .iter()
            .flat_map(|e| e["hooks"].as_array().cloned().unwrap_or_default())
            .map(|h| h["command"].as_str().unwrap_or("").to_string())
            .collect()
    }

    #[test]
    fn install_hook_creates_new_file() {
        let path = tmp("hook-new").join(".claude/settings.json");
        install_hook(&path, "/usr/local/bin/redacted").unwrap();
        assert_eq!(
            post_tool_use(&read_back(&path)),
            [json!({"hooks": [{"type": "command", "command": "/usr/local/bin/redacted scrub"}]})]
        );
    }

    #[test]
    fn install_hook_preserves_existing_settings() {
        let path = tmp("hook-keep").join(".claude/settings.json");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let existing = json!({
            "theme": "dark",
            "hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "/usr/local/bin/rtk-rewrite.sh"}]}]}
        });
        fs::write(&path, existing.to_string()).unwrap();
        install_hook(&path, "/usr/local/bin/redacted").unwrap();
        let v = read_back(&path);
        assert_eq!(v["theme"], "dark");
        assert_eq!(v["hooks"]["PreToolUse"], existing["hooks"]["PreToolUse"]);
        assert_eq!(post_tool_use(&v).len(), 1);
    }

    #[test]
    fn install_hook_preserves_other_post_tool_use_hooks_verbatim() {
        let path = tmp("hook-other").join(".claude/settings.json");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        // Unknown fields like timeout must survive (Go 0.7's typed round-trip dropped them).
        let other = json!({"matcher": "Bash", "hooks": [{"type": "command", "command": "/usr/local/bin/other-hook", "timeout": 5}]});
        fs::write(
            &path,
            json!({"hooks": {"PostToolUse": [other]}}).to_string(),
        )
        .unwrap();
        install_hook(&path, "/usr/local/bin/redacted").unwrap();
        let v = read_back(&path);
        let entries = post_tool_use(&v);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0], other);
    }

    #[test]
    fn install_hook_replaces_existing_redacted() {
        let path = tmp("hook-replace").join(".claude/settings.json");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let existing = json!({"hooks": {"PostToolUse": [
            {"matcher": "Bash", "hooks": [{"type": "command", "command": "/old/path/to/redacted scrub"}]},
            {"matcher": "Bash", "hooks": [{"type": "command", "command": "/usr/local/bin/other-hook"}]},
        ]}});
        fs::write(&path, existing.to_string()).unwrap();
        install_hook(&path, "/new/path/redacted").unwrap();
        let cmds = commands(post_tool_use(&read_back(&path)));
        assert_eq!(
            cmds,
            ["/usr/local/bin/other-hook", "/new/path/redacted scrub"]
        );
    }

    #[test]
    fn install_hook_is_idempotent() {
        let path = tmp("hook-twice").join(".claude/settings.json");
        install_hook(&path, "/usr/local/bin/redacted").unwrap();
        install_hook(&path, "/usr/local/bin/redacted").unwrap();
        assert_eq!(post_tool_use(&read_back(&path)).len(), 1);
    }

    #[test]
    fn install_hook_rejects_invalid_existing_json() {
        let path = tmp("hook-bad").join(".claude/settings.json");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, "not json").unwrap();
        let err = install_hook(&path, "/usr/local/bin/redacted").unwrap_err();
        assert!(err.contains("parsing"), "{err}");
        assert_eq!(fs::read_to_string(&path).unwrap(), "not json");
    }

    fn settings_file(tag: &str, v: Value) -> PathBuf {
        let path = tmp(tag).join("settings.json");
        fs::write(&path, v.to_string()).unwrap();
        path
    }

    fn ours() -> Value {
        json!({"matcher": "Bash", "hooks": [{"type": "command", "command": "/usr/local/bin/redacted scrub"}]})
    }

    #[test]
    fn remove_hook_drops_the_entry_and_the_emptied_keys() {
        let path = settings_file(
            "rm-only",
            json!({"theme": "dark", "hooks": {"PostToolUse": [ours()]}}),
        );
        assert_eq!(remove_hook(&path), Ok(true));
        assert_eq!(read_back(&path), json!({"theme": "dark"}));
    }

    #[test]
    fn remove_hook_keeps_other_hooks_and_settings() {
        let other = json!({"matcher": "Bash", "hooks": [{"type": "command", "command": "/usr/local/bin/other-hook", "timeout": 5}]});
        let pre = json!([{"matcher": "Bash", "hooks": [{"type": "command", "command": "/usr/local/bin/rtk"}]}]);
        let path = settings_file(
            "rm-keep",
            json!({"theme": "dark", "hooks": {"PreToolUse": pre, "PostToolUse": [other, ours()]}}),
        );
        assert_eq!(remove_hook(&path), Ok(true));
        let v = read_back(&path);
        assert_eq!(v["theme"], "dark");
        assert_eq!(v["hooks"]["PreToolUse"], pre);
        assert_eq!(v["hooks"]["PostToolUse"], json!([other]));
    }

    #[test]
    fn remove_hook_reports_nothing_to_remove() {
        let other = json!({"hooks": [{"type": "command", "command": "/usr/local/bin/other-hook"}]});
        for (tag, v) in [
            ("rm-none", json!({"hooks": {"PostToolUse": [other]}})),
            ("rm-empty", json!({})),
            ("rm-nohooks", json!({"theme": "dark"})),
        ] {
            let path = settings_file(tag, v.clone());
            assert_eq!(remove_hook(&path), Ok(false), "{tag}");
            assert_eq!(read_back(&path), v, "{tag}: file must be untouched");
        }
        let missing = tmp("rm-missing").join("settings.json");
        assert_eq!(remove_hook(&missing), Ok(false));
        assert!(!missing.exists());
    }

    #[test]
    fn remove_hook_is_idempotent() {
        let path = settings_file("rm-twice", json!({"hooks": {"PostToolUse": [ours()]}}));
        assert_eq!(remove_hook(&path), Ok(true));
        assert_eq!(remove_hook(&path), Ok(false));
    }

    #[test]
    fn remove_hook_errors_on_invalid_json_and_leaves_it() {
        let path = tmp("rm-bad").join("settings.json");
        fs::write(&path, "not json").unwrap();
        assert!(remove_hook(&path).unwrap_err().contains("parsing"));
        assert_eq!(fs::read_to_string(&path).unwrap(), "not json");
    }

    #[cfg(unix)]
    #[test]
    fn remove_hook_errors_when_the_file_cannot_be_rewritten() {
        use std::os::unix::fs::PermissionsExt;
        let path = settings_file("rm-ro", json!({"hooks": {"PostToolUse": [ours()]}}));
        fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
        // Root ignores file modes, so the rewrite would succeed there.
        if fs::OpenOptions::new().write(true).open(&path).is_ok() {
            return;
        }
        assert!(remove_hook(&path).is_err());
    }

    #[test]
    fn is_redacted_entry_matches_the_command_suffix() {
        for (cmd, want) in [
            ("/usr/local/bin/redacted scrub", true),
            ("/home/user/go/bin/redacted scrub", true),
            ("/usr/local/bin/other-hook", false),
            ("/usr/local/bin/not-redacted scrub-extra", false),
            ("", false),
        ] {
            let entry = json!({"hooks": [{"type": "command", "command": cmd}]});
            assert_eq!(is_redacted_entry(&entry), want, "{cmd}");
        }
    }
}
