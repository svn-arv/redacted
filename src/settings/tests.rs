//! Unit tests for settings.json editing.

use super::*;
use std::path::PathBuf;

fn fresh_temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("redacted-settings-{tag}-{}", std::process::id()));
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
    let path = fresh_temp_dir("hook-new").join(".claude/settings.json");
    install_hook(&path, "/usr/local/bin/redacted").unwrap();
    assert_eq!(
        hook_entries(&read_back(&path), "PostToolUse"),
        [json!({"hooks": [{"type": "command", "command": "/usr/local/bin/redacted scrub"}]})]
    );
}

#[test]
fn install_hook_preserves_existing_settings() {
    let path = fresh_temp_dir("hook-keep").join(".claude/settings.json");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let existing = json!({
        "theme": "dark",
        "hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "/usr/local/bin/rtk-rewrite.sh"}]}]}
    });
    fs::write(&path, existing.to_string()).unwrap();
    install_hook(&path, "/usr/local/bin/redacted").unwrap();
    let written = read_back(&path);
    assert_eq!(written["theme"], "dark");
    assert_eq!(
        hook_entries(&written, "PreToolUse")[0],
        existing["hooks"]["PreToolUse"][0]
    );
    assert_eq!(hook_entries(&written, "PostToolUse").len(), 1);
}

#[test]
fn install_hook_preserves_other_post_tool_use_hooks_verbatim() {
    let path = fresh_temp_dir("hook-other").join(".claude/settings.json");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    // Unknown fields like timeout must survive (Go 0.7's typed round-trip dropped them).
    let other = json!({"matcher": "Bash", "hooks": [{"type": "command", "command": "/usr/local/bin/other-hook", "timeout": 5}]});
    fs::write(
        &path,
        json!({"hooks": {"PostToolUse": [other]}}).to_string(),
    )
    .unwrap();
    install_hook(&path, "/usr/local/bin/redacted").unwrap();
    let written = read_back(&path);
    let entries = hook_entries(&written, "PostToolUse");
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0], other);
}

#[test]
fn install_hook_replaces_existing_redacted() {
    let path = fresh_temp_dir("hook-replace").join(".claude/settings.json");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let existing = json!({"hooks": {"PostToolUse": [
        {"matcher": "Bash", "hooks": [{"type": "command", "command": "/old/path/to/redacted scrub"}]},
        {"matcher": "Bash", "hooks": [{"type": "command", "command": "/usr/local/bin/other-hook"}]},
    ]}});
    fs::write(&path, existing.to_string()).unwrap();
    install_hook(&path, "/new/path/redacted").unwrap();
    let cmds = commands(hook_entries(&read_back(&path), "PostToolUse"));
    assert_eq!(
        cmds,
        ["/usr/local/bin/other-hook", "/new/path/redacted scrub"]
    );
}

#[test]
fn install_hook_is_idempotent() {
    let path = fresh_temp_dir("hook-twice").join(".claude/settings.json");
    install_hook(&path, "/usr/local/bin/redacted").unwrap();
    install_hook(&path, "/usr/local/bin/redacted").unwrap();
    assert_eq!(hook_entries(&read_back(&path), "PostToolUse").len(), 1);
}

#[test]
fn install_hook_rejects_invalid_existing_json() {
    let path = fresh_temp_dir("hook-bad").join(".claude/settings.json");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, "not json").unwrap();
    let err = install_hook(&path, "/usr/local/bin/redacted").unwrap_err();
    assert!(err.contains("parsing"), "{err}");
    assert_eq!(fs::read_to_string(&path).unwrap(), "not json");
}

fn settings_file(tag: &str, settings: Value) -> PathBuf {
    let path = fresh_temp_dir(tag).join("settings.json");
    fs::write(&path, settings.to_string()).unwrap();
    path
}

fn redacted_entry() -> Value {
    json!({"matcher": "Bash", "hooks": [{"type": "command", "command": "/usr/local/bin/redacted scrub"}]})
}

#[test]
fn remove_hook_drops_the_entry_and_the_emptied_keys() {
    let path = settings_file(
        "rm-only",
        json!({"theme": "dark", "hooks": {"PostToolUse": [redacted_entry()]}}),
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
        json!({"theme": "dark", "hooks": {"PreToolUse": pre, "PostToolUse": [other, redacted_entry()]}}),
    );
    assert_eq!(remove_hook(&path), Ok(true));
    let written = read_back(&path);
    assert_eq!(written["theme"], "dark");
    assert_eq!(written["hooks"]["PreToolUse"], pre);
    assert_eq!(written["hooks"]["PostToolUse"], json!([other]));
}

#[test]
fn remove_hook_reports_nothing_to_remove() {
    let other = json!({"hooks": [{"type": "command", "command": "/usr/local/bin/other-hook"}]});
    for (tag, settings) in [
        ("rm-none", json!({"hooks": {"PostToolUse": [other]}})),
        ("rm-empty", json!({})),
        ("rm-nohooks", json!({"theme": "dark"})),
    ] {
        let path = settings_file(tag, settings.clone());
        assert_eq!(remove_hook(&path), Ok(false), "{tag}");
        assert_eq!(read_back(&path), settings, "{tag}: file must be untouched");
    }
    let missing = fresh_temp_dir("rm-missing").join("settings.json");
    assert_eq!(remove_hook(&missing), Ok(false));
    assert!(!missing.exists());
}

#[test]
fn remove_hook_is_idempotent() {
    let path = settings_file(
        "rm-twice",
        json!({"hooks": {"PostToolUse": [redacted_entry()]}}),
    );
    assert_eq!(remove_hook(&path), Ok(true));
    assert_eq!(remove_hook(&path), Ok(false));
}

#[test]
fn remove_hook_errors_on_invalid_json_and_leaves_it() {
    let path = fresh_temp_dir("rm-bad").join("settings.json");
    fs::write(&path, "not json").unwrap();
    assert!(remove_hook(&path).unwrap_err().contains("parsing"));
    assert_eq!(fs::read_to_string(&path).unwrap(), "not json");
}

#[cfg(unix)]
#[test]
fn remove_hook_errors_when_the_file_cannot_be_rewritten() {
    use std::os::unix::fs::PermissionsExt;
    let path = settings_file(
        "rm-ro",
        json!({"hooks": {"PostToolUse": [redacted_entry()]}}),
    );
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

fn monitor_entry(bin: &str) -> Value {
    json!({"matcher": "Monitor", "hooks": [{"type": "command", "command": format!("{bin} scrub")}]})
}

#[test]
fn install_hook_also_wraps_monitor_commands_because_their_events_skip_post_tool_use() {
    let path = fresh_temp_dir("hook-both").join(".claude/settings.json");
    install_hook(&path, "/usr/local/bin/redacted").unwrap();
    let written = read_back(&path);
    assert_eq!(hook_entries(&written, "PostToolUse").len(), 1);
    assert_eq!(
        hook_entries(&written, "PreToolUse"),
        [monitor_entry("/usr/local/bin/redacted")]
    );
}

#[test]
fn rerunning_install_on_a_post_tool_use_only_install_adds_the_monitor_hook_once() {
    let path = settings_file(
        "hook-upgrade",
        json!({"hooks": {"PostToolUse": [redacted_entry()]}}),
    );
    install_hook(&path, "/usr/local/bin/redacted").unwrap();
    install_hook(&path, "/usr/local/bin/redacted").unwrap();
    let written = read_back(&path);
    assert_eq!(hook_entries(&written, "PostToolUse").len(), 1);
    assert_eq!(
        hook_entries(&written, "PreToolUse"),
        [monitor_entry("/usr/local/bin/redacted")]
    );
}

#[test]
fn remove_hook_drops_the_monitor_hook_too_so_uninstall_leaves_no_wrapper_behind() {
    let rtk =
        json!({"matcher": "Bash", "hooks": [{"type": "command", "command": "/usr/local/bin/rtk"}]});
    let path = settings_file(
        "rm-both",
        json!({"hooks": {
            "PostToolUse": [redacted_entry()],
            "PreToolUse": [rtk, monitor_entry("/usr/local/bin/redacted")],
        }}),
    );
    assert_eq!(remove_hook(&path), Ok(true));
    assert_eq!(read_back(&path), json!({"hooks": {"PreToolUse": [rtk]}}));
}

#[test]
fn remove_hook_finds_a_lone_monitor_hook() {
    let path = settings_file(
        "rm-monitor",
        json!({"hooks": {"PreToolUse": [monitor_entry("/usr/local/bin/redacted")]}}),
    );
    assert_eq!(remove_hook(&path), Ok(true));
    assert_eq!(read_back(&path), json!({}));
}
