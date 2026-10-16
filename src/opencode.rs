//! `redacted scrub --format opencode`: OpenCode's `tool.execute.after` hook
//! (issue #48), and the plugin file that sends it each tool's output.
//!
//! The plugin writes `{tool, sessionID, callID, args, output}` to stdin and
//! swaps the printed value in for `output`, which is what the model reads.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::panic::{self, AssertUnwindSafe};
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::config::{Config, ConfigError, EngineConfig};
use crate::hook::{self, WITHHELD};
use crate::scrub::{ScrubResult, Scrubber};

/// The plugin `redacted init --format opencode` writes, compiled into the binary.
pub const PLUGIN_SOURCE: &str = include_str!("../plugins/opencode/redacted.ts");

/// The plugin's first line starts with this, so uninstall and verify can tell it from a user's own.
pub const PLUGIN_MARKER: &str = "// redacted: OpenCode plugin";

/// The bytes to print and the per-pattern hit counts to record.
type OpenCodeResult = (Vec<u8>, BTreeMap<String, usize>);

/// Always prints a JSON value for the plugin to swap in: `output` scrubbed, or
/// withheld when the config, the payload or the scrubber fails.
pub fn respond(data: &[u8], loaded: Result<(Config, EngineConfig), ConfigError>) -> OpenCodeResult {
    // A config that does not parse withholds before it can pass a tool through.
    let (config, engine_config) = match loaded {
        Ok(loaded) => loaded,
        Err(error) => {
            eprintln!("{error}");
            return (withheld_output(data), BTreeMap::new());
        }
    };
    let Ok(scrubber) = Scrubber::new(&config, &engine_config) else {
        return (withheld_output(data), BTreeMap::new());
    };
    let skips_non_bash = config.ignore_internal_tools;
    // AssertUnwindSafe vouches that nothing a panic may leave half-written is used afterwards.
    let scrubbed = panic::catch_unwind(AssertUnwindSafe(|| {
        scrub_output(data, skips_non_bash, &|text| scrubber.scrub(text))
    }));
    match scrubbed {
        Ok(Ok(result)) => result,
        _ => (withheld_output(data), BTreeMap::new()),
    }
}

/// `output` with every string leaf and object key scrubbed. `bash` is OpenCode's
/// shell tool, the only one `ignore_internal_tools` keeps scrubbing.
fn scrub_output(
    data: &[u8],
    skips_non_bash: bool,
    scrub: &dyn Fn(&str) -> ScrubResult,
) -> Result<OpenCodeResult, String> {
    let payload: Value =
        serde_json::from_slice(data).map_err(|e| format!("parse opencode payload: {e}"))?;
    let output = match payload.get("output") {
        None | Some(Value::Null) => return Err("parse opencode payload: no output".into()),
        Some(output) => output,
    };
    let is_named_non_bash_tool =
        matches!(payload.get("tool"), Some(Value::String(tool)) if tool != "bash");
    if skips_non_bash && is_named_non_bash_tool {
        return Ok((hook::encode(output)?, BTreeMap::new()));
    }
    // One scrub of all the strings joined gives the counts, as hook mode does.
    let counts = scrub(&hook::text_to_scrub(output)?).counts_by_pattern;
    if counts.is_empty() {
        return Ok((hook::encode(output)?, counts));
    }
    Ok((hook::encode(&hook::scrub_json(output, scrub))?, counts))
}

/// `output` with every string leaf withheld, so the plugin still gets the shape
/// it expects; without a usable `output`, the bare notice as a JSON string.
fn withheld_output(data: &[u8]) -> Vec<u8> {
    let payload: Value = serde_json::from_slice(data).unwrap_or(Value::Null);
    let withheld = match payload.get("output") {
        None | Some(Value::Null) => Value::String(WITHHELD.into()),
        Some(output) => hook::withhold_strings(output),
    };
    hook::encode(&withheld).expect("a parsed Value always serializes")
}

/// OpenCode loads every file in this folder for every project.
pub fn global_plugin_path(home: &Path) -> PathBuf {
    home.join(".config/opencode/plugins/redacted.ts")
}

/// OpenCode loads every file in this folder for this project only.
pub fn local_plugin_path(cwd: &Path) -> PathBuf {
    cwd.join(".opencode/plugins/redacted.ts")
}

/// True when `path` exists and its first line is our marker.
pub fn is_our_plugin(path: &Path) -> bool {
    fs::read_to_string(path).is_ok_and(|text| text.starts_with(PLUGIN_MARKER))
}

/// Ok(false) when there is nothing of ours to remove, including a missing file.
pub fn remove_plugin(path: &Path) -> Result<bool, String> {
    if !is_our_plugin(path) {
        return Ok(false);
    }
    match fs::remove_file(path) {
        Ok(()) => Ok(true),
        // Gone between the check and the remove: nothing left to do.
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(format!("removing {}: {e}", path.display())),
    }
}

#[cfg(test)]
mod tests;
