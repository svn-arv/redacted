//! `redacted init`: learn secrets from a .env file into the global config, then
//! install the hook.

use std::fs;
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};
// A trait's methods only exist once the trait is imported: these add the unix
// `mode` to OpenOptions and `from_mode` to Permissions.
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use inquire::{Confirm, MultiSelect, Select};

use crate::cli::Format;
use crate::config::{self, LearnedSecret};
use crate::scrub::{learned_value_hint, percent_decode, sha256_hex};
use crate::{opencode, settings};

/// Prompting happens only here and in the steps below; every function they call
/// is tested without a TTY.
pub fn run(env_file: Option<PathBuf>, local: bool, format: Format) -> Result<(), String> {
    if !io::stdin().is_terminal() {
        return Err("init needs an interactive terminal".to_string());
    }
    prompt_and_install(env_file, local, format).map_err(|e| format!("init: {e}"))
}

fn prompt_and_install(
    env_file: Option<PathBuf>,
    local: bool,
    format: Format,
) -> Result<(), String> {
    let home = config::home_dir().ok_or("cannot determine home directory".to_string())?;
    let cwd =
        std::env::current_dir().map_err(|e| format!("cannot determine working directory: {e}"))?;
    let env_file = match env_file {
        Some(path) => Some(path),
        None => pick_env_file(&cwd)?,
    };
    match env_file {
        Some(path) => learn_from_env(&path, &home)?,
        None => println!("No .env file found; installing the hook only."),
    }
    install(format, local, &cwd, &home)
}

/// The only `.env*` file in `cwd`, or the user's pick when there are several.
fn pick_env_file(cwd: &Path) -> Result<Option<PathBuf>, String> {
    let mut files = find_env_files(cwd);
    if files.len() <= 1 {
        return Ok(files.pop());
    }
    let names: Vec<String> = files.iter().map(|p| p.display().to_string()).collect();
    let pick = Select::new("Which env file?", names)
        .raw_prompt()
        .map_err(|e| e.to_string())?;
    Ok(Some(files.swap_remove(pick.index)))
}

/// Lets the user tick the secrets in `path`, shows the merged global config and
/// writes it only after a confirm.
fn learn_from_env(path: &Path, home: &Path) -> Result<(), String> {
    let text = fs::read_to_string(path).map_err(|e| format!("reading {}: {e}", path.display()))?;
    let pairs = with_url_passwords(parse_dotenv(&text));
    if pairs.is_empty() {
        return Ok(());
    }
    let known = config::load(Some(home), None)?.learned;
    let chosen = pick_secrets_to_learn(&pairs, &known)?;
    let config_path = config::global_config_path(home);
    let existing = match fs::read_to_string(&config_path) {
        Ok(s) => s,
        Err(e) if e.kind() == io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(format!("reading {}: {e}", config_path.display())),
    };
    let merged = merge_learned_into_config(&existing, &chosen)?;
    println!("\n{} will contain:\n\n{merged}", config_path.display());
    let confirmed = Confirm::new("Write it?")
        .with_default(false)
        .prompt()
        .map_err(|e| e.to_string())?;
    if !confirmed {
        return Err("nothing written".into());
    }
    write_config(&config_path, &merged)
        .map_err(|e| format!("writing {}: {e}", config_path.display()))?;
    println!(
        "Learned {} secret(s) in {}",
        chosen.len(),
        config_path.display()
    );
    Ok(())
}

/// The secrets the user ticks among `pairs`, with likely and `known` secrets
/// ticked up front.
fn pick_secrets_to_learn(
    pairs: &[(String, String)],
    known: &[LearnedSecret],
) -> Result<Vec<LearnedSecret>, String> {
    let learn_results: Vec<_> = pairs.iter().map(|(key, value)| learn(key, value)).collect();
    let rows: Vec<String> = pairs
        .iter()
        .zip(&learn_results)
        .map(|((key, value), learned)| picker_row(key, value, learned, known))
        .collect();
    let defaults: Vec<usize> = (0..rows.len())
        .filter(|&i| {
            learn_results[i]
                .as_ref()
                .is_ok_and(|entry| should_preselect(entry, &pairs[i].1, known))
        })
        .collect();
    let picked = MultiSelect::new("Secrets to learn:", rows)
        .with_default(&defaults)
        .raw_prompt()
        .map_err(|e| e.to_string())?;
    // Ticked rows that cannot be learned are skipped, not written.
    let chosen: Vec<LearnedSecret> = picked
        .iter()
        .filter_map(|picked_row| learn_results[picked_row.index].clone().ok())
        .collect();
    Ok(chosen)
}

/// Registers the hook globally or for this project, then warns when only the
/// vendor tier would be active.
fn install(format: Format, local: bool, cwd: &Path, home: &Path) -> Result<(), String> {
    // Loaded before anything is written: a hook over a malformed config would withhold every output.
    // The global config alone (no cwd), so a re-run with no .env does not warn a user who has entries.
    let global_config = config::load(Some(home), None)?;
    let scope = if local { "local" } else { "global" };
    let hook_path = hook_path(format, local, if local { cwd } else { home });
    let binary = match format {
        Format::Claude => {
            let bin = this_executable_path()?;
            settings::install_hook(&hook_path, &bin)?;
            format!("{bin} scrub")
        }
        // The plugin names no path, so the same file works when copied by hand.
        // A rerun overwrites it, so an upgrade picks up the plugin this binary ships.
        Format::Opencode => {
            if let Some(dir) = hook_path.parent() {
                fs::create_dir_all(dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
            }
            fs::write(&hook_path, opencode::PLUGIN_SOURCE)
                .map_err(|e| format!("writing {}: {e}", hook_path.display()))?;
            "redacted on PATH, or $REDACTED_BIN".to_string()
        }
    };
    println!(
        "Installed redacted hook ({scope}) in {}",
        hook_path.display()
    );
    println!("Binary: {binary}");
    if config::is_vendor_only(&global_config) {
        println!("\nNotice: {}", config::VENDOR_ONLY_NOTICE);
    }
    Ok(())
}

/// `.env*` files in `dir`, minus example/sample/template ones, sorted.
fn find_env_files(dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    // `flatten` skips the entries that failed to read.
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = entry.file_name().to_str().map(str::to_lowercase) else {
            continue;
        };
        let is_template = ["example", "sample", "template"]
            .iter()
            .any(|w| name.contains(w));
        if path.is_file() && name.starts_with(".env") && !is_template {
            out.push(path);
        }
    }
    out.sort();
    out
}

/// `KEY=value` lines with optional `export` and quotes, commented-out ones included; empty values skipped.
fn parse_dotenv(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for line in text.lines() {
        // A commented-out assignment is still a secret in the file, so drop the `#` and parse it.
        let line = line.trim().trim_start_matches('#').trim_start();
        let line = line.strip_prefix("export ").unwrap_or(line);
        let Some((key, raw)) = line.split_once('=') else {
            continue;
        };
        let (key, raw) = (key.trim(), raw.trim());
        if key.is_empty() || key.contains(char::is_whitespace) {
            continue;
        }
        // A comment after an unquoted value starts at ` #`.
        let mut value = match raw.find(" #") {
            Some(i) => &raw[..i],
            None => raw,
        }
        .trim();
        for q in ['"', '\''] {
            if let Some(rest) = raw.strip_prefix(q)
                && let Some(end) = rest.rfind(q)
            {
                value = &rest[..end];
            }
        }
        if !value.is_empty() {
            out.push((key.to_string(), value.to_string()));
        }
    }
    out
}

/// A literal prefix ending in the last `_`/`-` of the first 12 chars, 3+ chars long,
/// plus the remainder's charset and a length band of ±4. None means exact hash only.
fn derive_shape(sample: &str) -> Option<String> {
    // Byte index of the 13th char, so the slice never splits a multi-byte char.
    let head_end = sample
        .char_indices()
        .nth(12)
        .map_or(sample.len(), |(i, _)| i);
    let prefix_end = sample[..head_end].rfind(['_', '-'])? + 1;
    let (prefix, rest) = sample.split_at(prefix_end);
    if prefix.chars().count() < 3 || rest.is_empty() {
        return None;
    }
    if !rest
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return None;
    }
    let charset: String = [
        (rest.chars().any(|c| c.is_ascii_lowercase()), "a-z"),
        (rest.chars().any(|c| c.is_ascii_uppercase()), "A-Z"),
        (rest.chars().any(|c| c.is_ascii_digit()), "0-9"),
        (rest.contains('_'), "_"),
        (rest.contains('-'), "-"),
    ]
    .iter()
    .filter(|(present, _)| *present)
    .map(|(_, class)| *class)
    .collect();
    let rest_len = rest.chars().count();
    Some(format!(
        r"\b{}[{charset}]{{{},{}}}\b",
        regex::escape(prefix),
        rest_len.saturating_sub(4).max(1),
        rest_len + 4
    ))
}

/// The password in `scheme://user:password@host`, percent-decoded.
fn url_password(value: &str) -> Option<String> {
    let (_, after_scheme) = value.split_once("://")?;
    let authority_end = after_scheme
        .find(['/', '?', '#'])
        .unwrap_or(after_scheme.len());
    // The last `@` ends the userinfo, so an unencoded `@` in the password stays in it.
    let (userinfo, _) = after_scheme[..authority_end].rsplit_once('@')?;
    let (_, password) = userinfo.split_once(':')?;
    if password.is_empty() {
        return None;
    }
    Some(String::from_utf8(percent_decode(password)).unwrap_or_else(|_| password.to_string()))
}

/// Each pair, followed by a `<KEY>_PASSWORD` pair when its value is a URL with a password.
fn with_url_passwords(pairs: Vec<(String, String)>) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for (key, value) in pairs {
        let password = url_password(&value);
        let password_key = format!("{key}_PASSWORD");
        out.push((key, value));
        if let Some(password) = password {
            out.push((password_key, password));
        }
    }
    out
}

/// Err is the reason the value cannot be learned, shown in the picker.
pub fn learn(key: &str, value: &str) -> Result<LearnedSecret, &'static str> {
    if value.contains(char::is_whitespace) {
        return Err("cannot match (contains spaces)");
    }
    if value.chars().count() < 8 {
        return Err("too short");
    }
    Ok(LearnedSecret {
        name: key.to_lowercase(),
        sha256: sha256_hex(value),
        byte_len: value.len(),
        shape: derive_shape(value),
    })
}

/// Ticked by default when the config already holds the key or the value, else
/// only with 2+ of {lower, upper, digit, other}: `development` or `3000` are
/// config, not secrets, and would redact everywhere.
fn should_preselect(entry: &LearnedSecret, value: &str, known: &[LearnedSecret]) -> bool {
    let is_in_config = known
        .iter()
        .any(|learned| learned.sha256 == entry.sha256 || learned.name == entry.name);
    let classes = [
        value.chars().any(|c| c.is_lowercase()),
        value.chars().any(|c| c.is_uppercase()),
        value.chars().any(|c| c.is_ascii_digit()),
        value.chars().any(|c| !c.is_alphanumeric()),
    ];
    is_in_config || classes.iter().filter(|&&has| has).count() >= 2
}

fn picker_row(
    key: &str,
    value: &str,
    learned: &Result<LearnedSecret, &str>,
    known: &[LearnedSecret],
) -> String {
    let entry = match learned {
        Ok(entry) => entry,
        Err(reason) => return format!("{key}  {reason}"),
    };
    // Matched by hash first: the scrubber keeps one label per value, whatever its key.
    if let Some(same_value) = known.iter().find(|learned| learned.sha256 == entry.sha256) {
        if same_value.name == entry.name {
            return format!("{key}  learned");
        }
        return format!("{key}  learned as {}", same_value.name);
    }
    if known.iter().any(|learned| learned.name == entry.name) {
        let written_as = unused_name(known, &entry.name);
        return format!("{key}  new value, kept as {written_as}");
    }
    let hint = match learned_value_hint(value) {
        Some(hint) => format!("...{hint}"),
        None => "(short)".to_string(),
    };
    format!(
        "{key}  {hint}  {}",
        entry.shape.as_deref().unwrap_or("exact only")
    )
}

/// Merges `entries` into the config text, keeping every other field. A value
/// already learned is never added twice, whatever its key; a new value under a
/// taken name gets a numeric suffix.
fn merge_learned_into_config(existing: &str, entries: &[LearnedSecret]) -> Result<String, String> {
    let mut doc = if existing.trim().is_empty() {
        serde_yaml::Value::Mapping(Default::default())
    } else {
        serde_yaml::from_str(existing).map_err(|e| format!("parsing config: {e}"))?
    };
    let map = doc
        .as_mapping_mut()
        .ok_or("config is not a YAML mapping".to_string())?;
    let mut learned: Vec<LearnedSecret> = match map.get("learned") {
        Some(v) => {
            serde_yaml::from_value(v.clone()).map_err(|e| format!("parsing learned: {e}"))?
        }
        None => Vec::new(),
    };
    for entry in entries {
        // The scrubber keeps one label per hash, so a second name would be dead data.
        if learned.iter().any(|known| known.sha256 == entry.sha256) {
            continue;
        }
        let name = unused_name(&learned, &entry.name);
        learned.push(LearnedSecret {
            name,
            ..entry.clone()
        });
    }
    map.insert("version".into(), 2.into());
    map.insert(
        "learned".into(),
        serde_yaml::to_value(&learned).map_err(|e| e.to_string())?,
    );
    serde_yaml::to_string(&doc).map_err(|e| e.to_string())
}

/// `name`, or the first `name_2`, `name_3`, ... not already in `learned`.
fn unused_name(learned: &[LearnedSecret], name: &str) -> String {
    let is_taken = |candidate: &str| learned.iter().any(|known| known.name == candidate);
    std::iter::once(name.to_string())
        .chain((2..).map(|number| format!("{name}_{number}")))
        .find(|candidate| !is_taken(candidate))
        .expect("an unbounded range always has a free name")
}

/// Owner-only: the file holds hashes of the user's secrets.
fn write_config(path: &Path, contents: &str) -> io::Result<()> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    options.mode(0o600);
    options.open(path)?.write_all(contents.as_bytes())?;
    // mode() only applies on create; tighten a file that already existed.
    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

/// Where `format`'s hook lives under `dir`: the home directory, or the project with `local`.
fn hook_path(format: Format, local: bool, dir: &Path) -> PathBuf {
    match (format, local) {
        (Format::Claude, true) => dir.join(".claude/settings.local.json"),
        (Format::Claude, false) => dir.join(".claude/settings.json"),
        (Format::Opencode, true) => opencode::local_plugin_path(dir),
        (Format::Opencode, false) => opencode::global_plugin_path(dir),
    }
}

/// This executable, never a `redacted` found on PATH: a writable PATH directory
/// could otherwise register its own binary as the hook.
fn this_executable_path() -> Result<String, String> {
    std::env::current_exe()
        .and_then(std::path::absolute)
        .map(|p| p.display().to_string())
        .map_err(|e| format!("cannot determine redacted binary path: {e}"))
}

/// `redacted uninstall`: removes the hook from both scopes (or the local one
/// only); the global config is kept so a reinstall keeps its learned secrets.
/// A file that fails is reported and skipped, so the other one is still cleaned.
pub fn uninstall(local: bool, format: Format) -> Result<(), String> {
    let home = config::home_dir();
    // as_deref() turns `Option<PathBuf>` into the borrowed `Option<&Path>`.
    let home = home.as_deref();
    let cwd = std::env::current_dir().unwrap_or_default();
    let mut paths = Vec::new();
    // Without a HOME there is no global file, only the local one.
    if !local && let Some(home) = home {
        paths.push(hook_path(format, false, home));
    }
    paths.push(hook_path(format, true, &cwd));
    let remove_hook = match format {
        Format::Claude => settings::remove_hook,
        Format::Opencode => opencode::remove_plugin,
    };
    let mut removed = 0;
    let mut errors = Vec::new();
    for path in paths {
        match remove_hook(&path) {
            Ok(true) => {
                println!("Removed redacted hook from {}", path.display());
                removed += 1;
            }
            Ok(false) => {}
            Err(e) => errors.push(format!("uninstall: {e}")),
        }
    }
    if removed == 0 && errors.is_empty() {
        println!("No redacted hooks found.");
    }
    if let Some(home) = home {
        let config_path = config::global_config_path(home);
        if config_path.exists() {
            println!("Config kept at {}", config_path.display());
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("\n"))
    }
}

#[cfg(test)]
mod tests;
