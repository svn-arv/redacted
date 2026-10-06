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

use crate::config::{self, Learned};
use crate::scrub::{learned_hint, sha256_hex};
use crate::settings;

/// Prompting happens only here and in the steps below; every function they call
/// is tested without a TTY.
pub fn run(env: Option<PathBuf>, local: bool) -> Result<(), String> {
    if !io::stdin().is_terminal() {
        return Err("init needs an interactive terminal".to_string());
    }
    prompt_and_install(env, local).map_err(|e| format!("init: {e}"))
}

fn prompt_and_install(env: Option<PathBuf>, local: bool) -> Result<(), String> {
    let home = config::home().ok_or("cannot determine home directory".to_string())?;
    let cwd =
        std::env::current_dir().map_err(|e| format!("cannot determine working directory: {e}"))?;
    let env = match env {
        Some(path) => Some(path),
        None => pick_env_file(&cwd)?,
    };
    match env {
        Some(path) => learn_from_env(&path, &home)?,
        None => println!("No .env file found; installing the hook only."),
    }
    install(local, &cwd, &home)
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
    let pairs = parse_dotenv(&text);
    if pairs.is_empty() {
        return Ok(());
    }
    let entries: Vec<_> = pairs.iter().map(|(k, v)| learn(k, v)).collect();
    let rows: Vec<String> = pairs
        .iter()
        .zip(&entries)
        .map(|((k, v), l)| row(k, v, l))
        .collect();
    let defaults: Vec<usize> = (0..rows.len())
        .filter(|&i| entries[i].is_ok() && preselect(&pairs[i].1))
        .collect();
    let picked = MultiSelect::new("Secrets to learn:", rows)
        .with_default(&defaults)
        .raw_prompt()
        .map_err(|e| e.to_string())?;
    // Ticked rows that cannot be learned are skipped, not written.
    let chosen: Vec<Learned> = picked
        .iter()
        .filter_map(|o| entries[o.index].clone().ok())
        .collect();
    let config_path = config::global_path(home);
    let existing = match fs::read_to_string(&config_path) {
        Ok(s) => s,
        Err(e) if e.kind() == io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(format!("reading {}: {e}", config_path.display())),
    };
    let merged = merge_config(&existing, &chosen)?;
    println!("\n{} will contain:\n\n{merged}", config_path.display());
    let ok = Confirm::new("Write it?")
        .with_default(false)
        .prompt()
        .map_err(|e| e.to_string())?;
    if !ok {
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

/// Registers the hook globally or for this project, then warns when only the
/// vendor tier would be active.
fn install(local: bool, cwd: &Path, home: &Path) -> Result<(), String> {
    let bin = bin_path()?;
    let settings_path = if local {
        cwd.join(".claude/settings.local.json")
    } else {
        home.join(".claude/settings.json")
    };
    settings::install_hook(&settings_path, &bin)?;
    let scope = if local { "local" } else { "global" };
    println!(
        "Installed redacted hook ({scope}) in {}",
        settings_path.display()
    );
    println!("Binary: {bin} scrub");
    // Judged on the written global config alone (no cwd), so a re-run with no .env
    // does not warn a user who has entries.
    if config::vendor_only(&config::load(Some(home), None)) {
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

/// `KEY=value` lines with optional `export`, quotes and `#` comments; empty values skipped.
fn parse_dotenv(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        let line = line.strip_prefix("export ").unwrap_or(line);
        let Some((key, raw)) = line.split_once('=') else {
            continue;
        };
        let (key, raw) = (key.trim(), raw.trim());
        if key.is_empty() || key.starts_with('#') || key.contains(char::is_whitespace) {
            continue;
        }
        // A comment after an unquoted value starts at ` #`.
        let mut value = match raw.find(" #") {
            Some(i) => &raw[..i],
            None => raw,
        }
        .trim();
        for q in ['"', '\''] {
            if let Some(rest) = raw.strip_prefix(q) {
                if let Some(end) = rest.rfind(q) {
                    value = &rest[..end];
                }
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
    let cut = sample[..head_end].rfind(['_', '-'])? + 1;
    let (prefix, rest) = sample.split_at(cut);
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
    let n = rest.chars().count();
    Some(format!(
        r"\b{}[{charset}]{{{},{}}}\b",
        regex::escape(prefix),
        n.saturating_sub(4).max(1),
        n + 4
    ))
}

/// Err is the reason the value cannot be learned, shown in the picker.
pub fn learn(key: &str, value: &str) -> Result<Learned, &'static str> {
    if value.contains(char::is_whitespace) {
        return Err("cannot match (contains spaces)");
    }
    if value.chars().count() < 8 {
        return Err("too short");
    }
    Ok(Learned {
        name: key.to_lowercase(),
        sha256: sha256_hex(value),
        len: value.len(),
        shape: derive_shape(value),
    })
}

/// Ticked by default only with 2+ of {lower, upper, digit, other}: `development`
/// or `3000` are config, not secrets, and would redact everywhere.
fn preselect(value: &str) -> bool {
    let classes = [
        value.chars().any(|c| c.is_lowercase()),
        value.chars().any(|c| c.is_uppercase()),
        value.chars().any(|c| c.is_ascii_digit()),
        value.chars().any(|c| !c.is_alphanumeric()),
    ];
    classes.iter().filter(|&&has| has).count() >= 2
}

fn row(key: &str, value: &str, l: &Result<Learned, &str>) -> String {
    let l = match l {
        Ok(l) => l,
        Err(reason) => return format!("{key}  {reason}"),
    };
    let hint = match learned_hint(value) {
        "" => "(short)".to_string(),
        h => format!("...{h}"),
    };
    format!(
        "{key}  {hint}  {}",
        l.shape.as_deref().unwrap_or("exact only")
    )
}

/// Merges `entries` by name into the config text, keeping every other field.
fn merge_config(existing: &str, entries: &[Learned]) -> Result<String, String> {
    let mut doc = if existing.trim().is_empty() {
        serde_yaml::Value::Mapping(Default::default())
    } else {
        serde_yaml::from_str(existing).map_err(|e| format!("parsing config: {e}"))?
    };
    let map = doc
        .as_mapping_mut()
        .ok_or("config is not a YAML mapping".to_string())?;
    let mut learned: Vec<Learned> = match map.get("learned") {
        Some(v) => {
            serde_yaml::from_value(v.clone()).map_err(|e| format!("parsing learned: {e}"))?
        }
        None => Vec::new(),
    };
    for e in entries {
        match learned.iter_mut().find(|l| l.name == e.name) {
            Some(slot) => *slot = e.clone(),
            None => learned.push(e.clone()),
        }
    }
    map.insert("version".into(), 2.into());
    map.insert(
        "learned".into(),
        serde_yaml::to_value(&learned).map_err(|e| e.to_string())?,
    );
    serde_yaml::to_string(&doc).map_err(|e| e.to_string())
}

/// Owner-only: the file holds hashes of the user's secrets.
fn write_config(path: &Path, contents: &str) -> io::Result<()> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    opts.mode(0o600);
    opts.open(path)?.write_all(contents.as_bytes())?;
    // mode() only applies on create; tighten a file that already existed.
    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

/// This executable, never a `redacted` found on PATH: a writable PATH directory
/// could otherwise register its own binary as the hook.
fn bin_path() -> Result<String, String> {
    std::env::current_exe()
        .and_then(std::path::absolute)
        .map(|p| p.display().to_string())
        .map_err(|e| format!("cannot determine redacted binary path: {e}"))
}

/// `redacted uninstall`: removes the hook from both settings files (or the local
/// one only); the global config is kept so a reinstall keeps its learned secrets.
/// A file that fails is reported and skipped, so the other one is still cleaned.
pub fn uninstall(local: bool) -> Result<(), String> {
    let home = config::home();
    let cwd = std::env::current_dir().unwrap_or_default();
    let mut paths = Vec::new();
    // Without a HOME there is no global file, only the local one.
    if !local {
        if let Some(home) = &home {
            paths.push(home.join(".claude/settings.json"));
        }
    }
    paths.push(cwd.join(".claude/settings.local.json"));
    let mut removed = 0;
    let mut errors = Vec::new();
    for path in paths {
        match settings::remove_hook(&path) {
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
    if let Some(home) = &home {
        let config_path = config::global_path(home);
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
mod tests {
    use super::*;
    use crate::config::Learned;
    use std::fs;
    use std::path::PathBuf;

    fn tmp(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("redacted-init-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn derive_shape_needs_a_short_separated_prefix() {
        let stripe = format!("sk_live_{}", "Ab1".repeat(8));
        let gh = format!("ghp_{}", "aB3".repeat(12));
        let slack = format!("xoxb-{}-{}", "1".repeat(12), "2".repeat(12));
        // Built at runtime so no secret-shaped literal sits in the source.
        let hubspot = format!(
            "pat-na1-{}-{}",
            "0a1b-".repeat(4).trim_end_matches('-'),
            "0a1b2c3d4e5f"
        );
        let aws = format!("AKIA{}", "Q7".repeat(8));
        let lang = format!("lsv2_pt_{}", "Zz9".repeat(10));
        for (sample, want) in [
            (stripe.as_str(), Some(r"\bsk_live_[a-zA-Z0-9]{20,28}\b")),
            (&gh, Some(r"\bghp_[a-zA-Z0-9]{32,40}\b")),
            (&slack, Some(r"\bxoxb\-[0-9-]{21,29}\b")),
            (&hubspot, Some(r"\bpat\-na1\-[a-z0-9-]{28,36}\b")),
            (&lang, Some(r"\blsv2_pt_[a-zA-Z0-9]{26,34}\b")),
            ("abc_xy", Some(r"\babc_[a-z]{1,6}\b")),
            // No separator: exact hash only (AKIA keys land here).
            (&aws, None),
            // Separator past the 12th character.
            ("abcdefghijklm_nopqrstu", None),
            // Prefix shorter than 3 characters.
            ("a_bcdefghijk", None),
            // Characters outside the shape charset: a band would match a truncated prefix.
            ("key_abc/def+ghi=", None),
            ("abc_", None),
        ] {
            assert_eq!(derive_shape(sample).as_deref(), want, "{sample}");
        }
    }

    #[test]
    fn derived_shapes_compile_and_match_their_sample() {
        let sample = format!("pat-na1-{}", "0a1b2c3d-".repeat(4));
        let shape = derive_shape(sample.trim_end_matches('-')).unwrap();
        let re = regex::Regex::new(&shape).unwrap();
        assert!(re.is_match(sample.trim_end_matches('-')));
    }

    #[test]
    fn parse_dotenv_handles_export_quotes_and_comments() {
        let text = "# comment\n\nexport A=1\nB = \"two words\" # trailing\nC='single'\nD=bare # note\nEMPTY=\nQUOTED_EMPTY=\"\"\nnot a pair\n  E=x=y\n";
        let got = parse_dotenv(text);
        let want: Vec<(String, String)> = [
            ("A", "1"),
            ("B", "two words"),
            ("C", "single"),
            ("D", "bare"),
            ("E", "x=y"),
        ]
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
        assert_eq!(got, want);
    }

    #[test]
    fn find_env_files_skips_examples_and_sorts() {
        let dir = tmp("find");
        for name in [
            ".env",
            ".env.local",
            ".env.example",
            ".env.sample",
            ".env.template",
            "env",
            "README",
        ] {
            fs::write(dir.join(name), "A=1\n").unwrap();
        }
        fs::create_dir_all(dir.join(".env.d")).unwrap();
        let names: Vec<_> = find_env_files(&dir)
            .iter()
            .map(|p| p.file_name().unwrap().to_str().unwrap().to_string())
            .collect();
        assert_eq!(names, [".env", ".env.local"]);
    }

    #[test]
    fn learn_hashes_the_value_and_lowercases_the_name() {
        let value = format!("sk_live_{}", "Ab1".repeat(8));
        let l = learn("STRIPE_KEY", &value).unwrap();
        assert_eq!(l.name, "stripe_key");
        assert_eq!(l.sha256, crate::scrub::sha256_hex(&value));
        assert_eq!(l.len, value.len());
        assert_eq!(l.shape, derive_shape(&value));
    }

    #[test]
    fn learn_rejects_values_under_eight_characters() {
        // Learned values redact everywhere, so `PORT=3000` would hide every 3000 in output.
        for v in ["3000", "true", "Pw9xQz7"] {
            assert_eq!(learn("K", v).unwrap_err(), "too short", "{v}");
        }
        assert!(learn("K", "Pw9xQz7k").is_ok());
        assert!(row("PORT", "3000", &learn("PORT", "3000")).contains("too short"));
    }

    #[test]
    fn only_values_with_two_character_classes_are_preselected() {
        // Listed in the picker, just not ticked by default.
        assert!(learn("NODE_ENV", "development").is_ok());
        let hex = "9f86d081884c7d659a2feaa0c55ad015";
        for (v, want) in [
            ("development", false),
            ("DEVELOPMENT", false),
            ("2024010112", false),
            ("P@ssw0rd2024", true),
            (hex, true),
        ] {
            assert_eq!(preselect(v), want, "{v}");
        }
    }

    #[test]
    fn learn_rejects_a_value_with_spaces() {
        // Candidates never span whitespace, so such a value could never be redacted.
        assert_eq!(
            learn("GREETING", "hello there world").unwrap_err(),
            "cannot match (contains spaces)"
        );
        let r = row(
            "GREETING",
            "hello there world",
            &learn("GREETING", "hello there world"),
        );
        assert!(
            r.contains("cannot match (contains spaces)") && !r.contains("hello"),
            "{r}"
        );
    }

    #[test]
    fn row_shows_key_hint_and_shape_never_the_value() {
        let value = format!("sk_live_{}", "Ab1".repeat(8));
        let r = row("STRIPE_KEY", &value, &learn("STRIPE_KEY", &value));
        assert!(
            r.contains("STRIPE_KEY") && r.contains("...",) && r.contains("Ab1"),
            "{r}"
        );
        assert!(r.contains(r"\bsk_live_") && !r.contains(&value), "{r}");
        let short = row("PIN", "Pw9xQz7k", &learn("PIN", "Pw9xQz7k"));
        assert!(
            short.contains("exact only") && !short.contains("Qz7k"),
            "{short}"
        );
    }

    #[test]
    fn merge_config_keeps_other_fields_and_merges_by_name() {
        let existing = "whitelist: [jwt]\nfuture_field: {a: 1}\nlearned:\n- {name: keep, sha256: aa, len: 1}\n- {name: stripe_key, sha256: old, len: 1}\n";
        let new = Learned {
            name: "stripe_key".into(),
            sha256: "new".into(),
            len: 32,
            shape: Some("s".into()),
        };
        let added = Learned {
            name: "db_pass".into(),
            sha256: "bb".into(),
            len: 9,
            shape: None,
        };
        let out = merge_config(existing, &[new.clone(), added.clone()]).unwrap();
        let doc: serde_yaml::Value = serde_yaml::from_str(&out).unwrap();
        assert_eq!(doc["version"], serde_yaml::Value::from(2));
        assert_eq!(doc["whitelist"][0], serde_yaml::Value::from("jwt"));
        assert_eq!(doc["future_field"]["a"], serde_yaml::Value::from(1));
        let learned: Vec<Learned> = serde_yaml::from_value(doc["learned"].clone()).unwrap();
        let names: Vec<_> = learned.iter().map(|l| l.name.as_str()).collect();
        assert_eq!(names, ["keep", "stripe_key", "db_pass"]);
        assert_eq!(learned[1], new);
        assert!(
            !out.contains("shape: null"),
            "absent shape is omitted:\n{out}"
        );

        assert!(merge_config("", &[added])
            .unwrap()
            .starts_with("version: 2\n"));
    }

    #[test]
    fn merge_config_rejects_a_non_mapping() {
        // Rewriting a list or scalar as a mapping would drop what the user wrote.
        assert!(merge_config("[not, a, map]", &[]).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn write_config_is_owner_only_even_over_an_existing_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tmp("write");
        let path = dir.join("nested/config.yaml");
        write_config(&path, "a: 1\n").unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        write_config(&path, "a: 2\n").unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(fs::read_to_string(&path).unwrap(), "a: 2\n");
    }

    #[test]
    fn bin_path_ignores_a_redacted_file_on_path() {
        // A writable PATH directory must not get its own binary registered as the hook.
        let dir = tmp("path");
        fs::write(dir.join("redacted"), "#!/bin/sh\n").unwrap();
        let old = std::env::var_os("PATH").unwrap_or_default();
        let mut paths = vec![dir.clone()];
        paths.extend(std::env::split_paths(&old));
        std::env::set_var("PATH", std::env::join_paths(paths).unwrap());
        let got = bin_path();
        std::env::set_var("PATH", old);
        // Not canonicalized: a Homebrew symlink must stay, its Cellar target goes on upgrade.
        let want = std::path::absolute(std::env::current_exe().unwrap()).unwrap();
        assert_eq!(got.unwrap(), want.display().to_string());
    }
}
