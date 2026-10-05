//! `redacted init`: learn secrets from a .env file into the global config, then
//! install the hook (the hook half ported from cmd/init.go).

use std::fs;
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};

use inquire::{Confirm, MultiSelect, Select};
use serde_json::{json, Value};

use crate::config::Learned;
use crate::scrub::{learned_hint, sha256_hex};

/// The only function that prompts; everything it calls is tested without a TTY.
pub fn run(env: Option<PathBuf>, local: bool) -> i32 {
    if !io::stdin().is_terminal() {
        eprintln!("init needs an interactive terminal");
        return 1;
    }
    match prompt_and_install(env, local) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("init: {e}");
            1
        }
    }
}

fn prompt_and_install(env: Option<PathBuf>, local: bool) -> Result<(), String> {
    let home = std::env::var("HOME").map_err(|_| "cannot determine home directory")?;
    let cwd =
        std::env::current_dir().map_err(|e| format!("cannot determine working directory: {e}"))?;
    let env = match env {
        Some(p) => Some(p),
        None => {
            let mut files = find_env_files(&cwd);
            match files.len() {
                0 => None,
                1 => files.pop(),
                _ => {
                    let names: Vec<String> =
                        files.iter().map(|p| p.display().to_string()).collect();
                    let pick = Select::new("Which env file?", names)
                        .raw_prompt()
                        .map_err(|e| e.to_string())?;
                    Some(files.swap_remove(pick.index))
                }
            }
        }
    };

    if let Some(path) = env {
        let text =
            fs::read_to_string(&path).map_err(|e| format!("reading {}: {e}", path.display()))?;
        let pairs = parse_dotenv(&text);
        let entries: Vec<Learned> = pairs.iter().map(|(k, v)| learn(k, v)).collect();
        let rows: Vec<String> = pairs
            .iter()
            .zip(&entries)
            .map(|((k, v), l)| row(k, v, l))
            .collect();
        if !rows.is_empty() {
            let picked = MultiSelect::new("Secrets to learn:", rows)
                .with_all_selected_by_default()
                .raw_prompt()
                .map_err(|e| e.to_string())?;
            let chosen: Vec<Learned> = picked.iter().map(|o| entries[o.index].clone()).collect();
            let config_path = Path::new(&home).join(".config/redacted/config.yaml");
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
        }
    } else {
        println!("No .env file found; installing the hook only.");
    }

    let bin = bin_path()?;
    let settings = if local {
        cwd.join(".claude/settings.local.json")
    } else {
        Path::new(&home).join(".claude/settings.json")
    };
    install_hook_to_path(&settings, &bin)?;
    let scope = if local { "local" } else { "global" };
    println!(
        "Installed redacted hook ({scope}) in {}",
        settings.display()
    );
    println!("Binary: {bin} scrub");
    Ok(())
}

/// `.env*` files in `dir`, minus example/sample/template ones, sorted.
fn find_env_files(dir: &Path) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_file())
        .filter(|p| {
            let name = p
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("")
                .to_lowercase();
            name.starts_with(".env")
                && !["example", "sample", "template"]
                    .iter()
                    .any(|w| name.contains(w))
        })
        .collect();
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
        let quoted = ['"', '\''].into_iter().find_map(|q| {
            let rest = raw.strip_prefix(q)?;
            rest.rfind(q).map(|end| &rest[..end])
        });
        let value = quoted.unwrap_or_else(|| raw.split(" #").next().unwrap_or("").trim());
        if !value.is_empty() {
            out.push((key.to_string(), value.to_string()));
        }
    }
    out
}

/// A literal prefix ending in the last `_`/`-` of the first 12 chars, 3+ chars long,
/// plus the remainder's charset and a length band of ±4. None means exact hash only.
fn derive_shape(sample: &str) -> Option<String> {
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

pub fn learn(key: &str, value: &str) -> Learned {
    Learned {
        name: key.to_lowercase(),
        sha256: sha256_hex(value),
        len: value.len(),
        shape: derive_shape(value),
    }
}

fn row(key: &str, value: &str, l: &Learned) -> String {
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
    let map = doc.as_mapping_mut().ok_or("config is not a YAML mapping")?;
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
    std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
    opts.open(path)?.write_all(contents.as_bytes())?;
    // mode() only applies on create; tighten a file that already existed.
    #[cfg(unix)]
    fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(0o600))?;
    Ok(())
}

/// `redacted` on PATH, else this executable, made absolute (Go's LookPath order).
fn bin_path() -> Result<String, String> {
    let on_path = std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths)
            .map(|d| d.join("redacted"))
            .find(|p| p.is_file())
    });
    let bin = match on_path {
        Some(p) => p,
        None => std::env::current_exe()
            .map_err(|e| format!("cannot determine redacted binary path: {e}"))?,
    };
    std::path::absolute(&bin)
        .map(|p| p.display().to_string())
        .map_err(|e| e.to_string())
}

/// Replaces any redacted entry in PostToolUse with one for `bin`; other entries
/// and settings are kept as-is.
fn install_hook_to_path(settings_path: &Path, bin: &str) -> Result<(), String> {
    let shown = settings_path.display();
    let mut settings: Value = match fs::read(settings_path) {
        Ok(data) => serde_json::from_slice(&data).map_err(|e| format!("parsing {shown}: {e}"))?,
        Err(e) if e.kind() == io::ErrorKind::NotFound => json!({}),
        Err(e) => return Err(format!("reading {shown}: {e}")),
    };
    let root = settings
        .as_object_mut()
        .ok_or(format!("parsing {shown}: not an object"))?;
    let hooks = root.entry("hooks").or_insert_with(|| json!({}));
    if !hooks.is_object() {
        *hooks = json!({});
    }
    let mut entries: Vec<Value> = hooks["PostToolUse"].as_array().cloned().unwrap_or_default();
    entries.retain(|e| !is_redacted_entry(e));
    entries.push(json!({"hooks": [{"type": "command", "command": format!("{bin} scrub")}]}));
    hooks["PostToolUse"] = Value::Array(entries);

    let out =
        serde_json::to_string_pretty(&settings).map_err(|e| format!("marshal settings: {e}"))?;
    if let Some(dir) = settings_path.parent() {
        fs::create_dir_all(dir).map_err(|e| format!("create config directory: {e}"))?;
    }
    fs::write(settings_path, out).map_err(|e| format!("writing {shown}: {e}"))
}

fn is_redacted_entry(entry: &Value) -> bool {
    entry["hooks"].as_array().is_some_and(|hooks| {
        hooks.iter().any(|h| {
            h["command"]
                .as_str()
                .is_some_and(|c| c.ends_with("redacted scrub"))
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Learned;
    use serde_json::{json, Value};
    use std::fs;
    use std::path::PathBuf;

    fn tmp(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("redacted-init-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn derive_shape_table() {
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
        let l = learn("STRIPE_KEY", &value);
        assert_eq!(l.name, "stripe_key");
        assert_eq!(l.sha256, crate::scrub::sha256_hex(&value));
        assert_eq!(l.len, value.len());
        assert_eq!(l.shape, derive_shape(&value));
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

    // Hook install, ported from cmd/init_test.go.

    fn post_tool_use(path: &std::path::Path) -> Vec<Value> {
        let v: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        v["hooks"]["PostToolUse"]
            .as_array()
            .cloned()
            .unwrap_or_default()
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
        install_hook_to_path(&path, "/usr/local/bin/redacted").unwrap();
        let entries = post_tool_use(&path);
        assert_eq!(
            entries,
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
        install_hook_to_path(&path, "/usr/local/bin/redacted").unwrap();
        let v: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(v["theme"], "dark");
        assert_eq!(v["hooks"]["PreToolUse"], existing["hooks"]["PreToolUse"]);
        assert_eq!(post_tool_use(&path).len(), 1);
    }

    #[test]
    fn install_hook_preserves_other_post_tool_use_hooks_verbatim() {
        let path = tmp("hook-other").join(".claude/settings.json");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        // Unknown fields like timeout must survive (Go's typed round-trip dropped them).
        let other = json!({"matcher": "Bash", "hooks": [{"type": "command", "command": "/usr/local/bin/other-hook", "timeout": 5}]});
        fs::write(
            &path,
            json!({"hooks": {"PostToolUse": [other]}}).to_string(),
        )
        .unwrap();
        install_hook_to_path(&path, "/usr/local/bin/redacted").unwrap();
        let entries = post_tool_use(&path);
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
        install_hook_to_path(&path, "/new/path/redacted").unwrap();
        let cmds = commands(&post_tool_use(&path));
        assert_eq!(
            cmds,
            ["/usr/local/bin/other-hook", "/new/path/redacted scrub"]
        );
    }

    #[test]
    fn install_hook_is_idempotent() {
        let path = tmp("hook-twice").join(".claude/settings.json");
        install_hook_to_path(&path, "/usr/local/bin/redacted").unwrap();
        install_hook_to_path(&path, "/usr/local/bin/redacted").unwrap();
        assert_eq!(post_tool_use(&path).len(), 1);
    }

    #[test]
    fn install_hook_rejects_invalid_existing_json() {
        let path = tmp("hook-bad").join(".claude/settings.json");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, "not json").unwrap();
        let err = install_hook_to_path(&path, "/usr/local/bin/redacted").unwrap_err();
        assert!(err.contains("parsing"), "{err}");
        assert_eq!(fs::read_to_string(&path).unwrap(), "not json");
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
