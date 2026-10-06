//! Per-pattern redaction counts appended as JSONL.
//! Only pattern names and counts are stored, never values.

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Write};
// A trait's methods only exist once the trait is imported: this adds `mode`.
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Default)]
#[serde(default)]
struct Event {
    t: String,
    tool: String,
    by: BTreeMap<String, u64>,
}

/// Best-effort append: every error is swallowed so stats can never break the hook.
pub fn record(path: &Path, tool: &str, by_pattern: &BTreeMap<String, usize>) {
    if by_pattern.is_empty() {
        return;
    }
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let event = Event {
        t: rfc3339(secs),
        tool: tool.to_string(),
        by: by_pattern
            .iter()
            .map(|(k, &v)| (k.clone(), v as u64))
            .collect(),
    };
    let Ok(mut line) = serde_json::to_string(&event) else {
        return;
    };
    line.push('\n');
    if let Some(dir) = path.parent() {
        let _ = fs::create_dir_all(dir);
    }
    let mut opts = OpenOptions::new();
    opts.append(true).create(true);
    #[cfg(unix)]
    opts.mode(0o600);
    let file = opts.open(path);
    if let Ok(mut f) = file {
        let _ = f.write_all(line.as_bytes());
    }
}

#[derive(Debug, Default)]
pub struct Summary {
    pub events: u64,
    pub total: u64,
    pub by_pattern: BTreeMap<String, u64>,
}

/// A missing file is an empty summary; malformed lines are skipped.
pub fn aggregate(path: &Path) -> std::io::Result<Summary> {
    let mut s = Summary::default();
    let data = match fs::read_to_string(path) {
        Ok(data) => data,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(s),
        Err(e) => return Err(e),
    };
    for line in data.lines().filter(|l| !l.is_empty()) {
        let Ok(e) = serde_json::from_str::<Event>(line) else {
            continue;
        };
        s.events += 1;
        for (name, n) in e.by {
            *s.by_pattern.entry(name).or_default() += n;
            s.total += n;
        }
    }
    Ok(s)
}

pub fn render(s: &Summary) -> String {
    if s.total == 0 {
        return "No redactions recorded yet.\n".to_string();
    }
    let mut rows: Vec<_> = s.by_pattern.iter().collect();
    rows.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
    let mut out = format!(
        "Redactions: {} across {} hook runs\n\nBy pattern:\n",
        s.total, s.events
    );
    for (name, n) in rows {
        out.push_str(&format!("  {name:<22} {n}\n"));
    }
    out
}

// Civil-from-days (Howard Hinnant), so no date crate is needed.
fn rfc3339(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

/// REDACTED_STATS_FILE overrides the default ~/.config/redacted/stats.jsonl.
pub fn file_path() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("REDACTED_STATS_FILE").filter(|p| !p.is_empty()) {
        return Some(PathBuf::from(p));
    }
    let home = crate::config::home_dir()?;
    Some(home.join(".config/redacted/stats.jsonl"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_file(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("redacted-stats-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir.join("nested/stats.jsonl")
    }

    #[test]
    fn record_then_aggregate_sums_per_pattern() {
        let path = temp_file("sum");
        record(&path, "Bash", &BTreeMap::from([("jwt".to_string(), 2)]));
        record(
            &path,
            "Read",
            &BTreeMap::from([("jwt".to_string(), 1), ("npm_token".to_string(), 1)]),
        );
        record(&path, "Read", &BTreeMap::new()); // nothing redacted: no line
        let s = aggregate(&path).unwrap();
        assert_eq!((s.events, s.total), (2, 4));
        assert_eq!(s.by_pattern["jwt"], 3);
    }

    #[test]
    fn record_writes_the_go_jsonl_schema() {
        let path = temp_file("schema");
        record(&path, "Bash", &BTreeMap::from([("jwt".to_string(), 1)]));
        let line = std::fs::read_to_string(&path).unwrap();
        let (head, rest) = line.split_at(6);
        assert_eq!(head, r#"{"t":""#);
        assert!(
            rest.ends_with("Z\",\"tool\":\"Bash\",\"by\":{\"jwt\":1}}\n"),
            "{line}"
        );
    }

    #[test]
    fn aggregate_skips_malformed_lines_and_missing_file() {
        let path = temp_file("bad");
        assert_eq!(aggregate(&path).unwrap().events, 0);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(
            &path,
            "not json\n\n{\"by\":{\"jwt\":1.5}}\n{\"by\":{\"jwt\":2}}\n",
        )
        .unwrap();
        let s = aggregate(&path).unwrap();
        assert_eq!((s.events, s.total), (1, 2));
    }

    #[test]
    fn render_sorts_by_count_then_name() {
        let s = Summary {
            events: 2,
            total: 4,
            by_pattern: BTreeMap::from([
                ("npm_token".into(), 1),
                ("jwt".into(), 1),
                ("env_secret".into(), 2),
            ]),
        };
        assert_eq!(
            render(&s),
            "Redactions: 4 across 2 hook runs\n\nBy pattern:\n  env_secret             2\n  jwt                    1\n  npm_token              1\n"
        );
        assert_eq!(render(&Summary::default()), "No redactions recorded yet.\n");
    }

    #[test]
    fn rfc3339_formats_utc() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(1_700_000_000), "2023-11-14T22:13:20Z");
        assert_eq!(rfc3339(951_782_400), "2000-02-29T00:00:00Z");
    }
}
