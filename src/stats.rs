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
struct HookRunRecord {
    #[serde(rename = "t")]
    timestamp: String,
    tool: String,
    #[serde(rename = "by")]
    counts_by_pattern: BTreeMap<String, u64>,
}

/// Best-effort append: every error is swallowed so stats can never break the hook.
pub fn record(path: &Path, tool: &str, counts_by_pattern: &BTreeMap<String, usize>) {
    if counts_by_pattern.is_empty() {
        return;
    }
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let record = HookRunRecord {
        timestamp: format_rfc3339_utc(secs),
        tool: tool.to_string(),
        counts_by_pattern: counts_by_pattern
            .iter()
            .map(|(k, &v)| (k.clone(), v as u64))
            .collect(),
    };
    let Ok(mut line) = serde_json::to_string(&record) else {
        return;
    };
    line.push('\n');
    if let Some(dir) = path.parent() {
        let _ = fs::create_dir_all(dir);
    }
    let mut options = OpenOptions::new();
    options.append(true).create(true);
    #[cfg(unix)]
    options.mode(0o600);
    if let Ok(mut file) = options.open(path) {
        let _ = file.write_all(line.as_bytes());
    }
}

#[derive(Debug, Default)]
pub struct Summary {
    pub hook_runs: u64,
    pub total_redactions: u64,
    pub counts_by_pattern: BTreeMap<String, u64>,
}

/// A missing file is an empty summary; malformed lines are skipped.
pub fn aggregate(path: &Path) -> std::io::Result<Summary> {
    let mut summary = Summary::default();
    let data = match fs::read_to_string(path) {
        Ok(data) => data,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(summary),
        Err(e) => return Err(e),
    };
    for line in data.lines().filter(|l| !l.is_empty()) {
        let Ok(record) = serde_json::from_str::<HookRunRecord>(line) else {
            continue;
        };
        summary.hook_runs += 1;
        for (name, count) in record.counts_by_pattern {
            *summary.counts_by_pattern.entry(name).or_default() += count;
            summary.total_redactions += count;
        }
    }
    Ok(summary)
}

pub fn render(summary: &Summary) -> String {
    if summary.total_redactions == 0 {
        return "No redactions recorded yet.\n".to_string();
    }
    let mut rows: Vec<_> = summary.counts_by_pattern.iter().collect();
    rows.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
    let mut out = format!(
        "Redactions: {} across {} hook runs\n\nBy pattern:\n",
        summary.total_redactions, summary.hook_runs
    );
    for (name, count) in rows {
        out.push_str(&format!("  {name:<22} {count}\n"));
    }
    out
}

// Civil-from-days (Howard Hinnant), so no date crate is needed.
fn format_rfc3339_utc(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let secs_of_day = secs % 86_400;
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
        secs_of_day / 3600,
        secs_of_day % 3600 / 60,
        secs_of_day % 60
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
mod tests;
