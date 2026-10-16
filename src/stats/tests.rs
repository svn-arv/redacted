//! Unit tests for the stats log.

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
    let summary = aggregate(&path).unwrap();
    assert_eq!((summary.hook_runs, summary.total_redactions), (2, 4));
    assert_eq!(summary.counts_by_pattern["jwt"], 3);
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
    assert_eq!(aggregate(&path).unwrap().hook_runs, 0);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(
        &path,
        "not json\n\n{\"by\":{\"jwt\":1.5}}\n{\"by\":{\"jwt\":2}}\n",
    )
    .unwrap();
    let summary = aggregate(&path).unwrap();
    assert_eq!((summary.hook_runs, summary.total_redactions), (1, 2));
}

#[test]
fn render_sorts_by_count_then_name() {
    let summary = Summary {
        hook_runs: 2,
        total_redactions: 4,
        counts_by_pattern: BTreeMap::from([
            ("npm_token".into(), 1),
            ("jwt".into(), 1),
            ("env_secret".into(), 2),
        ]),
    };
    assert_eq!(
        render(&summary),
        "Redactions: 4 across 2 hook runs\n\nBy pattern:\n  env_secret             2\n  jwt                    1\n  npm_token              1\n"
    );
    assert_eq!(render(&Summary::default()), "No redactions recorded yet.\n");
}

#[test]
fn timestamps_are_rfc3339_utc_including_leap_days() {
    assert_eq!(format_rfc3339_utc(0), "1970-01-01T00:00:00Z");
    assert_eq!(format_rfc3339_utc(1_700_000_000), "2023-11-14T22:13:20Z");
    assert_eq!(format_rfc3339_utc(951_782_400), "2000-02-29T00:00:00Z");
}
