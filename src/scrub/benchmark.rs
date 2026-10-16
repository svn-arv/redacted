//! Detection benchmark: every built-in pattern planted in common output shapes.
//! `REDACTED_BENCHMARK_REPORT=docs/BENCHMARK.md cargo test detection_benchmark`
//! regenerates the published page, so its numbers always come from this code.

use std::fmt::Write;
use std::time::{SystemTime, UNIX_EPOCH};

use super::Scrubber;
use super::tests::{
    PatternCase, builtin_pattern_cases, clean_corpus, default_scrubber, enabled_heuristic,
    pii_scrubber, scrubber_with_heuristic,
};

/// Plain placements carry the recall floor. Expected misses are reported, never asserted.
#[derive(Clone, Copy, PartialEq)]
enum Group {
    Plain,
    Harder,
    ExpectedMiss,
}

impl Group {
    fn label(self) -> &'static str {
        match self {
            Group::Plain => "plain",
            Group::Harder => "harder",
            Group::ExpectedMiss => "expected miss",
        }
    }
}

struct Placement {
    name: &'static str,
    group: Group,
    plant: fn(&str) -> String,
}

const PLACEMENTS: &[Placement] = &[
    Placement {
        name: "env line",
        group: Group::Plain,
        plant: |v| format!("BENCH_TOKEN={v}"),
    },
    Placement {
        name: "shell export",
        group: Group::Plain,
        plant: |v| format!("export BENCH_TOKEN=\"{v}\""),
    },
    Placement {
        name: "JSON value",
        group: Group::Plain,
        plant: |v| format!("{{\"id\": 7, \"token\": \"{v}\"}}"),
    },
    Placement {
        name: "JSON nested as escaped string",
        group: Group::Harder,
        plant: |v| {
            let inner = format!("{{\"token\": \"{v}\"}}");
            format!(
                "{{\"payload\": {}}}",
                serde_json::to_string(&inner).unwrap()
            )
        },
    },
    Placement {
        name: "URL query parameter",
        group: Group::Plain,
        plant: |v| format!("GET https://api.example.com/v1/items?token={v}&page=2 200"),
    },
    Placement {
        name: "URL path segment",
        group: Group::Harder,
        plant: |v| format!("GET https://api.example.com/v1/keys/{v}/rotate 200"),
    },
    Placement {
        name: "git diff added line",
        group: Group::Plain,
        plant: |v| format!("+    const token = \"{v}\";"),
    },
    Placement {
        name: "log line",
        group: Group::Plain,
        plant: |v| format!("2026-10-13T08:15:02.481Z INFO auth: using token {v}"),
    },
    Placement {
        name: "YAML value",
        group: Group::Plain,
        plant: |v| format!("  token: {v}"),
    },
    Placement {
        name: "markdown inline code",
        group: Group::Plain,
        plant: |v| format!("Set the token to `{v}` and rerun."),
    },
    Placement {
        name: "quoted in error message",
        group: Group::Plain,
        plant: |v| format!("Error: invalid credential '{v}' (401 Unauthorized)"),
    },
    Placement {
        name: "CSV field",
        group: Group::Plain,
        plant: |v| format!("42,deploy-bot,{v},2026-10-13"),
    },
    Placement {
        name: "mid-token",
        group: Group::Harder,
        plant: |v| format!("prefix_{v}_suffix"),
    },
    Placement {
        name: "trailing period",
        group: Group::Harder,
        plant: |v| format!("The token is {v}."),
    },
    Placement {
        name: "trailing comma",
        group: Group::Harder,
        plant: |v| format!("token {v}, expires in 1h"),
    },
    Placement {
        name: "base64 of the line",
        group: Group::ExpectedMiss,
        plant: |v| base64(format!("BENCH_TOKEN={v}").as_bytes()),
    },
    Placement {
        name: "line-wrapped at 40",
        group: Group::ExpectedMiss,
        plant: |v| wrap_at_40(&format!("BENCH_TOKEN={v}")),
    },
];

/// Standard base64 with padding; written out so the benchmark adds no dependency.
fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let n =
            chunk.iter().fold(0u32, |acc, b| (acc << 8) | u32::from(*b)) << (8 * (3 - chunk.len()));
        for i in 0..4 {
            let symbol = if i <= chunk.len() {
                ALPHABET[(n >> (18 - 6 * i) & 63) as usize] as char
            } else {
                '='
            };
            out.push(symbol);
        }
    }
    out
}

fn wrap_at_40(line: &str) -> String {
    let chars: Vec<char> = line.chars().collect();
    let rows: Vec<String> = chars.chunks(40).map(|row| row.iter().collect()).collect();
    rows.join("\n")
}

/// Mid-file, so the planted line sits inside normal tool output.
fn plant_in(host: &str, line: &str) -> String {
    let lines: Vec<&str> = host.lines().collect();
    let (before, after) = lines.split_at(lines.len() / 2);
    format!("{}\n{line}\n{}\n", before.join("\n"), after.join("\n"))
}

/// Any 8-character run of the secret left outside a marker is a leak, so a partly
/// redacted or line-wrapped value never scores as caught. Runs the surrounding text holds don't count.
fn leaks(text: &str, context: &str, secret: &str) -> bool {
    let unmarked = without_markers(text);
    secret
        .lines()
        .flat_map(|line| line.as_bytes().windows(8))
        .filter_map(|run| std::str::from_utf8(run).ok())
        .any(|run| unmarked.contains(run) && !context.contains(run))
}

/// Marker labels repeat the pattern name, which some secrets start with (`rubygems_`).
fn without_markers(text: &str) -> String {
    let mut parts = text.split("[REDACTED");
    let mut out = parts.next().unwrap_or_default().to_string();
    for part in parts {
        out.push_str(part.split_once(']').map_or(part, |(_, rest)| rest));
    }
    out
}

/// The host count is subtracted because the heuristic may already redact clean text.
fn is_caught(scrubber: &Scrubber, host: &str, placement: &Placement, case: &PatternCase) -> bool {
    let baseline = scrubber.scrub(host).count;
    let result = scrubber.scrub(&plant_in(host, &(placement.plant)(&case.input)));
    let context = format!("{host}\n{}", (placement.plant)(""));
    result.count > baseline && !leaks(&result.text, &context, &case.secret)
}

struct Outcome {
    placement: &'static Placement,
    pattern: &'static str,
    caught: bool,
}

/// Host files rotate across rows, so every corpus file is used and runs repeat exactly.
fn run_matrix(scrubber: &Scrubber, corpus: &[(String, String)]) -> Vec<Outcome> {
    let mut outcomes = Vec::new();
    for (i, case) in builtin_pattern_cases().iter().enumerate() {
        for (j, placement) in PLACEMENTS.iter().enumerate() {
            let host = &corpus[(i + j) % corpus.len()].1;
            outcomes.push(Outcome {
                placement,
                pattern: case.name,
                caught: is_caught(scrubber, host, placement, case),
            });
        }
    }
    outcomes
}

fn recall<'a>(outcomes: impl Iterator<Item = &'a Outcome>) -> String {
    let (mut caught, mut total) = (0, 0);
    for outcome in outcomes {
        total += 1;
        caught += usize::from(outcome.caught);
    }
    let percent = 100.0 * caught as f64 / total.max(1) as f64;
    format!("{caught}/{total} ({percent:.1}%)")
}

fn header(seed: u64) -> String {
    format!(
        "# Detection benchmark\n\n\
         Generated by `src/scrub/benchmark.rs` for redacted {}. Do not edit by hand.\n\n\
         The tool reduces exposure to secrets in tool output. It never prevents it.\n\n\
         ## What is measured and how\n\n\
         - The scrub engine (`Scrubber`) runs in process, not through the hook binary.\n\
         - Two configurations: default (vendor signatures, heuristic off) and heuristic on. No learned secrets in either.\n\
         - Each built-in pattern gets one fake value per placement, generated at run time by `src/fake_secrets.rs`. Keyed patterns are planted with their key, since the key is part of the match.\n\
         - Each value is planted mid-file in a `corpus/clean/*.txt` file. Files rotate across rows.\n\
         - Caught means at least one new redaction and no 8-character run of the value left outside a redaction marker.\n\
         - Seed {seed}. Replay with `REDACTED_BENCHMARK_SEED={seed}`.\n\n",
        env!("CARGO_PKG_VERSION")
    )
}

/// Both matrices list the same rows in the same order, so zipping pairs each row's two outcomes.
fn misses_section(default: &[Outcome], heuristic: &[Outcome]) -> String {
    let mut out = String::from(
        "## Misses\n\n| Placement | Patterns missed | Default | Heuristic on |\n| --- | --- | --- | --- |\n",
    );
    for placement in PLACEMENTS.iter().filter(|p| p.group != Group::ExpectedMiss) {
        let in_placement = |o: &&Outcome| o.placement.name == placement.name;
        let missed = |outcomes: &[Outcome]| {
            outcomes
                .iter()
                .filter(in_placement)
                .filter(|o| !o.caught)
                .count()
        };
        let union: Vec<String> = default
            .iter()
            .zip(heuristic)
            .filter(|(d, h)| in_placement(d) && !(d.caught && h.caught))
            .map(|(d, _)| format!("`{}`", d.pattern))
            .collect();
        if !union.is_empty() {
            let (d, h) = (missed(default), missed(heuristic));
            writeln!(
                out,
                "| {} | {} | {d} | {h} |",
                placement.name,
                union.join(", ")
            )
            .unwrap();
        }
    }
    out + "\nExpected-miss placements (base64, line-wrapped) appear in the recall table only.\n\n"
}

fn placement_section(default: &[Outcome], heuristic: &[Outcome]) -> String {
    let mut out = String::from(
        "## Recall by placement\n\n| Placement | Group | Default | Heuristic on |\n| --- | --- | --- | --- |\n",
    );
    let mut row = |label: &str, group: &str, keep: &dyn Fn(&Outcome) -> bool| {
        let default = recall(default.iter().filter(|o| keep(o)));
        let heuristic = recall(heuristic.iter().filter(|o| keep(o)));
        writeln!(out, "| {label} | {group} | {default} | {heuristic} |").unwrap();
    };
    for placement in PLACEMENTS {
        let label = placement.group.label();
        row(placement.name, label, &|o| {
            o.placement.name == placement.name
        });
    }
    row("all plain placements", "plain", &|o| {
        o.placement.group == Group::Plain
    });
    row("all placements", "all", &|_| true);
    out + "\n"
}

fn scored_rows<'a>(outcomes: &'a [Outcome], pattern: &'a str) -> impl Iterator<Item = &'a Outcome> {
    outcomes
        .iter()
        .filter(move |o| o.pattern == pattern && o.placement.group != Group::ExpectedMiss)
}

/// Base64 and wrapped lines miss for every pattern, so they would hide which patterns differ.
fn pattern_section(default: &[Outcome], heuristic: &[Outcome]) -> String {
    let mut out = String::from(
        "## Recall by pattern\n\nExcludes the expected-miss placements (base64, line-wrapped).\n\n\
         | Pattern | Default | Heuristic on |\n| --- | --- | --- |\n",
    );
    for case in builtin_pattern_cases() {
        let name = case.name;
        if scored_rows(default, name)
            .chain(scored_rows(heuristic, name))
            .all(|o| o.caught)
        {
            continue;
        }
        let row = format!(
            "| `{name}` | {} | {} |",
            recall(scored_rows(default, name)),
            recall(scored_rows(heuristic, name))
        );
        writeln!(out, "{row}").unwrap();
    }
    out + "\nAll other patterns: 100% in both configurations.\n\n"
}

fn precision_section(precision: &[(String, usize, usize)]) -> String {
    let mut out = String::from(
        "## Precision on the clean corpus\n\nRedactions in files that hold no secret. Zero is correct.\n\n\
         | File | Default | Heuristic on |\n| --- | --- | --- |\n",
    );
    for (file, default, heuristic) in precision {
        writeln!(out, "| `{file}` | {default} | {heuristic} |").unwrap();
    }
    out + "\n"
}

fn footer(seed: u64) -> String {
    format!(
        "## How to reproduce\n\n\
         ```bash\nREDACTED_BENCHMARK_SEED={seed} REDACTED_BENCHMARK_REPORT=docs/BENCHMARK.md cargo test detection_benchmark\n```\n\n\
         ## What this does not show\n\n\
         - Learned secrets are excluded. They match values from your own environment, which a fixed benchmark cannot hold.\n\
         - The hook envelope path (JSON in, JSON out) is tested in `tests/cli.rs` and `tests/golden.rs`, not here.\n\
         - No competitor numbers. Other tools were not run.\n\
         - The placements were chosen by the author. Real output can hold shapes not listed here.\n\
         - The floors run on fresh values on every `cargo test`. Counts on the expected-miss rows can move by a few between seeds.\n\
         - Contributions of failing samples are welcome: open an issue with the shape, never a real secret.\n",
    )
}

/// Each clean file's redaction count, per configuration.
fn precision(default: &Scrubber, heuristic: &Scrubber) -> Vec<(String, usize, usize)> {
    clean_corpus()
        .into_iter()
        .map(|(path, text)| {
            let file = path.rsplit('/').next().unwrap().to_string();
            (
                file,
                default.scrub(&text).count,
                heuristic.scrub(&text).count,
            )
        })
        .collect()
}

/// A fresh seed checks the floors against new values on every run; the env var replays one.
fn benchmark_seed() -> u64 {
    match std::env::var("REDACTED_BENCHMARK_SEED") {
        Ok(seed) => seed
            .parse()
            .expect("REDACTED_BENCHMARK_SEED must be a whole number"),
        Err(_) => {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(1, |d| d.as_nanos() as u64)
                | 1
        }
    }
}

fn plain_misses(outcomes: &[Outcome]) -> Vec<String> {
    outcomes
        .iter()
        .filter(|o| o.placement.group == Group::Plain && !o.caught)
        .map(|o| format!("{} in {}", o.pattern, o.placement.name))
        .collect()
}

#[test]
fn detection_benchmark() {
    let seed = benchmark_seed();
    crate::fake_secrets::reseed(seed);
    let corpus = clean_corpus();
    let (default, heuristic) = (
        default_scrubber(),
        scrubber_with_heuristic(enabled_heuristic()),
    );
    let default_outcomes = run_matrix(&default, &corpus);
    let heuristic_outcomes = run_matrix(&heuristic, &corpus);
    let pii_outcomes = run_matrix(&pii_scrubber(), &corpus);
    let precision = precision(&default, &heuristic);
    if let Ok(path) = std::env::var("REDACTED_BENCHMARK_REPORT") {
        let report = header(seed)
            + &misses_section(&default_outcomes, &heuristic_outcomes)
            + &placement_section(&default_outcomes, &heuristic_outcomes)
            + &pattern_section(&default_outcomes, &heuristic_outcomes)
            + &precision_section(&precision)
            + &footer(seed);
        std::fs::write(path, report).unwrap();
    }
    let default_misses = plain_misses(&default_outcomes);
    assert!(
        default_misses.is_empty(),
        "default config missed (seed {seed}): {default_misses:?}"
    );
    let pii_misses = plain_misses(&pii_outcomes);
    assert!(
        pii_misses.is_empty(),
        "PII toggles on missed (seed {seed}): {pii_misses:?}"
    );
    let false_positives: Vec<&String> =
        precision.iter().filter(|p| p.1 > 0).map(|p| &p.0).collect();
    assert!(
        false_positives.is_empty(),
        "default config redacted clean files (seed {seed}): {false_positives:?}"
    );
}
