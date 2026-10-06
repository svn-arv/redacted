//! Detection tiers: vendor signatures (engine.yml `patterns:` plus user patterns),
//! learned secrets, and the opt-in entropy heuristic.

mod go_regex;
mod learned;
mod skip;

use std::collections::{BTreeMap, HashMap, HashSet};

use regex::Regex;
use serde::Deserialize;

use crate::config::{Config, EngineConfig, Heuristic};
use go_regex::go_regex;
// Re-exported so callers write `scrub::sha256_hex`, not `scrub::learned::sha256_hex`.
pub use learned::{learned_hint, sha256_hex};

const ENGINE_YML: &str = include_str!("engine.yml");

// Built-in heuristic thresholds (engine.yml) that the includes_key guards still
// use to tell a random segment from an identifier.
const MIN_CHAR_CLASSES: usize = 3;
const MIN_ENTROPY: f64 = 3.5;

#[derive(Deserialize)]
struct PatternDef {
    name: String,
    regex: String,
    #[serde(default)]
    includes_key: bool,
    #[serde(default)]
    prefilters: Vec<String>,
    #[serde(default)]
    prefilters_fold: Vec<String>,
}

#[derive(Deserialize)]
struct EngineFile {
    value_safe_char: String,
    allow_values: Vec<String>,
    patterns: Vec<PatternDef>,
}

struct Pattern {
    name: String,
    regex: Regex,
    includes_key: bool,
    prefilters: Vec<String>,
    prefilters_fold: Vec<String>,
    is_heuristic: bool,
}

impl Pattern {
    /// No key handling and no prefilters, as user patterns from engine.yml run.
    fn plain(name: String, regex: Regex) -> Self {
        Pattern {
            name,
            regex,
            includes_key: false,
            prefilters: Vec::new(),
            prefilters_fold: Vec::new(),
            is_heuristic: false,
        }
    }
}

/// Every tier compiled once from the config, then reused for each scrub.
pub struct Scrubber {
    patterns: Vec<Pattern>,
    /// Pattern names the user turned off.
    whitelist: HashSet<String>,
    /// Uppercased names; a match containing one is left alone.
    allow: Vec<String>,
    /// A match whose value fits one of these is left alone.
    allow_values: Vec<Regex>,
    /// Learned name and the regex derived from its sample.
    shapes: Vec<(String, Regex)>,
    /// sha256 of a learned value to its name.
    exact: HashMap<String, String>,
    /// Only candidates of these byte lengths are hashed.
    exact_lens: HashSet<usize>,
    /// Runs of the characters a value can hold (engine.yml `value_safe_char`).
    safe_run: Regex,
    /// Whitespace-delimited runs, for values holding `@`, `(` or quotes.
    word_run: Regex,
    heuristic: Option<Pattern>,
    thresholds: Heuristic,
}

/// The rewritten text plus how many secrets each pattern redacted.
#[derive(Debug, Default)]
pub struct ScrubResult {
    pub text: String,
    pub count: usize,
    pub by_pattern: BTreeMap<String, usize>,
}

impl ScrubResult {
    pub fn redacted(&self) -> bool {
        self.count > 0
    }

    /// Counts `n` hits for `name`; zero adds nothing, so a pattern that never
    /// matched stays out of `by_pattern`.
    fn add(&mut self, name: &str, n: usize) {
        if n == 0 {
            return;
        }
        // entry() finds or inserts the key; or_default() starts a new count at 0.
        *self.by_pattern.entry(name.to_string()).or_default() += n;
        self.count += n;
    }
}

fn compile(expr: &str) -> Result<Regex, String> {
    Regex::new(&go_regex(expr)).map_err(|e| format!("invalid regex {expr:?}: {e}"))
}

impl Scrubber {
    pub fn new(cfg: &Config, eng: &EngineConfig) -> Result<Self, String> {
        let engine: EngineFile =
            serde_yaml::from_str(ENGINE_YML).map_err(|e| format!("engine.yml: {e}"))?;
        let mut patterns = Vec::new();
        for p in engine.patterns {
            patterns.push(Pattern {
                regex: compile(&p.regex)?,
                name: p.name,
                includes_key: p.includes_key,
                prefilters: p.prefilters,
                prefilters_fold: p.prefilters_fold,
                is_heuristic: false,
            });
        }
        for p in &eng.patterns {
            patterns.push(Pattern::plain(p.name.clone(), compile(&p.regex)?));
        }
        let allow_values = engine
            .allow_values
            .iter()
            .chain(&eng.allow_values)
            .map(|e| compile(e))
            .collect::<Result<_, _>>()?;
        let thresholds = with_defaults(&cfg.heuristic);
        let heuristic = if thresholds.enabled {
            let regex = compile(&heuristic_regex(
                thresholds.min_length_or_default(),
                &engine.value_safe_char,
            ))?;
            Some(Pattern {
                includes_key: true,
                is_heuristic: true,
                ..Pattern::plain("secret_value".into(), regex)
            })
        } else {
            None
        };
        let mut shapes = Vec::new();
        for l in &cfg.learned {
            if let Some(shape) = &l.shape {
                shapes.push((l.name.clone(), compile(shape)?));
            }
        }
        Ok(Scrubber {
            patterns,
            whitelist: cfg.whitelist.iter().cloned().collect(),
            allow: cfg.allow.iter().map(|a| a.to_uppercase()).collect(),
            allow_values,
            shapes,
            exact: cfg
                .learned
                .iter()
                .map(|l| (l.sha256.clone(), l.name.clone()))
                .collect(),
            exact_lens: cfg.learned.iter().map(|l| l.len).collect(),
            safe_run: compile(&format!("{}+", engine.value_safe_char))?,
            word_run: compile(r"[^ \t\n\x0C\r]+")?,
            heuristic,
            thresholds,
        })
    }

    pub fn scrub(&self, text: &str) -> ScrubResult {
        let mut result = ScrubResult {
            text: text.to_string(),
            ..Default::default()
        };
        // Lowered once, like Go 0.7: redaction markers never add a prefilter literal.
        let mut lowered: Option<String> = None;
        for p in &self.patterns {
            if self.whitelist.contains(&p.name) {
                continue;
            }
            if !p.prefilters.is_empty()
                && !p
                    .prefilters
                    .iter()
                    .any(|l| result.text.contains(l.as_str()))
            {
                continue;
            }
            if !p.prefilters_fold.is_empty() {
                // Computes the lowercase copy on first use only, then reuses it.
                let low = lowered.get_or_insert_with(|| result.text.to_lowercase());
                if !p.prefilters_fold.iter().any(|l| low.contains(l.as_str())) {
                    continue;
                }
            }
            let n = self.apply_pattern(p, &mut result.text);
            result.add(&p.name, n);
        }
        self.scrub_learned(&mut result);
        if let Some(p) = &self.heuristic {
            let n = self.apply_pattern(p, &mut result.text);
            result.add(&p.name, n);
        }
        result
    }

    /// Returns the hit count; `text` is rewritten only on a hit.
    fn apply_pattern(&self, p: &Pattern, text: &mut String) -> usize {
        let mut out = String::with_capacity(text.len());
        let (mut last, mut count) = (0, 0);
        for m in p.regex.find_iter(text) {
            out.push_str(&text[last..m.start()]);
            last = m.end();
            if self.skip_match(p, m.as_str(), text, m.end()) {
                out.push_str(m.as_str());
                continue;
            }
            out.push_str(&redact(&p.name, m.as_str(), p.includes_key));
            count += 1;
        }
        if count > 0 {
            out.push_str(&text[last..]);
            *text = out;
        }
        count
    }
}

fn redact(name: &str, m: &str, includes_key: bool) -> String {
    if includes_key {
        if let Some(i) = m.find(['=', ':']) {
            let value = m[i + 1..].trim_start_matches([' ', '\t']);
            return format!("{}{} [REDACTED ...{}]", &m[..i], &m[i..=i], tail(value, 4));
        }
    }
    format!("[REDACTED:{name} ...{}]", tail(m, 4))
}

fn tail(s: &str, n: usize) -> &str {
    match s.char_indices().rev().nth(n - 1) {
        Some((i, _)) => &s[i..],
        None => s,
    }
}

/// Zero thresholds take the engine.yml defaults, like Go; `min_length`
/// resolves its own default.
fn with_defaults(h: &Heuristic) -> Heuristic {
    let or = |v: usize, d: usize| if v == 0 { d } else { v };
    Heuristic {
        enabled: h.enabled,
        min_length: h.min_length,
        max_length: or(h.max_length, 128),
        min_char_classes: or(h.min_char_classes, MIN_CHAR_CLASSES),
        min_entropy: if h.min_entropy == 0.0 {
            MIN_ENTROPY
        } else {
            h.min_entropy
        },
    }
}

/// KEY=value with a value of min_length+ chars that can't start with `/`, so a
/// URL scheme isn't read as one.
fn heuristic_regex(min_length: usize, safe_char: &str) -> String {
    let first = match safe_char.strip_suffix(']') {
        Some(class) if safe_char.starts_with("[^") => format!("{class}/]"),
        _ => safe_char.to_string(),
    };
    format!(
        r#"(?i)\b[A-Za-z0-9_\-]*[A-Za-z][A-Za-z0-9_\-]*["']?[ \t]*(?:=>?|:)[ \t]*["']?{first}{safe_char}{{{},}}"#,
        min_length.max(1) - 1
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fake;

    pub(super) fn default_scrubber() -> Scrubber {
        Scrubber::new(&Config::default(), &EngineConfig::default()).unwrap()
    }

    pub(super) fn value_only(name: &str, secret: &str) -> String {
        format!("[REDACTED:{name} ...{}]", fake::hint(secret))
    }

    /// One engine.yml pattern: an input, its exact expected output, and the
    /// secret part that must not survive.
    struct Row {
        name: &'static str,
        input: String,
        want: String,
        secret: String,
    }

    fn builtin_rows() -> Vec<Row> {
        let mut rows = Vec::new();
        let mut bare = |name: &'static str, secret: String| {
            rows.push(Row {
                name,
                input: secret.clone(),
                want: value_only(name, &secret),
                secret,
            });
        };
        bare("aws_access_key", fake::aws_access_key());
        bare("github_fine_grained", fake::github_fine_grained());
        bare("github_token", fake::github_token("ghp_"));
        bare("github_oauth", fake::github_token("gho_"));
        bare("github_refresh", fake::github_token("ghr_"));
        bare("stripe_live", fake::stripe_key("sk_live_"));
        bare("stripe_test", fake::stripe_key("pk_test_"));
        bare("twilio_api_key", fake::twilio_sid("SK"));
        bare("twilio_account_sid", fake::twilio_sid("AC"));
        bare("digitalocean_token", fake::digitalocean_token());
        bare("sentry_dsn", fake::sentry_dsn());
        bare("slack_token", fake::slack_token("xoxb"));
        bare("sendgrid_key", fake::sendgrid_key());
        bare("hubspot_key", fake::hubspot_pat("na1"));
        bare("private_key", fake::private_key("RSA "));
        bare("private_key_truncated", fake::private_key_truncated(""));
        bare("jwt", fake::jwt());
        bare("anthropic_key", format!("sk-ant-{}", fake::alnum(90)));
        bare("circleci_token", format!("CCIPAT_{}", fake::alnum(30)));
        bare("sentry_user_token", format!("sntryu_{}", fake::alnum(40)));
        bare("rubygems_key", format!("rubygems_{}", fake::alnum(30)));
        bare("newrelic_key", format!("NRAK-{}", fake::alnum(27)));
        bare("openai_key", format!("sk-proj-{}", fake::alnum(48)));
        bare("openai_classic_key", format!("sk-{}", fake::alnum(48)));
        bare("google_api_key", format!("AIza{}", fake::base64url(35)));
        bare("google_api_key_v2", format!("AQ.{}", fake::base64url(50)));
        bare(
            "stripe_webhook_secret",
            format!("whsec_{}", fake::alnum(32)),
        );
        bare("huggingface_token", format!("hf_{}", fake::alnum(34)));
        bare("groq_key", format!("gsk_{}", fake::alnum(52)));
        bare("openrouter_key", format!("sk-or-v1-{}", fake::hex(64)));
        bare("xai_key", format!("xai-{}", fake::alnum(80)));
        bare("perplexity_key", format!("pplx-{}", fake::alnum(48)));
        bare("tavily_key", format!("tvly-{}", fake::alnum(32)));
        bare(
            "langsmith_key",
            format!("lsv2_pt_{}_{}", fake::alnum(32), fake::alnum(10)),
        );
        bare("gitlab_pat", format!("glpat-{}", fake::alnum(20)));
        bare("npm_token", fake::npm_token());
        bare("slack_webhook", fake::slack_webhook());
        bare("pypi_token", format!("pypi-{}", fake::alnum(60)));
        bare(
            "database_url",
            fake::database_url("postgres", "db.example.com"),
        );
        bare(
            "credentialed_url",
            fake::database_url("postgis", "db.example.com"),
        );

        // includes_key patterns keep the key and separator and drop the label.
        let mut keyed = |name: &'static str, key: &str, sep: &str, value: String| {
            let want = format!(
                "{key}{} [REDACTED ...{}]",
                sep.trim_end(),
                fake::hint(&value)
            );
            rows.push(Row {
                name,
                input: format!("{key}{sep}{value}"),
                want,
                secret: value,
            });
        };
        keyed(
            "aws_secret_key",
            "aws_secret_access_key",
            "=",
            fake::aws_secret_key(),
        );
        keyed(
            "digitalocean_spaces",
            "SPACES_SECRET_KEY",
            "=",
            fake::digitalocean_spaces_value(),
        );
        keyed(
            "gcp_sa_key_id",
            r#""private_key_id""#,
            ": ",
            format!("\"{}\"", fake::hex(40)),
        );
        keyed(
            "auth_header",
            "Authorization",
            ": ",
            format!("Bearer {}", fake::alnum(32)),
        );
        let gcp = fake::gcp_private_key_field();
        let value = gcp.trim_start_matches(r#""private_key": "#).to_string();
        keyed("gcp_sa_private_key", r#""private_key""#, ": ", value);
        rows
    }

    #[test]
    fn builtin_patterns_redact_with_label_and_hint() {
        let s = default_scrubber();
        // Destructuring in the loop header names the fields; `..` skips the rest.
        for Row {
            name, input, want, ..
        } in builtin_rows()
        {
            let r = s.scrub(&input);
            assert_eq!(r.text, want, "{name}: wrong redaction");
            assert_eq!(r.count, 1, "{name}: count");
            assert_eq!(
                r.by_pattern.get(name),
                Some(&1),
                "{name}: label {:?}",
                r.by_pattern
            );
        }
    }

    #[test]
    fn every_engine_pattern_has_a_row() {
        let engine: serde_yaml::Value = serde_yaml::from_str(ENGINE_YML).unwrap();
        let mut in_yml: Vec<String> = engine["patterns"]
            .as_sequence()
            .unwrap()
            .iter()
            .map(|p| p["name"].as_str().unwrap().to_string())
            .collect();
        let mut in_rows: Vec<String> = builtin_rows().iter().map(|r| r.name.to_string()).collect();
        in_yml.sort();
        in_rows.sort();
        assert_eq!(in_rows, in_yml);
    }

    #[test]
    fn hint_is_last_four_chars_not_bytes() {
        let r = default_scrubber().scrub("postgis://u:pw@host/dbéèêë");
        assert_eq!(r.text, "[REDACTED:credentialed_url ...éèêë]");
    }

    #[test]
    fn whitelist_skips_a_pattern_by_name() {
        let cfg = Config {
            whitelist: vec!["aws_access_key".into()],
            ..Default::default()
        };
        let key = fake::aws_access_key();
        let r = Scrubber::new(&cfg, &EngineConfig::default())
            .unwrap()
            .scrub(&key);
        assert_eq!(r.text, key);
    }

    #[test]
    fn allow_skips_matches_containing_the_name_case_insensitively() {
        let cfg = Config {
            allow: vec!["aws_secret_access_key".into()],
            ..Default::default()
        };
        let input = format!("AWS_SECRET_ACCESS_KEY={}", fake::aws_secret_key());
        let r = Scrubber::new(&cfg, &EngineConfig::default())
            .unwrap()
            .scrub(&input);
        assert_eq!(r.text, input);
    }

    #[test]
    fn builtin_allow_values_clear_placeholder_urls() {
        let input = "postgres://user:password@db.example.com:5432/app";
        assert_eq!(default_scrubber().scrub(input).text, input);
    }

    #[test]
    fn user_allow_values_and_patterns_apply() {
        let eng = EngineConfig {
            patterns: vec![crate::config::CustomPattern {
                name: "acme".into(),
                regex: r"acme_\w{12}".into(),
            }],
            allow_values: vec!["^acme_test".into()],
            ..Default::default()
        };
        let s = Scrubber::new(&Config::default(), &eng).unwrap();
        assert_eq!(s.scrub("acme_live1234abcd").text, "[REDACTED:acme ...abcd]");
        assert_eq!(s.scrub("acme_test1234abcd").text, "acme_test1234abcd");
    }

    #[test]
    fn bad_user_regex_is_an_error() {
        let eng = EngineConfig {
            patterns: vec![crate::config::CustomPattern {
                name: "bad".into(),
                regex: "(".into(),
            }],
            ..Default::default()
        };
        assert!(Scrubber::new(&Config::default(), &eng).is_err());
    }

    pub(super) fn with_learned(entries: Vec<crate::config::Learned>) -> Scrubber {
        let cfg = Config {
            learned: entries,
            ..Default::default()
        };
        Scrubber::new(&cfg, &EngineConfig::default()).unwrap()
    }

    pub(super) fn with_heuristic(h: crate::config::Heuristic) -> Scrubber {
        let cfg = Config {
            heuristic: h,
            ..Default::default()
        };
        Scrubber::new(&cfg, &EngineConfig::default()).unwrap()
    }

    pub(super) fn heuristic_on() -> crate::config::Heuristic {
        crate::config::Heuristic {
            enabled: true,
            ..Default::default()
        }
    }

    const RANDOM_ASSIGNMENT: &str = "FOO_CONF=Xy7aB3kQ9mZ2pL5nR8tW";

    #[test]
    fn heuristic_is_off_by_default() {
        assert_eq!(
            default_scrubber().scrub(RANDOM_ASSIGNMENT).text,
            RANDOM_ASSIGNMENT
        );
    }

    #[test]
    fn heuristic_enabled_redacts_a_random_value_under_any_key() {
        let r = with_heuristic(heuristic_on()).scrub(RANDOM_ASSIGNMENT);
        assert_eq!(r.text, "FOO_CONF= [REDACTED ...R8tW]");
        assert_eq!(r.by_pattern.get("secret_value"), Some(&1));
    }

    #[test]
    fn heuristic_thresholds_come_from_config() {
        let strict = crate::config::Heuristic {
            min_length: Some(50),
            ..heuristic_on()
        };
        assert_eq!(
            with_heuristic(strict).scrub(RANDOM_ASSIGNMENT).text,
            RANDOM_ASSIGNMENT
        );
        let short = "GADGET=aB3xK9pQ7mZ2";
        assert_eq!(with_heuristic(heuristic_on()).scrub(short).text, short);
        let loose = crate::config::Heuristic {
            min_length: Some(10),
            ..heuristic_on()
        };
        assert!(with_heuristic(loose).scrub(short).redacted());
        // Only an absent min_length takes the default; an explicit 0 is honored.
        let zero: crate::config::Heuristic =
            serde_yaml::from_str("{enabled: true, min_length: 0}").unwrap();
        assert!(with_heuristic(zero).scrub(short).redacted());
    }

    #[test]
    fn corpus_precision_no_redaction_on_clean_files() {
        let s = default_scrubber();
        for (name, data) in clean_corpus() {
            let r = s.scrub(&data);
            assert!(
                !r.redacted(),
                "false positive in {name}: {:?}",
                r.by_pattern
            );
        }
    }

    #[test]
    fn corpus_recall_every_secret_redacted_in_every_file() {
        let s = default_scrubber();
        for (name, data) in clean_corpus() {
            for row in builtin_rows() {
                let planted = format!("{data}\n{}\n", row.input);
                let r = s.scrub(&planted);
                let pattern = row.name;
                assert!(r.redacted(), "{pattern} missed in {name}");
                assert!(!r.text.contains(&row.secret), "{pattern} leaked in {name}");
            }
        }
    }

    /// Learned entries derived the way `init` derives them, from synthetic values:
    /// one exact-only, one custom-prefix shape (all three classes, so the band is stable).
    fn learned_corpus_scrubber() -> (Scrubber, String, String) {
        let exact = fake::alnum(24);
        let shaped = format!("acme_{}aZ9", fake::alnum(27));
        let entries = vec![
            crate::init::learn("DB_PASS", &exact).unwrap(),
            crate::init::learn("ACME_KEY", &shaped).unwrap(),
            crate::init::learn("STRIPE_KEY", &fake::stripe_key("sk_live_")).unwrap(),
            crate::init::learn("GH_TOKEN", &fake::github_token("ghp_")).unwrap(),
            crate::init::learn("SLACK_TOKEN", &fake::slack_token("xoxb")).unwrap(),
            crate::init::learn("HUBSPOT_KEY", &fake::hubspot_pat("na1")).unwrap(),
            crate::init::learn("AWS_KEY", &fake::aws_access_key()).unwrap(),
            crate::init::learn(
                "DATABASE_URL",
                &fake::database_url("postgres", "db.example.com"),
            )
            .unwrap(),
        ];
        assert!(entries[1].shape.is_some() && entries[0].shape.is_none());
        (with_learned(entries), exact, shaped)
    }

    #[test]
    fn corpus_precision_holds_with_learned_secrets_loaded() {
        let (s, _, _) = learned_corpus_scrubber();
        for (name, data) in clean_corpus() {
            let r = s.scrub(&data);
            assert!(
                !r.redacted(),
                "false positive in {name}: {:?}",
                r.by_pattern
            );
        }
    }

    #[test]
    fn corpus_recall_learned_exact_and_shape_including_a_rotated_key() {
        let (s, exact, shaped) = learned_corpus_scrubber();
        // Rotated: same prefix, 3 characters longer than the sample.
        let rotated = format!("acme_{}", fake::alnum(33));
        for (name, data) in clean_corpus() {
            let planted = format!("{data}\nDB_PASS={exact}\nkey: {shaped}\nnew {rotated}\n");
            let r = s.scrub(&planted);
            assert_eq!(r.by_pattern.get("db_pass"), Some(&1), "{name}");
            assert_eq!(r.by_pattern.get("acme_key"), Some(&2), "{name}");
            for secret in [&exact, &shaped, &rotated] {
                assert!(!r.text.contains(secret.as_str()), "leaked in {name}");
            }
        }
    }

    fn clean_corpus() -> Vec<(String, String)> {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/corpus/clean");
        let mut files: Vec<(String, String)> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| p.extension().is_some_and(|x| x == "txt"))
            .map(|p| {
                (
                    p.display().to_string(),
                    std::fs::read_to_string(&p).unwrap(),
                )
            })
            .collect();
        files.sort();
        assert!(!files.is_empty(), "corpus not found");
        files
    }
}
