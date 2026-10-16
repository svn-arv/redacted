//! Detection tiers: vendor signatures (engine.yml `patterns:` plus user patterns),
//! learned secrets, and the opt-in entropy heuristic.

// Child modules add `impl Scrubber` blocks and read its private fields; what this
// file calls from them (and the shared test helpers) is marked `pub(super)`.
#[cfg(test)]
mod benchmark;
mod go_regex;
mod guards;
mod learned;

use std::collections::{BTreeMap, HashMap, HashSet};

use regex::Regex;
use serde::Deserialize;

use crate::config::{Config, CustomPattern, EngineConfig, HeuristicConfig, PiiConfig};
use go_regex::go_to_rust_regex;
// Re-exported so callers write `scrub::sha256_hex`, not `scrub::learned::sha256_hex`.
pub use guards::percent_decode;
pub use learned::{learned_value_hint, sha256_hex};

const BUILTIN_ENGINE_YML: &str = include_str!("engine.yml");

#[derive(Deserialize)]
struct BuiltinPatternYaml {
    name: String,
    regex: String,
    #[serde(default)]
    includes_key: bool,
    #[serde(default)]
    prefilters: Vec<String>,
    #[serde(default)]
    prefilters_ignore_case: Vec<String>,
    #[serde(default)]
    opt_in: bool,
}

#[derive(Deserialize)]
struct BuiltinEngine {
    value_safe_char: String,
    allow_values: Vec<String>,
    patterns: Vec<BuiltinPatternYaml>,
}

struct Pattern {
    name: String,
    regex: Regex,
    includes_key: bool,
    prefilters: Vec<String>,
    prefilters_ignore_case: Vec<String>,
    is_heuristic: bool,
}

impl Pattern {
    /// No key handling and no prefilters, as user patterns from engine.yml run.
    fn unkeyed(name: String, regex: Regex) -> Self {
        Pattern {
            name,
            regex,
            includes_key: false,
            prefilters: Vec::new(),
            prefilters_ignore_case: Vec::new(),
            is_heuristic: false,
        }
    }
}

/// Every tier compiled once from the config, then reused for each scrub.
pub struct Scrubber {
    patterns: Vec<Pattern>,
    disabled_patterns: HashSet<String>,
    /// A match containing one of these key names is left alone.
    allowed_keys_upper: Vec<String>,
    /// A match whose value fits one of these is left alone.
    allow_values: Vec<Regex>,
    /// Learned name and the regex derived from its sample.
    learned_shapes: Vec<(String, Regex)>,
    learned_name_by_hash: HashMap<String, String>,
    /// Only candidates of these byte lengths are hashed.
    learned_byte_lengths: HashSet<usize>,
    /// Runs of the characters a value can hold (engine.yml `value_safe_char`).
    value_char_run: Regex,
    /// For values holding `@`, `(` or quotes, which split a `value_char_run`.
    non_whitespace_run: Regex,
    heuristic_pattern: Option<Pattern>,
    heuristic_thresholds: HeuristicConfig,
}

/// The rewritten text plus how many redactions each pattern made.
#[derive(Debug, Default)]
pub struct ScrubResult {
    pub text: String,
    pub count: usize,
    pub counts_by_pattern: BTreeMap<String, usize>,
}

impl ScrubResult {
    pub fn has_redactions(&self) -> bool {
        self.count > 0
    }

    /// Zero adds nothing, so a pattern that never matched stays out of
    /// `counts_by_pattern`.
    fn add_redactions(&mut self, name: &str, redactions: usize) {
        if redactions == 0 {
            return;
        }
        // entry() finds or inserts the key; or_default() starts a new count at 0.
        *self.counts_by_pattern.entry(name.to_string()).or_default() += redactions;
        self.count += redactions;
    }
}

fn compile_go_regex(expr: &str) -> Result<Regex, String> {
    Regex::new(&go_to_rust_regex(expr)).map_err(|e| format!("invalid regex {expr:?}: {e}"))
}

/// The engine.yml patterns followed by the user's, each compiled from Go syntax.
fn compile_vendor_patterns(
    builtin: Vec<BuiltinPatternYaml>,
    user: &[CustomPattern],
    pii: &PiiConfig,
) -> Result<Vec<Pattern>, String> {
    let mut patterns = Vec::new();
    for pattern in builtin {
        // An opt_in row is PII: it runs only when its toggle in `pii` is on.
        let is_toggled_on = match pattern.name.as_str() {
            "email" => pii.email,
            "phone" => pii.phone,
            _ => false,
        };
        if pattern.opt_in && !is_toggled_on {
            continue;
        }
        patterns.push(Pattern {
            regex: compile_go_regex(&pattern.regex)?,
            name: pattern.name,
            includes_key: pattern.includes_key,
            prefilters: pattern.prefilters,
            prefilters_ignore_case: pattern.prefilters_ignore_case,
            is_heuristic: false,
        });
    }
    for pattern in user {
        patterns.push(Pattern::unkeyed(
            pattern.name.clone(),
            compile_go_regex(&pattern.regex)?,
        ));
    }
    Ok(patterns)
}

impl Scrubber {
    pub fn new(config: &Config, user_engine: &EngineConfig) -> Result<Self, String> {
        let builtin: BuiltinEngine =
            serde_yaml::from_str(BUILTIN_ENGINE_YML).map_err(|e| format!("engine.yml: {e}"))?;
        let patterns =
            compile_vendor_patterns(builtin.patterns, &user_engine.patterns, &config.pii)?;
        let allow_values = builtin
            .allow_values
            .iter()
            .chain(&user_engine.allow_values)
            .map(|expr| compile_go_regex(expr))
            .collect::<Result<_, _>>()?;
        let heuristic_pattern = compile_heuristic(&config.heuristic, &builtin.value_safe_char)?;
        let mut learned_shapes = Vec::new();
        let mut learned_name_by_hash = HashMap::new();
        let mut learned_byte_lengths = HashSet::new();
        for learned in &config.learned {
            learned_name_by_hash.insert(learned.sha256.clone(), learned.name.clone());
            learned_byte_lengths.insert(learned.byte_len);
            if let Some(shape) = &learned.shape {
                learned_shapes.push((learned.name.clone(), compile_go_regex(shape)?));
            }
        }
        Ok(Scrubber {
            patterns,
            disabled_patterns: config.disabled_patterns.iter().cloned().collect(),
            allowed_keys_upper: config
                .allowed_keys
                .iter()
                .map(|a| a.to_uppercase())
                .collect(),
            allow_values,
            learned_shapes,
            learned_name_by_hash,
            learned_byte_lengths,
            value_char_run: compile_go_regex(&format!("{}+", builtin.value_safe_char))?,
            non_whitespace_run: compile_go_regex(r"[^ \t\n\x0C\r]+")?,
            heuristic_pattern,
            heuristic_thresholds: config.heuristic.clone(),
        })
    }

    pub fn scrub(&self, text: &str) -> ScrubResult {
        let mut result = ScrubResult {
            text: text.to_string(),
            ..Default::default()
        };
        // Lowered once, like Go 0.7: redaction markers never add a prefilter literal.
        let mut lowercase_text: Option<String> = None;
        for pattern in &self.patterns {
            if self.disabled_patterns.contains(&pattern.name) {
                continue;
            }
            if !pattern.prefilters.is_empty()
                && !pattern
                    .prefilters
                    .iter()
                    .any(|literal| result.text.contains(literal.as_str()))
            {
                continue;
            }
            if !pattern.prefilters_ignore_case.is_empty() {
                // Computes the lowercase copy on first use only, then reuses it.
                let lowercase = lowercase_text.get_or_insert_with(|| result.text.to_lowercase());
                if !pattern
                    .prefilters_ignore_case
                    .iter()
                    .any(|literal| lowercase.contains(literal.as_str()))
                {
                    continue;
                }
            }
            let redactions = self.redact_matches(pattern, &mut result.text);
            result.add_redactions(&pattern.name, redactions);
        }
        self.scrub_learned(&mut result);
        if let Some(pattern) = &self.heuristic_pattern {
            let redactions = self.redact_matches(pattern, &mut result.text);
            result.add_redactions(&pattern.name, redactions);
        }
        result
    }

    /// Returns the redaction count; `text` is rewritten only when it is above zero.
    fn redact_matches(&self, pattern: &Pattern, text: &mut String) -> usize {
        let mut out = String::with_capacity(text.len());
        let (mut copied_until, mut count) = (0, 0);
        for found in pattern.regex.find_iter(text) {
            out.push_str(&text[copied_until..found.start()]);
            copied_until = found.end();
            if self.should_skip_match(pattern, found.as_str(), text, found.end()) {
                out.push_str(found.as_str());
                continue;
            }
            out.push_str(&marker_for(
                &pattern.name,
                found.as_str(),
                pattern.includes_key,
            ));
            count += 1;
        }
        if count > 0 {
            out.push_str(&text[copied_until..]);
            *text = out;
        }
        count
    }
}

fn marker_for(name: &str, matched: &str, includes_key: bool) -> String {
    if includes_key && let Some(separator_at) = matched.find(['=', ':']) {
        let separator = &matched[separator_at..=separator_at];
        let value = matched[separator_at + 1..].trim_start_matches([' ', '\t']);
        let key = &matched[..separator_at];
        return format!("{key}{separator} [REDACTED ...{}]", last_chars(value, 4));
    }
    format!("[REDACTED:{name} ...{}]", last_chars(matched, 4))
}

fn last_chars(text: &str, count: usize) -> &str {
    match text.char_indices().rev().nth(count - 1) {
        Some((start, _)) => &text[start..],
        None => text,
    }
}

/// The opt-in entropy pattern, or None while the heuristic is off.
fn compile_heuristic(
    heuristic: &HeuristicConfig,
    safe_char: &str,
) -> Result<Option<Pattern>, String> {
    if !heuristic.enabled {
        return Ok(None);
    }
    let regex = compile_go_regex(&heuristic_regex(heuristic.min_length, safe_char))?;
    Ok(Some(Pattern {
        includes_key: true,
        is_heuristic: true,
        ..Pattern::unkeyed("secret_value".into(), regex)
    }))
}

/// KEY=value with a value of min_length+ chars that can't start with `/`, so a
/// URL scheme isn't read as one.
fn heuristic_regex(min_length: usize, safe_char: &str) -> String {
    let first_char_class = match safe_char.strip_suffix(']') {
        Some(class) if safe_char.starts_with("[^") => format!("{class}/]"),
        _ => safe_char.to_string(),
    };
    format!(
        r#"(?i)\b[A-Za-z0-9_\-]*[A-Za-z][A-Za-z0-9_\-]*["']?[ \t]*(?:=>?|:)[ \t]*["']?{first_char_class}{safe_char}{{{},}}"#,
        min_length.max(1) - 1
    )
}

#[cfg(test)]
mod tests;
