//! Learned tier: secrets `init` stored as a sha256 and length, matched exactly
//! or by their derived shape, and the markers that replace them.

use sha2::{Digest, Sha256};

use super::{ScrubResult, Scrubber, last_chars};

impl Scrubber {
    /// Shapes first, then exact hashes on the rewritten text, so a span a shape
    /// already redacted is a marker and cannot match again.
    pub(super) fn scrub_learned(&self, result: &mut ScrubResult) {
        for (name, shape) in &self.learned_shapes {
            let spans = shape
                .find_iter(&result.text)
                .map(|found| (found.start(), found.end(), name.as_str()))
                .collect();
            redact_spans(result, spans);
        }
        if self.learned_name_by_hash.is_empty() {
            return;
        }
        // A value holding `@`, `(` or quotes spans several value-char runs, so
        // non-whitespace runs go second, on the rewritten text so a marker is never matched again.
        for run_regex in [&self.value_char_run, &self.non_whitespace_run] {
            let runs = run_regex
                .find_iter(&result.text)
                .map(|found| (found.start(), found.end()))
                .collect();
            let spans = self.spans_matching_learned_hashes(&result.text, runs);
            redact_spans(result, spans);
        }
    }

    fn spans_matching_learned_hashes(
        &self,
        text: &str,
        runs: Vec<(usize, usize)>,
    ) -> Vec<(usize, usize, &str)> {
        let mut spans = Vec::new();
        // The `'runs` label names this outer loop so an inner loop can continue it.
        'runs: for (run_start, run_end) in runs {
            // `KEY=value` is one run, so also try each suffix after `=` or `:`.
            let mut starts = vec![run_start];
            let run = &text[run_start..run_end];
            starts.extend(
                run.match_indices(['=', ':'])
                    .map(|(i, _)| run_start + i + 1),
            );
            for start in starts {
                for (candidate_start, candidate_end) in peeled_candidate_spans(text, start, run_end)
                {
                    if candidate_start >= candidate_end
                        || !self
                            .learned_byte_lengths
                            .contains(&(candidate_end - candidate_start))
                    {
                        continue;
                    }
                    let hash = sha256_hex(&text[candidate_start..candidate_end]);
                    if let Some(name) = self.learned_name_by_hash.get(&hash) {
                        spans.push((candidate_start, candidate_end, name.as_str()));
                        // One learned match per run, then on to the next run.
                        continue 'runs;
                    }
                }
            }
        }
        spans
    }
}

/// Punctuation and quotes around a value stay inside its run, so try each stage of
/// peeling them: trailing `.:!?,;)}]`, then one matching quote pair, then trailing again.
/// Every stage is a candidate, so a quoted value ending in `)` still matches.
fn peeled_candidate_spans(text: &str, start: usize, end: usize) -> [(usize, usize); 4] {
    const TRAILING_PUNCTUATION: [char; 9] = ['.', ':', '!', '?', ',', ';', ')', '}', ']'];
    let trimmed_end = start
        + text[start..end]
            .trim_end_matches(TRAILING_PUNCTUATION)
            .len();
    // Slice pattern: the first and last byte are the same quote character.
    let (inner_start, inner_end) = match text.as_bytes()[start..trimmed_end] {
        [quote @ (b'"' | b'\''), .., last] if quote == last => (start + 1, trimmed_end - 1),
        _ => (start, trimmed_end),
    };
    let inner_trimmed_end = inner_start
        + text[inner_start..inner_end]
            .trim_end_matches(TRAILING_PUNCTUATION)
            .len();
    [
        (start, end),
        (start, trimmed_end),
        (inner_start, inner_end),
        (inner_start, inner_trimmed_end),
    ]
}

pub fn sha256_hex(text: &str) -> String {
    Sha256::digest(text.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// The 4-char hint, or None when it would be a third or more of the value.
pub fn learned_value_hint(value: &str) -> Option<&str> {
    if value.chars().count() < 12 {
        return None;
    }
    Some(last_chars(value, 4))
}

/// Rewrites sorted, non-overlapping spans as learned markers.
fn redact_spans(result: &mut ScrubResult, spans: Vec<(usize, usize, &str)>) {
    if spans.is_empty() {
        return;
    }
    let text = &result.text;
    let mut out = String::with_capacity(text.len());
    let mut copied_until = 0;
    for &(start, end, name) in &spans {
        out.push_str(&text[copied_until..start]);
        match learned_value_hint(&text[start..end]) {
            Some(hint) => out.push_str(&format!("[REDACTED:{name} ...{hint}]")),
            None => out.push_str(&format!("[REDACTED:{name}]")),
        }
        copied_until = end;
    }
    out.push_str(&text[copied_until..]);
    result.text = out;
    for (_, _, name) in spans {
        result.add_redactions(name, 1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, EngineConfig};
    use crate::fake_secrets;
    use crate::scrub::tests::{scrubber_with_learned, value_only_marker};

    fn learned(name: &str, value: &str, shape: Option<&str>) -> crate::config::LearnedSecret {
        crate::config::LearnedSecret {
            name: name.into(),
            sha256: sha256_hex(value),
            byte_len: value.len(),
            shape: shape.map(Into::into),
        }
    }

    #[test]
    fn learned_exact_value_is_redacted_as_a_token_or_assignment_value() {
        let v = fake_secrets::alnum(24);
        let scrubber = scrubber_with_learned(vec![learned("db_pass", &v, None)]);
        let marker = value_only_marker("db_pass", &v);
        for (input, expected) in [
            (format!("pw {v} end"), format!("pw {marker} end")),
            (format!("DB_PASS={v}"), format!("DB_PASS={marker}")),
            (format!("\"DB_PASS={v}\""), format!("\"DB_PASS={marker}\"")),
            (format!("db_pass: '{v}'"), format!("db_pass: '{marker}'")),
            (format!("x:y={v}"), format!("x:y={marker}")),
            (format!("it is {v}."), format!("it is {marker}.")),
            (format!("K={v}:!"), format!("K={marker}:!")),
        ] {
            let result = scrubber.scrub(&input);
            assert_eq!(result.text, expected);
            assert_eq!(result.counts_by_pattern.get("db_pass"), Some(&1));
        }
        // A different value of the same length, or the value inside a longer token, is not it.
        let other = fake_secrets::alnum(24);
        assert_eq!(scrubber.scrub(&other).text, other);
        let longer = format!("{v}x");
        assert_eq!(scrubber.scrub(&longer).text, longer);
    }

    #[test]
    fn learned_short_value_gets_no_hint() {
        // The 4-char hint would be most or all of a short value.
        let v = "Pw9xQz7k";
        let scrubber = scrubber_with_learned(vec![learned("pin", v, None)]);
        assert_eq!(
            scrubber.scrub(&format!("PIN={v}")).text,
            "PIN=[REDACTED:pin]"
        );
    }

    #[test]
    fn learned_value_with_characters_outside_the_token_set_is_redacted() {
        // `@` splits the token rule's runs, so the whitespace-delimited run must catch it.
        let v = "P@ssw0rd2024";
        let scrubber = scrubber_with_learned(vec![learned("db_password", v, None)]);
        let marker = "[REDACTED:db_password ...2024]";
        for (input, expected) in [
            (format!("pw {v} here"), format!("pw {marker} here")),
            (format!("DB_PASSWORD={v}"), format!("DB_PASSWORD={marker}")),
            (format!("it is {v}."), format!("it is {marker}.")),
        ] {
            let result = scrubber.scrub(&input);
            assert_eq!(result.text, expected);
            assert_eq!(result.count, 1);
        }
    }

    #[test]
    fn learned_quoted_value_is_redacted_inside_its_quotes() {
        // Env, JSON and YAML quote the value, so the candidate after `=`/`:` carries quotes.
        let v = "P@ssw0rd2024";
        let scrubber = scrubber_with_learned(vec![learned("db_password", v, None)]);
        let marker = "[REDACTED:db_password ...2024]";
        for (input, expected) in [
            (
                format!("PASSWORD=\"{v}\""),
                format!("PASSWORD=\"{marker}\""),
            ),
            (
                format!("\"password\":\"{v}\","),
                format!("\"password\":\"{marker}\","),
            ),
            (format!("db_pass: '{v}'"), format!("db_pass: '{marker}'")),
            (format!("PASSWORD={v}"), format!("PASSWORD={marker}")),
        ] {
            let result = scrubber.scrub(&input);
            assert_eq!(result.text, expected);
            assert_eq!(result.count, 1);
        }
    }

    #[test]
    fn quoted_value_ending_in_paren_keeps_the_paren() {
        // Peeling trailing punctuation after the quotes would drop the `)`, so the
        // quote-only stage must stay a candidate.
        let v = "Pa55w0rd(x)";
        let scrubber = scrubber_with_learned(vec![learned("db_password", v, None)]);
        let result = scrubber.scrub(&format!("KEY=\"{v}\""));
        assert_eq!(result.text, "KEY=\"[REDACTED:db_password]\"");
    }

    #[test]
    fn quoted_non_secret_is_untouched() {
        let scrubber = scrubber_with_learned(vec![learned("db_password", "P@ssw0rd2024", None)]);
        for input in [
            "PASSWORD=\"N0t@Secret99\"",
            "PASSWORD=\"P@ssw0rd2024x\"",
            "\"P@ssw0rd2024x\",",
        ] {
            assert_eq!(scrubber.scrub(input).text, input);
        }
    }

    #[test]
    fn learned_shape_catches_a_rotated_value_and_wins_over_exact() {
        let v = format!("acme_{}", fake_secrets::alnum(24));
        let shape = r"\bacme_[a-zA-Z0-9]{20,28}\b";
        let scrubber = scrubber_with_learned(vec![learned("acme_key", &v, Some(shape))]);
        let rotated = format!("acme_{}", fake_secrets::alnum(27));
        let result = scrubber.scrub(&format!("{v} {rotated}"));
        assert_eq!(
            result.text,
            format!(
                "{} {}",
                value_only_marker("acme_key", &v),
                value_only_marker("acme_key", &rotated)
            )
        );
        assert_eq!(result.count, 2, "same span must not be redacted twice");
        assert_eq!(result.counts_by_pattern.get("acme_key"), Some(&2));
    }

    #[test]
    fn bad_learned_shape_is_an_error() {
        let cfg = Config {
            learned: vec![learned("x", "abc_def", Some("("))],
            ..Default::default()
        };
        assert!(Scrubber::new(&cfg, &EngineConfig::default()).is_err());
    }
}
