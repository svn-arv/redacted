//! Learned tier: secrets `init` stored as a sha256 and length, matched exactly
//! or by their derived shape, and the markers that replace them.

use sha2::{Digest, Sha256};

use super::{tail, ScrubResult, Scrubber};

impl Scrubber {
    /// Shapes first, then exact hashes on the rewritten text, so a span a shape
    /// already redacted is a marker and cannot match again.
    // `pub(super)`: visible to the parent module (scrub.rs), which calls it. A child
    // module may add `impl Scrubber` blocks and read the struct's private fields.
    pub(super) fn scrub_learned(&self, result: &mut ScrubResult) {
        for (name, re) in &self.shapes {
            let spans = re
                .find_iter(&result.text)
                .map(|m| (m.start(), m.end(), name.as_str()))
                .collect();
            replace_spans(result, spans);
        }
        if self.exact.is_empty() {
            return;
        }
        // A value holding `@`, `(` or quotes spans several safe runs, so whitespace-delimited
        // runs go second, on the rewritten text so a marker is never matched again.
        for run_regex in [&self.safe_run, &self.word_run] {
            let runs = run_regex
                .find_iter(&result.text)
                .map(|m| (m.start(), m.end()))
                .collect();
            let spans = self.exact_spans(&result.text, runs);
            replace_spans(result, spans);
        }
    }

    fn exact_spans(&self, text: &str, runs: Vec<(usize, usize)>) -> Vec<(usize, usize, &str)> {
        let mut spans = Vec::new();
        // A labeled loop: `continue 'runs` jumps to the next run from the inner loops.
        'runs: for (run_start, run_end) in runs {
            // `KEY=value` is one run, so also try each suffix after `=` or `:`.
            let mut starts = vec![run_start];
            let run = &text[run_start..run_end];
            starts.extend(
                run.match_indices(['=', ':'])
                    .map(|(i, _)| run_start + i + 1),
            );
            for start in starts {
                for (s, e) in unwrap_candidates(text, start, run_end) {
                    if s >= e || !self.exact_lens.contains(&(e - s)) {
                        continue;
                    }
                    if let Some(name) = self.exact.get(&sha256_hex(&text[s..e])) {
                        spans.push((s, e, name.as_str()));
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
fn unwrap_candidates(text: &str, start: usize, end: usize) -> [(usize, usize); 4] {
    const TRAIL: [char; 9] = ['.', ':', '!', '?', ',', ';', ')', '}', ']'];
    let trailed = start + text[start..end].trim_end_matches(TRAIL).len();
    // Slice pattern: the first and last byte are the same quote character.
    let (qs, qe) = match text.as_bytes()[start..trailed] {
        [q @ (b'"' | b'\''), .., l] if q == l => (start + 1, trailed - 1),
        _ => (start, trailed),
    };
    let again = qs + text[qs..qe].trim_end_matches(TRAIL).len();
    [(start, end), (start, trailed), (qs, qe), (qs, again)]
}

pub fn sha256_hex(s: &str) -> String {
    Sha256::digest(s.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// The 4-char hint, left out when it would be a third or more of the value.
pub fn learned_hint(value: &str) -> &str {
    if value.chars().count() < 12 {
        return "";
    }
    tail(value, 4)
}

/// Rewrites sorted, non-overlapping spans as learned markers.
fn replace_spans(result: &mut ScrubResult, spans: Vec<(usize, usize, &str)>) {
    if spans.is_empty() {
        return;
    }
    let text = &result.text;
    let mut out = String::with_capacity(text.len());
    let mut last = 0;
    for &(start, end, name) in &spans {
        out.push_str(&text[last..start]);
        let hint = learned_hint(&text[start..end]);
        if hint.is_empty() {
            out.push_str(&format!("[REDACTED:{name}]"));
        } else {
            out.push_str(&format!("[REDACTED:{name} ...{hint}]"));
        }
        last = end;
    }
    out.push_str(&text[last..]);
    result.text = out;
    for (_, _, name) in spans {
        result.add(name, 1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, EngineConfig};
    use crate::fake;
    use crate::scrub::tests::{value_only, with_learned};

    fn learned(name: &str, value: &str, shape: Option<&str>) -> crate::config::Learned {
        crate::config::Learned {
            name: name.into(),
            sha256: sha256_hex(value),
            len: value.len(),
            shape: shape.map(Into::into),
        }
    }

    #[test]
    fn learned_exact_value_is_redacted_as_a_token_or_assignment_value() {
        let v = fake::alnum(24);
        let s = with_learned(vec![learned("db_pass", &v, None)]);
        let marker = value_only("db_pass", &v);
        for (input, want) in [
            (format!("pw {v} end"), format!("pw {marker} end")),
            (format!("DB_PASS={v}"), format!("DB_PASS={marker}")),
            (format!("\"DB_PASS={v}\""), format!("\"DB_PASS={marker}\"")),
            (format!("db_pass: '{v}'"), format!("db_pass: '{marker}'")),
            (format!("x:y={v}"), format!("x:y={marker}")),
            (format!("it is {v}."), format!("it is {marker}.")),
            (format!("K={v}:!"), format!("K={marker}:!")),
        ] {
            let r = s.scrub(&input);
            assert_eq!(r.text, want);
            assert_eq!(r.by_pattern.get("db_pass"), Some(&1));
        }
        // A different value of the same length, or the value inside a longer token, is not it.
        let other = fake::alnum(24);
        assert_eq!(s.scrub(&other).text, other);
        let longer = format!("{v}x");
        assert_eq!(s.scrub(&longer).text, longer);
    }

    #[test]
    fn learned_short_value_gets_no_hint() {
        // The 4-char hint would be most or all of a short value.
        let v = "Pw9xQz7k";
        let s = with_learned(vec![learned("pin", v, None)]);
        assert_eq!(s.scrub(&format!("PIN={v}")).text, "PIN=[REDACTED:pin]");
    }

    #[test]
    fn learned_value_with_characters_outside_the_token_set_is_redacted() {
        // `@` splits the token rule's runs, so the whitespace-delimited run must catch it.
        let v = "P@ssw0rd2024";
        let s = with_learned(vec![learned("db_password", v, None)]);
        let marker = "[REDACTED:db_password ...2024]";
        for (input, want) in [
            (format!("pw {v} here"), format!("pw {marker} here")),
            (format!("DB_PASSWORD={v}"), format!("DB_PASSWORD={marker}")),
            (format!("it is {v}."), format!("it is {marker}.")),
        ] {
            let r = s.scrub(&input);
            assert_eq!(r.text, want);
            assert_eq!(r.count, 1);
        }
    }

    #[test]
    fn learned_quoted_value_is_redacted_inside_its_quotes() {
        // Env, JSON and YAML quote the value, so the candidate after `=`/`:` carries quotes.
        let v = "P@ssw0rd2024";
        let s = with_learned(vec![learned("db_password", v, None)]);
        let m = "[REDACTED:db_password ...2024]";
        for (input, want) in [
            (format!("PASSWORD=\"{v}\""), format!("PASSWORD=\"{m}\"")),
            (
                format!("\"password\":\"{v}\","),
                format!("\"password\":\"{m}\","),
            ),
            (format!("db_pass: '{v}'"), format!("db_pass: '{m}'")),
            (format!("PASSWORD={v}"), format!("PASSWORD={m}")),
        ] {
            let r = s.scrub(&input);
            assert_eq!(r.text, want);
            assert_eq!(r.count, 1);
        }
        // A quoted value that ends in a strip character keeps it.
        let v = "Pa55w0rd(x)";
        let s = with_learned(vec![learned("db_password", v, None)]);
        let r = s.scrub(&format!("KEY=\"{v}\""));
        assert_eq!(r.text, "KEY=\"[REDACTED:db_password]\"");
    }

    #[test]
    fn quoted_non_secret_is_untouched() {
        let s = with_learned(vec![learned("db_password", "P@ssw0rd2024", None)]);
        for input in [
            "PASSWORD=\"N0t@Secret99\"",
            "PASSWORD=\"P@ssw0rd2024x\"",
            "\"P@ssw0rd2024x\",",
        ] {
            assert_eq!(s.scrub(input).text, input);
        }
    }

    #[test]
    fn learned_shape_catches_a_rotated_value_and_wins_over_exact() {
        let v = format!("acme_{}", fake::alnum(24));
        let shape = r"\bacme_[a-zA-Z0-9]{20,28}\b";
        let s = with_learned(vec![learned("acme_key", &v, Some(shape))]);
        let rotated = format!("acme_{}", fake::alnum(27));
        let r = s.scrub(&format!("{v} {rotated}"));
        assert_eq!(
            r.text,
            format!(
                "{} {}",
                value_only("acme_key", &v),
                value_only("acme_key", &rotated)
            )
        );
        assert_eq!(r.count, 2, "same span must not be redacted twice");
        assert_eq!(r.by_pattern.get("acme_key"), Some(&2));
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
