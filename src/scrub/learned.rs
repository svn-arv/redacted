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
mod tests;
