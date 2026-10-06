//! Skip rules: the allow lists and the Go 0.7 guards that keep code, identifiers
//! and URLs from being redacted as secrets.

use std::collections::HashMap;

use super::{Pattern, Scrubber};
use crate::config::{MIN_CHAR_CLASSES, MIN_ENTROPY};

impl Scrubber {
    pub(super) fn skip_match(&self, p: &Pattern, m: &str, text: &str, end: usize) -> bool {
        if self.name_allowed(m) || self.value_allowed(p, m, text, end) {
            return true;
        }
        if !p.includes_key {
            return false;
        }
        if matches!(text.as_bytes().get(end), Some(b'(' | b'[')) {
            return true;
        }
        let value = value_of(m);
        let key = key_of(m);
        if !key.is_empty() && key.eq_ignore_ascii_case(value) {
            return true;
        }
        if looks_like_identifier(value)
            || (looks_like_code_reference(value) && !has_random_segment(value))
        {
            return true;
        }
        if separator_lenient(m)
            && looks_like_lenient_identifier(value)
            && !has_random_segment(value)
        {
            return true;
        }
        if (1..=12).contains(&value.len()) && value.bytes().all(|c| c.is_ascii_lowercase()) {
            return true;
        }
        p.is_heuristic && self.skip_scored(m, value, text, end)
    }

    /// Go's secret_value guards: identifier keys, URLs, and values that don't score as random.
    fn skip_scored(&self, m: &str, value: &str, text: &str, end: usize) -> bool {
        let key = key_of(m);
        is_identifier_key(key)
            || inside_url(text, end - m.len())
            || (!self.secret_like(value) && !hex_under_key_suffix(key, value))
    }

    /// Lower + upper + digit together is what lets UUIDs, hashes and timestamps through.
    fn secret_like(&self, v: &str) -> bool {
        if v.contains("://") {
            return false;
        }
        let decoded = percent_decode(v);
        // Decoding that reveals a space or control byte means encoded prose.
        if decoded != v.as_bytes() && decoded.iter().any(|&c| c < 0x21 || c == 0x7f) {
            return false;
        }
        let decoded_text = String::from_utf8_lossy(&decoded);
        let h = &self.heuristic_thresholds;
        let len = decoded_text.chars().count();
        (h.min_length..=h.max_length).contains(&len)
            && char_classes(&decoded_text) >= h.min_char_classes
            && shannon_entropy(&decoded_text) >= h.min_entropy
    }

    fn name_allowed(&self, m: &str) -> bool {
        if self.allowed_keys_upper.is_empty() {
            return false;
        }
        let upper = m.to_uppercase();
        self.allowed_keys_upper
            .iter()
            .any(|name| upper.contains(name.as_str()))
    }

    fn value_allowed(&self, p: &Pattern, m: &str, text: &str, end: usize) -> bool {
        if self.allow_values.is_empty() {
            return false;
        }
        let candidate = if p.includes_key {
            allow_value_token(m, text, end)
        } else {
            m.to_string()
        };
        self.allow_values.iter().any(|re| re.is_match(&candidate))
    }
}

fn hex_under_key_suffix(key: &str, value: &str) -> bool {
    if key.len() < 4 || value.len() < 24 || !value.bytes().all(|c| c.is_ascii_hexdigit()) {
        return false;
    }
    let upper = key.to_uppercase();
    upper.ends_with("_KEY") || upper.ends_with("-KEY")
}

/// Whether the token holding `start` begins with a URL scheme (Go caps the walk at 2048).
fn inside_url(text: &str, start: usize) -> bool {
    let b = text.as_bytes();
    let mut i = start;
    while i > 0 && start - i < 2048 && !is_token_boundary(b[i - 1]) {
        i -= 1;
    }
    b[i..start].windows(3).any(|w| w == b"://")
}

fn is_identifier_key(key: &str) -> bool {
    let k = key.to_lowercase();
    k == "id"
        || k == "uuid"
        || ["_id", "-id", "_uuid", "-uuid"]
            .iter()
            .any(|s| k.ends_with(s))
        || key.ends_with("Id")
        || key.ends_with("Uuid")
}

/// Each %XX becomes its byte; a malformed `%` stays literal and `+` is never a space.
fn percent_decode(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let hex = |c: u8| (c as char).to_digit(16);
        if b[i] == b'%' && i + 2 < b.len() {
            if let (Some(h), Some(l)) = (hex(b[i + 1]), hex(b[i + 2])) {
                out.push((h * 16 + l) as u8);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    out
}

fn key_of(m: &str) -> &str {
    match m.find(['=', ':']) {
        Some(i) => m[..i]
            .trim_end_matches([' ', '\t'])
            .trim_matches(['"', '\'']),
        None => "",
    }
}

fn value_of(m: &str) -> &str {
    let Some(i) = m.find(['=', ':']) else {
        return "";
    };
    let v = m[i + 1..].strip_prefix('>').unwrap_or(&m[i + 1..]);
    let v = v.trim_start_matches([' ', '\t']);
    v.strip_prefix(['\'', '"']).unwrap_or(v)
}

fn allow_value_token(m: &str, text: &str, end: usize) -> String {
    let rest = &text[end..];
    let n = rest
        .bytes()
        .position(is_token_boundary)
        .unwrap_or(rest.len());
    format!("{}{}", value_of(m), &rest[..n])
}

fn is_token_boundary(c: u8) -> bool {
    matches!(
        c,
        b' ' | b'\t'
            | b'\n'
            | b'\r'
            | b'"'
            | b'\''
            | b'`'
            | b'('
            | b')'
            | b'['
            | b']'
            | b'{'
            | b'}'
            | b'<'
            | b'>'
            | b','
            | b';'
    )
}

fn looks_like_identifier(v: &str) -> bool {
    let (mut lower, mut upper, mut sep) = (false, false, false);
    for c in v.chars() {
        match c {
            'a'..='z' => lower = true,
            'A'..='Z' => upper = true,
            '_' | '.' => sep = true,
            _ => return false,
        }
    }
    sep && lower != upper
}

fn looks_like_code_reference(v: &str) -> bool {
    let (mut sep, mut lower, mut upper) = (false, false, false);
    for c in v.chars() {
        match c {
            'a'..='z' => lower = true,
            'A'..='Z' => upper = true,
            '0'..='9' | '_' => {}
            '.' | ':' => sep = true,
            _ => return false,
        }
    }
    sep && lower && upper
}

fn has_random_segment(value: &str) -> bool {
    value
        .split(['.', ':'])
        .filter(|s| !s.is_empty())
        .any(|s| char_classes(s) >= MIN_CHAR_CLASSES && shannon_entropy(s) >= MIN_ENTROPY)
}

fn char_classes(v: &str) -> usize {
    [
        v.bytes().any(|c| c.is_ascii_lowercase()),
        v.bytes().any(|c| c.is_ascii_uppercase()),
        v.bytes().any(|c| c.is_ascii_digit()),
    ]
    .into_iter()
    .filter(|&b| b)
    .count()
}

fn shannon_entropy(s: &str) -> f64 {
    let mut counts: HashMap<char, usize> = HashMap::new();
    for c in s.chars() {
        *counts.entry(c).or_default() += 1;
    }
    let total = s.chars().count() as f64;
    counts
        .values()
        .map(|&n| {
            let p = n as f64 / total;
            -p * p.log2()
        })
        .sum()
}

fn separator_lenient(m: &str) -> bool {
    let b = m.as_bytes();
    for (i, &c) in b.iter().enumerate() {
        match c {
            b':' => return true,
            b'=' => {
                if b.get(i + 1) == Some(&b'>') {
                    return true;
                }
                let spaced = |c: Option<&u8>| matches!(c, Some(b' ' | b'\t'));
                return i > 0 && spaced(b.get(i - 1)) && spaced(b.get(i + 1));
            }
            _ => {}
        }
    }
    false
}

fn looks_like_lenient_identifier(v: &str) -> bool {
    let stem = v.strip_suffix(['?', '!']).unwrap_or(v);
    let (mut letter, mut upper, mut lower, mut digit, mut sep) =
        (false, false, false, false, false);
    for c in stem.bytes() {
        match c {
            b'a'..=b'z' => (lower, letter) = (true, true),
            b'A'..=b'Z' => (upper, letter) = (true, true),
            b'0'..=b'9' => digit = true,
            b'_' | b'.' | b'&' | b'#' => sep = true,
            _ => return false,
        }
    }
    letter && (sep || (!digit && upper && lower))
}

#[cfg(test)]
mod tests {
    use crate::scrub::tests::{default_scrubber, enabled_heuristic, scrubber_with_heuristic};

    #[test]
    fn keyed_identifier_values_are_skipped() {
        // Same includes_key guards as Go: method calls and identifiers are code, not secrets.
        let s = default_scrubber();
        for input in [
            "SPACES_SECRET_KEY=spaces.secret_key",
            "SPACES_SECRET_KEY=SPACES_SECRET_KEY",
            "SPACES_SECRET_KEY=ENV.fetch(KEY)",
            "SPACES_SECRET_KEY=placeholder",
        ] {
            assert_eq!(s.scrub(input).text, input);
        }
    }

    #[test]
    fn heuristic_keeps_the_go_skip_guards() {
        let s = scrubber_with_heuristic(enabled_heuristic());
        for input in [
            "session_id=Xy7aB3kQ9mZ2pL5nR8tW",
            "url=https://Xy7aB3kQ9mZ2pL5nR8tW.example.com/a",
            "see https://host.example.com:8080/Xy7aB3kQ9mZ2pL5nR8tW",
            "FOO_CONF=Xy7aB3kQ9mZ2pL5nR8tW(arg)",
            "FOO_CONF=3f2a9c1d4e5b6a7c8d9e0f1a2b3c4d5e",
            "MSG=Hello%20World%20From%20Abc123",
        ] {
            assert_eq!(s.scrub(input).text, input, "{input}");
        }
        // Hex under a *_KEY name still redacts though the scorer rejects 2-class hex.
        assert!(
            s.scrub("SIGNING_KEY=3f2a9c1d4e5b6a7c8d9e0f1a2b3c4d5e")
                .has_redactions()
        );
    }
}
