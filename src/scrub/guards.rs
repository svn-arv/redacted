//! Skip guards: the allow lists and the Go 0.7 guards that keep code, identifiers
//! and URLs from being redacted as secrets.

use std::collections::HashMap;

use super::{Pattern, Scrubber};
use crate::config::{DEFAULT_MIN_CHAR_CLASSES, DEFAULT_MIN_ENTROPY};

impl Scrubber {
    pub(super) fn should_skip_match(
        &self,
        pattern: &Pattern,
        matched: &str,
        text: &str,
        end: usize,
    ) -> bool {
        if self.contains_allowed_key(matched)
            || self.matches_allow_values(pattern, matched, text, end)
            || is_pii_lookalike(&pattern.name, matched, text, end - matched.len())
        {
            return true;
        }
        if !pattern.includes_key {
            return false;
        }
        if matches!(text.as_bytes().get(end), Some(b'(' | b'[')) {
            return true;
        }
        let value = value_of(matched);
        let key = key_of(matched);
        if !key.is_empty() && key.eq_ignore_ascii_case(value) {
            return true;
        }
        if looks_like_identifier(value)
            || (looks_like_code_reference(value) && !has_random_segment(value))
        {
            return true;
        }
        if has_code_style_separator(matched)
            && looks_like_code_expression(value)
            && !has_random_segment(value)
        {
            return true;
        }
        if (1..=12).contains(&value.len()) && value.bytes().all(|c| c.is_ascii_lowercase()) {
            return true;
        }
        pattern.is_heuristic && self.should_skip_heuristic_match(matched, value, text, end)
    }

    /// Go's secret_value guards: identifier keys, URLs, and values that don't score as random.
    fn should_skip_heuristic_match(
        &self,
        matched: &str,
        value: &str,
        text: &str,
        end: usize,
    ) -> bool {
        let key = key_of(matched);
        is_id_key(key)
            || is_inside_url(text, end - matched.len())
            || (!self.looks_random(value) && !is_long_hex_under_key_name(key, value))
    }

    /// Lower + upper + digit together is what lets UUIDs, hashes and timestamps through.
    fn looks_random(&self, value: &str) -> bool {
        if value.contains("://") {
            return false;
        }
        let decoded = percent_decode(value);
        // Decoding that reveals a space or control byte means encoded prose.
        if decoded != value.as_bytes() && decoded.iter().any(|&c| c < 0x21 || c == 0x7f) {
            return false;
        }
        let decoded_text = String::from_utf8_lossy(&decoded);
        let thresholds = &self.heuristic_thresholds;
        let len = decoded_text.chars().count();
        (thresholds.min_length..=thresholds.max_length).contains(&len)
            && char_class_count(&decoded_text) >= thresholds.min_char_classes
            && shannon_entropy(&decoded_text) >= thresholds.min_entropy
    }

    fn contains_allowed_key(&self, matched: &str) -> bool {
        if self.allowed_keys_upper.is_empty() {
            return false;
        }
        let upper = matched.to_uppercase();
        self.allowed_keys_upper
            .iter()
            .any(|name| upper.contains(name.as_str()))
    }

    fn matches_allow_values(
        &self,
        pattern: &Pattern,
        matched: &str,
        text: &str,
        end: usize,
    ) -> bool {
        if self.allow_values.is_empty() {
            return false;
        }
        let value_to_check = if pattern.includes_key {
            value_through_token_end(matched, text, end)
        } else {
            matched.to_string()
        };
        self.allow_values
            .iter()
            .any(|allow_regex| allow_regex.is_match(&value_to_check))
    }
}

/// Domains reserved for documentation (RFC 2606) and bot senders: no person behind them.
const UNOWNED_EMAIL_DOMAINS: [&str; 8] = [
    "example.com",
    "example.net",
    "example.org",
    "example",
    "test",
    "invalid",
    "localhost",
    "noreply.github.com",
];

/// The PII rows match loose shapes; these are the look-alikes they leave alone.
fn is_pii_lookalike(pattern_name: &str, matched: &str, text: &str, start: usize) -> bool {
    match pattern_name {
        "email" => {
            is_unowned_email(matched)
                || is_url_userinfo(text, start)
                || is_ssh_target(text, start, start + matched.len())
        }
        "phone" => {
            is_embedded_number(text, start, start + matched.len())
                || is_diff_added_line(matched, text, start)
        }
        _ => false,
    }
}

fn is_unowned_email(address: &str) -> bool {
    let Some((local_part, domain)) = address.rsplit_once('@') else {
        return false;
    };
    let domain_lower = domain.to_ascii_lowercase();
    local_part.eq_ignore_ascii_case("noreply")
        || local_part.eq_ignore_ascii_case("no-reply")
        // Whole labels only, so mail.example.com is reserved and notexample.com is not.
        || UNOWNED_EMAIL_DOMAINS.into_iter().any(|parent| {
            domain_lower == parent || domain_lower.ends_with(&format!(".{parent}"))
        })
}

/// `user:password@host` inside a URL is a login the URL rows own, not an address.
fn is_url_userinfo(text: &str, start: usize) -> bool {
    matches!(text.as_bytes()[..start].last(), Some(b':' | b'/')) && is_inside_url(text, start)
}

/// Commands that take user@host as a login on a machine.
const SSH_COMMANDS: [&str; 5] = ["ssh", "scp", "sftp", "rsync", "ssh-copy-id"];

/// `user@host:path` (scp, git remotes, shell prompts) or `ssh user@host` is a login, not a mailbox.
fn is_ssh_target(text: &str, start: usize, end: usize) -> bool {
    let word_before = text[..start].split_whitespace().next_back();
    text.as_bytes().get(end) == Some(&b':')
        || word_before.is_some_and(|word| SSH_COMMANDS.contains(&word))
}

/// In a unified diff, a `+` at column 0 marks an added line, not a country code.
fn is_diff_added_line(matched: &str, text: &str, start: usize) -> bool {
    let is_line_start = start == 0 || text.as_bytes()[start - 1] == b'\n';
    // The text scan runs only for a `+` at column 0, so other matches stay cheap.
    matched.starts_with('+') && is_line_start && (text.starts_with("@@ ") || text.contains("\n@@ "))
}

/// Digits glued to a word, version, IP or timestamp belong to it, not to a phone.
fn is_embedded_number(text: &str, start: usize, end: usize) -> bool {
    let bytes = text.as_bytes();
    let is_glued_before = bytes[..start]
        .last()
        .is_some_and(|before| before.is_ascii_alphanumeric() || b".-+".contains(before));
    let is_continued_after = matches!(bytes.get(end), Some(b'.' | b':'))
        && bytes.get(end + 1).is_some_and(u8::is_ascii_digit);
    is_glued_before || is_continued_after
}

fn is_long_hex_under_key_name(key: &str, value: &str) -> bool {
    if key.len() < 4 || value.len() < 24 || !value.bytes().all(|c| c.is_ascii_hexdigit()) {
        return false;
    }
    let upper = key.to_uppercase();
    upper.ends_with("_KEY") || upper.ends_with("-KEY")
}

/// Whether the token holding `start` begins with a URL scheme (Go caps the walk at 2048).
fn is_inside_url(text: &str, start: usize) -> bool {
    let bytes = text.as_bytes();
    let mut i = start;
    while i > 0 && start - i < 2048 && !is_token_boundary(bytes[i - 1]) {
        i -= 1;
    }
    bytes[i..start].windows(3).any(|w| w == b"://")
}

fn is_id_key(key: &str) -> bool {
    let key_lower = key.to_lowercase();
    key_lower == "id"
        || key_lower == "uuid"
        || ["_id", "-id", "_uuid", "-uuid"]
            .iter()
            .any(|s| key_lower.ends_with(s))
        || key.ends_with("Id")
        || key.ends_with("Uuid")
}

/// Each %XX becomes its byte; a malformed `%` stays literal and `+` is never a space.
pub fn percent_decode(encoded: &str) -> Vec<u8> {
    let bytes = encoded.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let hex = |c: u8| (c as char).to_digit(16);
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let (Some(high_nibble), Some(low_nibble)) = (hex(bytes[i + 1]), hex(bytes[i + 2]))
        {
            out.push((high_nibble * 16 + low_nibble) as u8);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    out
}

fn key_of(matched: &str) -> &str {
    match matched.find(['=', ':']) {
        Some(i) => matched[..i]
            .trim_end_matches([' ', '\t'])
            .trim_matches(['"', '\'']),
        None => "",
    }
}

fn value_of(matched: &str) -> &str {
    let Some(i) = matched.find(['=', ':']) else {
        return "";
    };
    let value = matched[i + 1..]
        .strip_prefix('>')
        .unwrap_or(&matched[i + 1..]);
    let value = value.trim_start_matches([' ', '\t']);
    value.strip_prefix(['\'', '"']).unwrap_or(value)
}

fn value_through_token_end(matched: &str, text: &str, end: usize) -> String {
    let rest = &text[end..];
    let token_len = rest
        .bytes()
        .position(is_token_boundary)
        .unwrap_or(rest.len());
    format!("{}{}", value_of(matched), &rest[..token_len])
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

fn looks_like_identifier(value: &str) -> bool {
    let (mut lower, mut upper, mut sep) = (false, false, false);
    for c in value.chars() {
        match c {
            'a'..='z' => lower = true,
            'A'..='Z' => upper = true,
            '_' | '.' => sep = true,
            _ => return false,
        }
    }
    sep && lower != upper
}

fn looks_like_code_reference(value: &str) -> bool {
    let (mut sep, mut lower, mut upper) = (false, false, false);
    for c in value.chars() {
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
    value.split(['.', ':']).filter(|s| !s.is_empty()).any(|s| {
        char_class_count(s) >= DEFAULT_MIN_CHAR_CLASSES && shannon_entropy(s) >= DEFAULT_MIN_ENTROPY
    })
}

fn char_class_count(value: &str) -> usize {
    [
        value.bytes().any(|c| c.is_ascii_lowercase()),
        value.bytes().any(|c| c.is_ascii_uppercase()),
        value.bytes().any(|c| c.is_ascii_digit()),
    ]
    .into_iter()
    .filter(|&bytes| bytes)
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

fn has_code_style_separator(matched: &str) -> bool {
    let bytes = matched.as_bytes();
    for (i, &c) in bytes.iter().enumerate() {
        match c {
            b':' => return true,
            b'=' => {
                if bytes.get(i + 1) == Some(&b'>') {
                    return true;
                }
                let spaced = |c: Option<&u8>| matches!(c, Some(b' ' | b'\t'));
                return i > 0 && spaced(bytes.get(i - 1)) && spaced(bytes.get(i + 1));
            }
            _ => {}
        }
    }
    false
}

fn looks_like_code_expression(value: &str) -> bool {
    let stem = value.strip_suffix(['?', '!']).unwrap_or(value);
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
mod tests;
