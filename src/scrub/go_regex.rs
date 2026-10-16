//! Translation of Go RE2 regex syntax into Rust's `regex` dialect.

use std::iter::Peekable;
use std::str::Chars;

/// Rewrites Go RE2 syntax so it matches the same text under Rust's regex:
/// Go's \s \d \w \b are ASCII-only (\s without \v), and Go reads `[`, `&&`,
/// `--`, `~~` inside a class as literals where Rust nests or combines sets.
pub(super) fn go_to_rust_regex(expr: &str) -> String {
    let mut out = String::with_capacity(expr.len() + 16);
    let mut chars = expr.chars().peekable();
    let mut in_class = false;
    while let Some(c) = chars.next() {
        match c {
            '\\' => push_translated_escape(&mut chars, &mut out, in_class),
            '[' if !in_class => {
                in_class = true;
                out.push('[');
                if chars.peek() == Some(&'^') {
                    out.push('^');
                    chars.next();
                }
                if chars.peek() == Some(&']') {
                    out.push_str(r"\]");
                    chars.next();
                }
            }
            '[' if chars.peek() == Some(&':') => {
                // [:alpha:] inside a class: copy through the closing :]
                out.push('[');
                for c in chars.by_ref() {
                    out.push(c);
                    if c == ']' {
                        break;
                    }
                }
            }
            ']' if in_class => {
                in_class = false;
                out.push(']');
            }
            '[' | '&' | '~' if in_class => {
                out.push('\\');
                out.push(c);
            }
            '-' if in_class && chars.peek() == Some(&'-') => out.push_str(r"\-"),
            _ => out.push(c),
        }
    }
    out
}

/// Copies the escape after a backslash, in Rust's spelling where the dialects differ.
fn push_translated_escape(chars: &mut Peekable<Chars>, out: &mut String, in_class: bool) {
    let Some(escaped) = chars.next() else {
        out.push('\\');
        return;
    };
    match translate_escape(escaped, in_class) {
        Some(ascii) => out.push_str(ascii),
        None => {
            out.push('\\');
            out.push(escaped);
        }
    }
}

/// The ASCII-only Rust spelling of Go's `\s` `\d` `\w` `\b` (or `\S` `\D` `\W`), given
/// the letter after the backslash; bare ranges inside `[...]`. None: both read it alike.
fn translate_escape(escaped: char, in_class: bool) -> Option<&'static str> {
    let ascii = match (escaped, in_class) {
        ('s', false) => r"[\t\n\f\r ]",
        ('s', true) => r"\t\n\f\r ",
        ('S', _) => r"[^\t\n\f\r ]",
        ('d', false) => "[0-9]",
        ('d', true) => "0-9",
        ('D', _) => "[^0-9]",
        ('w', false) => "[0-9A-Za-z_]",
        ('w', true) => "0-9A-Za-z_",
        ('W', _) => "[^0-9A-Za-z_]",
        ('b', false) => r"(?-u:\b)",
        _ => return None,
    };
    Some(ascii)
}

#[cfg(test)]
mod tests;
