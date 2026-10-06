//! Translation of Go RE2 regex syntax into Rust's `regex` dialect.

/// Rewrites Go RE2 syntax so it matches the same text under Rust's regex:
/// Go's \s \d \w \b are ASCII-only (\s without \v), and Go reads `[`, `&&`,
/// `--`, `~~` inside a class as literals where Rust nests or combines sets.
pub(super) fn go_regex(expr: &str) -> String {
    let mut out = String::with_capacity(expr.len() + 16);
    let mut chars = expr.chars().peekable();
    let mut in_class = false;
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                let Some(n) = chars.next() else {
                    out.push('\\');
                    break;
                };
                out.push_str(match (n, in_class) {
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
                    _ => {
                        out.push('\\');
                        out.push(n);
                        continue;
                    }
                });
            }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fake;
    use crate::scrub::tests::{default_scrubber, value_only};

    #[test]
    fn go_perl_classes_stay_ascii() {
        // Go's \b is ASCII-only, so a letter like é before SK is still a boundary.
        let sid = fake::twilio_sid("SK");
        let r = default_scrubber().scrub(&format!("é{sid}"));
        assert_eq!(r.text, format!("é{}", value_only("twilio_api_key", &sid)));
        // Go's \s excludes NBSP, so it ends the PEM body match.
        assert_eq!(go_regex(r"[^\s]\s\b"), r"[^\t\n\f\r ][\t\n\f\r ](?-u:\b)");
    }
}
