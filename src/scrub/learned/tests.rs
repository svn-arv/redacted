//! Unit tests for the learned tier.

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
        (format!("DB_PASS={v}"), format!("DB_PASS={marker}")),
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
        (format!("DB_PASS=\"{v}\""), format!("DB_PASS=\"{marker}\"")),
        (
            format!("\"db_pass\":\"{v}\","),
            format!("\"db_pass\":\"{marker}\","),
        ),
        (format!("db_pass: '{v}'"), format!("db_pass: '{marker}'")),
        (format!("SECRET={v}"), format!("SECRET={marker}")),
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
        "DB_PASS=\"N0t@Secret99\"",
        "DB_PASS=\"P@ssw0rd2024x\"",
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
