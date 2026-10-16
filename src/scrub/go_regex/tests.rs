//! Unit tests for the Go regex translation.

use super::*;
use crate::fake_secrets;
use crate::scrub::tests::{default_scrubber, value_only_marker};

#[test]
fn go_shorthand_classes_match_ascii_only() {
    // Go's \b is ASCII-only, so a letter like é before SK is still a boundary.
    let sid = fake_secrets::twilio_sid("SK");
    let result = default_scrubber().scrub(&format!("é{sid}"));
    assert_eq!(
        result.text,
        format!("é{}", value_only_marker("twilio_api_key", &sid))
    );
    // Go's \s excludes NBSP, so it ends the PEM body match.
    assert_eq!(
        go_to_rust_regex(r"[^\s]\s\b"),
        r"[^\t\n\f\r ][\t\n\f\r ](?-u:\b)"
    );
}
