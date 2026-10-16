//! Unit tests for the skip guards.

use crate::config::{Config, EngineConfig};
use crate::fake_secrets;
use crate::scrub::Scrubber;
use crate::scrub::tests::{
    default_scrubber, enabled_heuristic, pii_scrubber, scrubber_with_heuristic,
};

#[test]
fn code_identifiers_after_a_secret_key_are_not_redacted() {
    // Same includes_key guards as Go: method calls and identifiers are code, not secrets.
    let scrubber = default_scrubber();
    for input in [
        "SPACES_SECRET_KEY=spaces.secret_key",
        "SPACES_SECRET_KEY=SPACES_SECRET_KEY",
        "SPACES_SECRET_KEY=ENV.fetch(KEY)",
        "SPACES_SECRET_KEY=placeholder",
    ] {
        assert_eq!(scrubber.scrub(input).text, input);
    }
}

#[test]
fn heuristic_leaves_ids_urls_calls_and_plain_hex_unredacted() {
    let scrubber = scrubber_with_heuristic(enabled_heuristic());
    for input in [
        "session_id=Xy7aB3kQ9mZ2pL5nR8tW",
        "url=https://Xy7aB3kQ9mZ2pL5nR8tW.example.com/a",
        "see https://host.example.com:8080/Xy7aB3kQ9mZ2pL5nR8tW",
        "FOO_CONF=Xy7aB3kQ9mZ2pL5nR8tW(arg)",
        "FOO_CONF=3f2a9c1d4e5b6a7c8d9e0f1a2b3c4d5e",
        "MSG=Hello%20World%20From%20Abc123",
    ] {
        assert_eq!(scrubber.scrub(input).text, input, "{input}");
    }
    // Hex under a *_KEY name still redacts though the scorer rejects 2-class hex.
    assert!(
        scrubber
            .scrub("SIGNING_KEY=3f2a9c1d4e5b6a7c8d9e0f1a2b3c4d5e")
            .has_redactions()
    );
}

#[test]
fn pii_leaves_numbers_that_only_look_like_phones_and_unowned_emails_alone() {
    // Timestamps, IPs, versions and ids fill tool output; redacting them would bury the signal.
    let scrubber = pii_scrubber();
    for input in [
        "2026-10-16T12:34:56+07:00",
        "2026-10-16 12:34:56",
        "192.168.100.200",
        "10.0.0.1:3000",
        "v2.1.292",
        "1.2.3",
        "6f1c2b7e-3d4a-4e8b-9c1d-2a3b4c5d6e7f",
        "3f9a1c2b7e4d5a6b8c9d0e1f2a3b4c5d6e7f8a9b",
        "1791860933376006001",
        "1,234,567.89",
        "@@ -120,7 +120,8 @@",
        "978-3-16-148410-0",
        "4111 1111 1111 1111",
        "someone@example.com",
        "admin@mail.example.org",
        "qa@app.test",
        "noreply@github.com",
        "no-reply@accounts.redacted.my.id",
        "12345678+user@users.noreply.github.com",
        "abc@thread.tacv2",
        "https://teams.microsoft.com/l/channel/19%3Aabc@thread.tacv2/General",
        "postgres://user:pass@db.internal.corp/app",
    ] {
        assert_eq!(scrubber.scrub(input).text, input, "{input}");
    }
}

#[test]
fn pii_leaves_ssh_targets_and_shell_prompts_alone() {
    // user@host here names a login on a machine, not a person's mailbox.
    let scrubber = pii_scrubber();
    for input in [
        "git@github.com:svn-arv/redacted.git",
        "ssh deploy@prod.internal.corp uptime",
        "scp a.txt ops@build.internal.corp:/tmp/",
        "ubuntu@ip-10-0-0-1.ec2.internal:~$ ls",
    ] {
        assert_eq!(scrubber.scrub(input).text, input, "{input}");
    }
}

#[test]
fn pii_leaves_added_lines_of_a_unified_diff_alone() {
    // The diff's own `+` makes any number on an added line read as international.
    let diff = "@@ -1,3 +1,3 @@\n+123 456 789\n+10-16-2026\n+1234567890\n";
    assert_eq!(pii_scrubber().scrub(diff).text, diff);
}

#[test]
fn a_credentialed_url_keeps_its_own_label_and_never_gains_an_email_marker() {
    // userinfo is user:password@host, so the email row must not split the URL in two.
    let url = fake_secrets::database_url("postgis", "db.internal.corp");
    let result = pii_scrubber().scrub(&url);
    assert_eq!(result.count, 1);
    assert_eq!(result.counts_by_pattern.get("credentialed_url"), Some(&1));

    // With the URL rows off, the email row sees the raw URL first and must still skip it.
    let cfg = Config {
        disabled_patterns: vec!["database_url".into(), "credentialed_url".into()],
        pii: crate::config::PiiConfig {
            email: true,
            phone: true,
        },
        ..Default::default()
    };
    let scrubber = Scrubber::new(&cfg, &EngineConfig::default()).unwrap();
    assert_eq!(scrubber.scrub(&url).text, url);
}
