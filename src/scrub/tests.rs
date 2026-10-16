//! Unit tests for the scrub engine.

use super::*;
use crate::fake_secrets;

pub(super) fn default_scrubber() -> Scrubber {
    Scrubber::new(&Config::default(), &EngineConfig::default()).unwrap()
}

/// Both PII toggles on, so the opt-in rows run next to the vendor patterns.
pub(super) fn pii_scrubber() -> Scrubber {
    Scrubber::new(&pii_config(), &EngineConfig::default()).unwrap()
}

fn pii_config() -> Config {
    Config {
        pii: crate::config::PiiConfig {
            email: true,
            phone: true,
        },
        ..Default::default()
    }
}

pub(super) fn value_only_marker(name: &str, secret: &str) -> String {
    format!(
        "[REDACTED:{name} ...{}]",
        fake_secrets::last_four_chars(secret)
    )
}

/// One engine.yml pattern: an input, its exact expected output, and the
/// secret part that must not survive.
pub(super) struct PatternCase {
    pub(super) name: &'static str,
    pub(super) input: String,
    expected: String,
    pub(super) secret: String,
    /// A PII row, compiled only when its `pii` toggle is on.
    pub(super) opt_in: bool,
}

pub(super) fn builtin_pattern_cases() -> Vec<PatternCase> {
    let mut cases = Vec::new();
    let value_only_secrets = generated_secrets().into_iter().chain(prefixed_secrets());
    for (name, secret) in value_only_secrets {
        cases.push(PatternCase {
            name,
            input: secret.clone(),
            expected: value_only_marker(name, &secret),
            secret,
            opt_in: matches!(name, "email" | "phone"),
        });
    }
    // includes_key patterns keep the key and separator and drop the label.
    for (name, key, sep, value) in keyed_secrets() {
        let expected = format!(
            "{key}{} [REDACTED ...{}]",
            sep.trim_end(),
            fake_secrets::last_four_chars(&value)
        );
        cases.push(PatternCase {
            name,
            input: format!("{key}{sep}{value}"),
            expected,
            secret: value,
            opt_in: false,
        });
    }
    cases
}

/// Value-only patterns whose secret comes from a dedicated fake_secrets builder.
fn generated_secrets() -> Vec<(&'static str, String)> {
    vec![
        ("aws_access_key", fake_secrets::aws_access_key()),
        ("github_fine_grained", fake_secrets::github_fine_grained()),
        ("github_token", fake_secrets::github_token("ghp_")),
        ("github_oauth", fake_secrets::github_token("gho_")),
        ("github_refresh", fake_secrets::github_token("ghr_")),
        ("stripe_live", fake_secrets::stripe_key("sk_live_")),
        ("stripe_test", fake_secrets::stripe_key("pk_test_")),
        ("twilio_api_key", fake_secrets::twilio_sid("SK")),
        ("twilio_account_sid", fake_secrets::twilio_sid("AC")),
        ("digitalocean_token", fake_secrets::digitalocean_token()),
        ("sentry_dsn", fake_secrets::sentry_dsn()),
        ("slack_token", fake_secrets::slack_token("xoxb")),
        ("sendgrid_key", fake_secrets::sendgrid_key()),
        ("hubspot_key", fake_secrets::hubspot_pat("na1")),
        ("private_key", fake_secrets::private_key("RSA ")),
        (
            "private_key_truncated",
            fake_secrets::private_key_truncated(""),
        ),
        ("jwt", fake_secrets::jwt()),
        ("npm_token", fake_secrets::npm_token()),
        ("slack_webhook", fake_secrets::slack_webhook()),
        (
            "database_url",
            fake_secrets::database_url("postgres", "db.example.com"),
        ),
        (
            "credentialed_url",
            fake_secrets::database_url("postgis", "db.example.com"),
        ),
        ("email", fake_secrets::email()),
        ("phone", fake_secrets::phone()),
    ]
}

/// Value-only patterns whose secret is a vendor prefix plus a random body.
fn prefixed_secrets() -> Vec<(&'static str, String)> {
    let prefix_and_body = [
        ("anthropic_key", "sk-ant-", fake_secrets::alnum(90)),
        ("circleci_token", "CCIPAT_", fake_secrets::alnum(30)),
        ("sentry_user_token", "sntryu_", fake_secrets::alnum(40)),
        ("rubygems_key", "rubygems_", fake_secrets::alnum(30)),
        ("newrelic_key", "NRAK-", fake_secrets::alnum(27)),
        ("openai_key", "sk-proj-", fake_secrets::alnum(48)),
        ("openai_classic_key", "sk-", fake_secrets::alnum(48)),
        ("google_api_key", "AIza", fake_secrets::base64url(35)),
        ("google_api_key_v2", "AQ.", fake_secrets::base64url(50)),
        ("stripe_webhook_secret", "whsec_", fake_secrets::alnum(32)),
        ("huggingface_token", "hf_", fake_secrets::alnum(34)),
        ("groq_key", "gsk_", fake_secrets::alnum(52)),
        ("openrouter_key", "sk-or-v1-", fake_secrets::hex(64)),
        ("xai_key", "xai-", fake_secrets::alnum(80)),
        ("perplexity_key", "pplx-", fake_secrets::alnum(48)),
        ("tavily_key", "tvly-", fake_secrets::alnum(32)),
        (
            "langsmith_key",
            "lsv2_pt_",
            format!("{}_{}", fake_secrets::alnum(32), fake_secrets::alnum(10)),
        ),
        ("gitlab_pat", "glpat-", fake_secrets::alnum(20)),
        ("pypi_token", "pypi-", fake_secrets::alnum(60)),
    ];
    let mut secrets = Vec::new();
    for (name, prefix, body) in prefix_and_body {
        secrets.push((name, format!("{prefix}{body}")));
    }
    secrets
}

/// includes_key patterns: name, key, separator and the secret value after them.
fn keyed_secrets() -> Vec<(&'static str, &'static str, &'static str, String)> {
    let gcp = fake_secrets::gcp_private_key_field();
    let gcp_value = gcp.trim_start_matches(r#""private_key": "#).to_string();
    vec![
        (
            "aws_secret_key",
            "aws_secret_access_key",
            "=",
            fake_secrets::aws_secret_key(),
        ),
        (
            "digitalocean_spaces",
            "SPACES_SECRET_KEY",
            "=",
            fake_secrets::digitalocean_spaces_value(),
        ),
        (
            "gcp_sa_key_id",
            r#""private_key_id""#,
            ": ",
            format!("\"{}\"", fake_secrets::hex(40)),
        ),
        (
            "auth_header",
            "Authorization",
            ": ",
            format!("Bearer {}", fake_secrets::alnum(32)),
        ),
        ("gcp_sa_private_key", r#""private_key""#, ": ", gcp_value),
        (
            "password_assignment",
            "DB_PASSWORD",
            "=",
            fake_secrets::password(),
        ),
    ]
}

#[test]
fn builtin_patterns_redact_with_label_and_hint() {
    let scrubber = pii_scrubber();
    // Destructuring in the loop header names the fields; `..` skips the rest.
    for PatternCase {
        name,
        input,
        expected,
        ..
    } in builtin_pattern_cases()
    {
        let result = scrubber.scrub(&input);
        assert_eq!(result.text, expected, "{name}: wrong redaction");
        assert_eq!(result.count, 1, "{name}: count");
        assert_eq!(
            result.counts_by_pattern.get(name),
            Some(&1),
            "{name}: label {:?}",
            result.counts_by_pattern
        );
    }
}

#[test]
fn every_builtin_pattern_has_a_test_case() {
    let engine: serde_yaml::Value = serde_yaml::from_str(BUILTIN_ENGINE_YML).unwrap();
    let mut in_yml: Vec<String> = engine["patterns"]
        .as_sequence()
        .unwrap()
        .iter()
        .map(|p| p["name"].as_str().unwrap().to_string())
        .collect();
    let mut in_cases: Vec<String> = builtin_pattern_cases()
        .iter()
        .map(|case| case.name.to_string())
        .collect();
    in_yml.sort();
    in_cases.sort();
    assert_eq!(in_cases, in_yml);
}

#[test]
fn password_assignment_redacts_the_value_in_env_yaml_json_and_libpq_forms() {
    let scrubber = default_scrubber();
    for (input, expected) in [
        ("password=Tr0ub4dor-99", "password= [REDACTED ...r-99]"),
        (
            "DB_PASSWORD=Tr0ub4dor-99",
            "DB_PASSWORD= [REDACTED ...r-99]",
        ),
        (
            "db.password=Tr0ub4dor-99",
            "db.password= [REDACTED ...r-99]",
        ),
        ("password: Tr0ub4dor-99", "password: [REDACTED ...r-99]"),
        (
            r#""password": "Tr0ub4dor-99""#,
            r#""password": [REDACTED ...r-99]""#,
        ),
        (
            "SMTP_PASSWD='Tr0ub4dor-99'",
            "SMTP_PASSWD= [REDACTED ...r-99]'",
        ),
        (
            "DB_PASSWORD=Password2024",
            "DB_PASSWORD= [REDACTED ...2024]",
        ),
        (
            "host=db port=5432 password=P@ssw0rd99 dbname=prod",
            "host=db port=5432 password= [REDACTED ...rd99] dbname=prod",
        ),
    ] {
        let result = scrubber.scrub(input);
        assert_eq!(result.text, expected, "{input}");
        assert_eq!(
            result.counts_by_pattern.get("password_assignment"),
            Some(&1)
        );
    }
}

#[test]
fn password_assignment_skips_other_keys_short_values_and_placeholders() {
    let scrubber = default_scrubber();
    for input in [
        "PASSWORD_FILE=/run/secrets/db",
        "PASSWORD_HASH=Tr0ub4dor-99",
        "pwd: /home/x",
        "DB_PASS=Tr0ub4dor-99",
        "password=Tr0u-99",
        "password=changeme",
        "password: password",
        "DB_PASSWORD=${DB_PASSWORD}",
        "DB_PASSWORD=<your-password>",
        "DB_PASSWORD=********",
        "DB_PASSWORD=xxxxxxxx",
        "DB_PASSWORD=your-password-here",
        r#"password: <%= ENV["DB_PASSWORD"] %>"#,
        "password: {{ db_password }}",
        "ADMIN_PASSWORD=password123",
        "DB_PASSWORD=$DB_PASSWORD",
        "update(password: @password)",
    ] {
        assert_eq!(scrubber.scrub(input).text, input, "{input}");
    }
}

/// The fiction-range numbers from the issue, one per supported shape.
const PHONE_SHAPES: [&str; 7] = [
    "+6281234567890",
    "+62 812-3456-7890",
    "+1 415 555 0123",
    "+44 20 7946 0958",
    "(415) 555-0123",
    "415-555-0123",
    "0812-3456-7890",
];

#[test]
fn pii_on_redacts_a_phone_number_in_every_supported_shape_and_placement() {
    let scrubber = pii_scrubber();
    for phone in PHONE_SHAPES.into_iter().chain(["0812 3456 7890"]) {
        let marker = value_only_marker("phone", phone);
        let line = format!("Call {phone} today");
        assert_eq!(scrubber.scrub(phone).text, marker, "{phone}");
        assert_eq!(scrubber.scrub(&line).text, format!("Call {marker} today"));
    }
    let json = scrubber.scrub(r#"{"to": "+14155550123"}"#);
    assert_eq!(json.text, r#"{"to": "[REDACTED:phone ...0123]"}"#);
    // Only the number goes; the scheme tells the reader what was there.
    let link = scrubber.scrub("tel:+14155550123");
    assert_eq!(link.text, "tel:[REDACTED:phone ...0123]");
    // Column 0 only reads as a diff line when the text holds a hunk header.
    let contact = scrubber.scrub("Name: Budi\n+62 812-3456-7890\n");
    assert_eq!(contact.text, "Name: Budi\n[REDACTED:phone ...7890]\n");
}

#[test]
fn pii_on_redacts_an_email_wherever_tool_output_puts_it() {
    let scrubber = pii_scrubber();
    let address = fake_secrets::email();
    for placement in [
        format!("SUPPORT_CONTACT={address}"),
        format!(r#"{{"customer": {{"email": "{address}"}}}}"#),
        format!("12:00:01 INFO mail queued for {address}, retry in 5s"),
        format!("Write to [{address}](mailto:{address})."),
    ] {
        let result = scrubber.scrub(&placement);
        assert!(!result.text.contains(&address), "{}", result.text);
        assert!(
            result.counts_by_pattern.contains_key("email"),
            "{placement}"
        );
    }
}

#[test]
fn pii_is_off_by_default_so_contacts_pass_through_untouched() {
    let scrubber = default_scrubber();
    let address = fake_secrets::email();
    let others = [
        "0812 3456 7890",
        r#""to": "+14155550123""#,
        "tel:+14155550123",
    ];
    for input in PHONE_SHAPES
        .into_iter()
        .chain(others)
        .chain([address.as_str()])
    {
        assert_eq!(scrubber.scrub(input).text, input);
    }
}

#[test]
fn whitelist_turns_off_a_pii_row_by_name() {
    let cfg = Config {
        disabled_patterns: vec!["email".into()],
        ..pii_config()
    };
    let address = fake_secrets::email();
    let scrubber = Scrubber::new(&cfg, &EngineConfig::default()).unwrap();
    assert_eq!(scrubber.scrub(&address).text, address);
}

#[test]
fn an_own_address_in_allow_values_stays_visible() {
    let address = fake_secrets::email();
    let eng = EngineConfig {
        allow_values: vec![format!("^{}$", regex::escape(&address))],
        ..Default::default()
    };
    let scrubber = Scrubber::new(&pii_config(), &eng).unwrap();
    assert_eq!(scrubber.scrub(&address).text, address);
}

#[test]
fn hint_is_last_four_chars_not_bytes() {
    let result = default_scrubber().scrub("postgis://u:pw@host/dbéèêë");
    assert_eq!(result.text, "[REDACTED:credentialed_url ...éèêë]");
}

#[test]
fn whitelist_skips_a_pattern_by_name() {
    let cfg = Config {
        disabled_patterns: vec!["aws_access_key".into()],
        ..Default::default()
    };
    let key = fake_secrets::aws_access_key();
    let result = Scrubber::new(&cfg, &EngineConfig::default())
        .unwrap()
        .scrub(&key);
    assert_eq!(result.text, key);
}

#[test]
fn allow_skips_matches_containing_the_name_case_insensitively() {
    let cfg = Config {
        allowed_keys: vec!["aws_secret_access_key".into()],
        ..Default::default()
    };
    let input = format!("AWS_SECRET_ACCESS_KEY={}", fake_secrets::aws_secret_key());
    let result = Scrubber::new(&cfg, &EngineConfig::default())
        .unwrap()
        .scrub(&input);
    assert_eq!(result.text, input);
}

#[test]
fn a_placeholder_login_later_in_the_output_never_unredacts_a_key() {
    // A truncated dump has no closing quote, so the match must stop at the line end.
    let body = "Q7xK".repeat(16);
    let dump = format!(r#""private_key": "-----BEGIN PRIVATE KEY-----\n{body}"#);
    let url_line = "DATABASE_URL=postgres://user:pass@db.internal.corp/app";
    let result = default_scrubber().scrub(&format!("{dump}\n{url_line}\n"));
    assert!(!result.text.contains(&body), "{}", result.text);
    assert!(result.text.ends_with(&format!("\n{url_line}\n")));
}

#[test]
fn a_raw_newline_dump_under_the_key_loses_every_body_line_not_only_the_first() {
    let body_lines = ["Q7xK".repeat(16), "Zp3/".repeat(16), "mW8+".repeat(16)];
    let url_line = "DATABASE_URL=postgres://user:pass@db.internal.corp/app";
    let input = format!(
        "\"private_key\": \"-----BEGIN PRIVATE KEY-----\n{}\n{url_line}\n",
        body_lines.join("\n")
    );
    let result = default_scrubber().scrub(&input);
    for line in &body_lines {
        assert!(!result.text.contains(line.as_str()), "{}", result.text);
    }
    assert!(result.text.ends_with(&format!("\n{url_line}\n")));
}

#[test]
fn a_token_on_the_line_after_a_key_dump_keeps_its_own_marker() {
    let body_lines = ["Q7xK".repeat(16), "Zp3/".repeat(16)];
    let header = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
    let payload = "eyJzdWIiOiIxMjM0NTY3ODkwIn0";
    let signature = format!("{}xYz", "Ab3_".repeat(10));
    let url_line = "DATABASE_URL=postgres://user:pass@db.internal.corp/app";
    let input = format!(
        "\"private_key\": \"-----BEGIN PRIVATE KEY-----\n{}\n{header}.{payload}.{signature}\n{url_line}\n",
        body_lines.join("\n")
    );
    let result = default_scrubber().scrub(&input);
    for line in &body_lines {
        assert!(!result.text.contains(line.as_str()), "{}", result.text);
    }
    assert!(result.text.contains("[REDACTED:jwt"), "{}", result.text);
    for segment in [header, payload, signature.as_str()] {
        assert!(!result.text.contains(segment), "{}", result.text);
    }
    assert!(result.text.ends_with(&format!("\n{url_line}\n")));
}

#[test]
fn placeholder_database_urls_are_not_redacted() {
    let input = "postgres://user:password@db.example.com:5432/app";
    assert_eq!(default_scrubber().scrub(input).text, input);
}

#[test]
fn user_patterns_redact_and_user_allow_values_exempt() {
    let eng = EngineConfig {
        patterns: vec![crate::config::CustomPattern {
            name: "acme".into(),
            regex: r"acme_\w{12}".into(),
        }],
        allow_values: vec!["^acme_test".into()],
        ..Default::default()
    };
    let scrubber = Scrubber::new(&Config::default(), &eng).unwrap();
    assert_eq!(
        scrubber.scrub("acme_live1234abcd").text,
        "[REDACTED:acme ...abcd]"
    );
    assert_eq!(
        scrubber.scrub("acme_test1234abcd").text,
        "acme_test1234abcd"
    );
}

#[test]
fn bad_user_regex_is_an_error() {
    let eng = EngineConfig {
        patterns: vec![crate::config::CustomPattern {
            name: "bad".into(),
            regex: "(".into(),
        }],
        ..Default::default()
    };
    assert!(Scrubber::new(&Config::default(), &eng).is_err());
}

pub(super) fn scrubber_with_learned(entries: Vec<crate::config::LearnedSecret>) -> Scrubber {
    let cfg = Config {
        learned: entries,
        ..Default::default()
    };
    Scrubber::new(&cfg, &EngineConfig::default()).unwrap()
}

pub(super) fn scrubber_with_heuristic(heuristic: crate::config::HeuristicConfig) -> Scrubber {
    let cfg = Config {
        heuristic,
        ..Default::default()
    };
    Scrubber::new(&cfg, &EngineConfig::default()).unwrap()
}

pub(super) fn enabled_heuristic() -> crate::config::HeuristicConfig {
    crate::config::HeuristicConfig {
        enabled: true,
        ..Default::default()
    }
}

const RANDOM_ASSIGNMENT: &str = "FOO_CONF=Xy7aB3kQ9mZ2pL5nR8tW";

#[test]
fn heuristic_is_off_by_default() {
    assert_eq!(
        default_scrubber().scrub(RANDOM_ASSIGNMENT).text,
        RANDOM_ASSIGNMENT
    );
}

#[test]
fn heuristic_enabled_redacts_a_random_value_under_any_key() {
    let result = scrubber_with_heuristic(enabled_heuristic()).scrub(RANDOM_ASSIGNMENT);
    assert_eq!(result.text, "FOO_CONF= [REDACTED ...R8tW]");
    assert_eq!(result.counts_by_pattern.get("secret_value"), Some(&1));
}

#[test]
fn heuristic_thresholds_come_from_config() {
    let strict = crate::config::HeuristicConfig {
        min_length: 50,
        ..enabled_heuristic()
    };
    assert_eq!(
        scrubber_with_heuristic(strict)
            .scrub(RANDOM_ASSIGNMENT)
            .text,
        RANDOM_ASSIGNMENT
    );
    let short = "GADGET=aB3xK9pQ7mZ2";
    assert_eq!(
        scrubber_with_heuristic(enabled_heuristic())
            .scrub(short)
            .text,
        short
    );
    let loose = crate::config::HeuristicConfig {
        min_length: 10,
        ..enabled_heuristic()
    };
    assert!(scrubber_with_heuristic(loose).scrub(short).has_redactions());
    // Only an absent threshold takes its default; an explicit 0 is honored.
    let zero: crate::config::HeuristicConfig =
        serde_yaml::from_str("{enabled: true, min_length: 0}").unwrap();
    assert!(scrubber_with_heuristic(zero).scrub(short).has_redactions());
    // A lowercase-only value has one character class, so it passes only at 0.
    let one_class = "FOO_CONF=qwertyuiopasdfghjk";
    let zero: crate::config::HeuristicConfig =
        serde_yaml::from_str("{enabled: true, min_char_classes: 0}").unwrap();
    assert!(
        scrubber_with_heuristic(zero)
            .scrub(one_class)
            .has_redactions()
    );
    assert!(
        !scrubber_with_heuristic(enabled_heuristic())
            .scrub(one_class)
            .has_redactions()
    );
}

#[test]
fn clean_corpus_files_produce_no_false_positives() {
    let scrubber = default_scrubber();
    for (name, data) in clean_corpus() {
        let result = scrubber.scrub(&data);
        assert!(
            !result.has_redactions(),
            "false positive in {name}: {:?}",
            result.counts_by_pattern
        );
    }
}

#[test]
fn every_builtin_secret_planted_in_the_corpus_is_redacted() {
    let scrubber = pii_scrubber();
    for (name, data) in clean_corpus() {
        for case in builtin_pattern_cases() {
            // Mid-line, as in a log: a `+` at column 0 of a diff is an added line.
            let planted = format!("{data}\nfound {}\n", case.input);
            let result = scrubber.scrub(&planted);
            let pattern = case.name;
            assert!(result.has_redactions(), "{pattern} missed in {name}");
            assert!(
                !result.text.contains(&case.secret),
                "{pattern} leaked in {name}"
            );
        }
    }
}

/// Learned entries derived the way `init` derives them, from synthetic values:
/// one exact-only, one custom-prefix shape (all three classes, so the band is stable).
fn learned_corpus_scrubber() -> (Scrubber, String, String) {
    let exact = fake_secrets::alnum(24);
    let shaped = format!("acme_{}aZ9", fake_secrets::alnum(27));
    let entries = vec![
        crate::init::learn("DB_PASS", &exact).unwrap(),
        crate::init::learn("ACME_KEY", &shaped).unwrap(),
        crate::init::learn("STRIPE_KEY", &fake_secrets::stripe_key("sk_live_")).unwrap(),
        crate::init::learn("GH_TOKEN", &fake_secrets::github_token("ghp_")).unwrap(),
        crate::init::learn("SLACK_TOKEN", &fake_secrets::slack_token("xoxb")).unwrap(),
        crate::init::learn("HUBSPOT_KEY", &fake_secrets::hubspot_pat("na1")).unwrap(),
        crate::init::learn("AWS_KEY", &fake_secrets::aws_access_key()).unwrap(),
        crate::init::learn(
            "DATABASE_URL",
            &fake_secrets::database_url("postgres", "db.example.com"),
        )
        .unwrap(),
    ];
    assert!(entries[1].shape.is_some() && entries[0].shape.is_none());
    (scrubber_with_learned(entries), exact, shaped)
}

#[test]
fn corpus_precision_holds_with_learned_secrets_loaded() {
    let (scrubber, _, _) = learned_corpus_scrubber();
    for (name, data) in clean_corpus() {
        let result = scrubber.scrub(&data);
        assert!(
            !result.has_redactions(),
            "false positive in {name}: {:?}",
            result.counts_by_pattern
        );
    }
}

#[test]
fn corpus_precision_holds_with_pii_on() {
    let scrubber = pii_scrubber();
    for (name, data) in clean_corpus() {
        let result = scrubber.scrub(&data);
        assert!(
            !result.has_redactions(),
            "false positive in {name}: {:?}",
            result.counts_by_pattern
        );
    }
}

#[test]
fn learned_and_rotated_values_planted_in_the_corpus_are_redacted() {
    let (scrubber, exact, shaped) = learned_corpus_scrubber();
    // Rotated: same prefix, 3 characters longer than the sample.
    let rotated = format!("acme_{}", fake_secrets::alnum(33));
    for (name, data) in clean_corpus() {
        let planted = format!("{data}\nDB_PASS={exact}\nkey: {shaped}\nnew {rotated}\n");
        let result = scrubber.scrub(&planted);
        assert_eq!(result.counts_by_pattern.get("db_pass"), Some(&1), "{name}");
        assert_eq!(result.counts_by_pattern.get("acme_key"), Some(&2), "{name}");
        for secret in [&exact, &shaped, &rotated] {
            assert!(!result.text.contains(secret.as_str()), "leaked in {name}");
        }
    }
}

pub(super) fn clean_corpus() -> Vec<(String, String)> {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/corpus/clean");
    let mut files: Vec<(String, String)> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "txt"))
        .map(|p| {
            (
                p.display().to_string(),
                std::fs::read_to_string(&p).unwrap(),
            )
        })
        .collect();
    files.sort();
    assert!(!files.is_empty(), "corpus not found");
    files
}
