//! Detection tiers: vendor signatures (engine.yml `patterns:` plus user patterns),
//! learned secrets, and the opt-in entropy heuristic.

// Child modules add `impl Scrubber` blocks and read its private fields; what this
// file calls from them (and the shared test helpers) is marked `pub(super)`.
mod go_regex;
mod guards;
mod learned;

use std::collections::{BTreeMap, HashMap, HashSet};

use regex::Regex;
use serde::Deserialize;

use crate::config::{Config, CustomPattern, EngineConfig, HeuristicConfig, PiiConfig};
use go_regex::go_to_rust_regex;
// Re-exported so callers write `scrub::sha256_hex`, not `scrub::learned::sha256_hex`.
pub use guards::percent_decode;
pub use learned::{learned_value_hint, sha256_hex};

const BUILTIN_ENGINE_YML: &str = include_str!("engine.yml");

#[derive(Deserialize)]
struct BuiltinPatternYaml {
    name: String,
    regex: String,
    #[serde(default)]
    includes_key: bool,
    #[serde(default)]
    prefilters: Vec<String>,
    #[serde(default)]
    prefilters_ignore_case: Vec<String>,
    #[serde(default)]
    opt_in: bool,
}

#[derive(Deserialize)]
struct BuiltinEngine {
    value_safe_char: String,
    allow_values: Vec<String>,
    patterns: Vec<BuiltinPatternYaml>,
}

struct Pattern {
    name: String,
    regex: Regex,
    includes_key: bool,
    prefilters: Vec<String>,
    prefilters_ignore_case: Vec<String>,
    is_heuristic: bool,
}

impl Pattern {
    /// No key handling and no prefilters, as user patterns from engine.yml run.
    fn unkeyed(name: String, regex: Regex) -> Self {
        Pattern {
            name,
            regex,
            includes_key: false,
            prefilters: Vec::new(),
            prefilters_ignore_case: Vec::new(),
            is_heuristic: false,
        }
    }
}

/// Every tier compiled once from the config, then reused for each scrub.
pub struct Scrubber {
    patterns: Vec<Pattern>,
    disabled_patterns: HashSet<String>,
    /// A match containing one of these key names is left alone.
    allowed_keys_upper: Vec<String>,
    /// A match whose value fits one of these is left alone.
    allow_values: Vec<Regex>,
    /// Learned name and the regex derived from its sample.
    learned_shapes: Vec<(String, Regex)>,
    learned_name_by_hash: HashMap<String, String>,
    /// Only candidates of these byte lengths are hashed.
    learned_byte_lengths: HashSet<usize>,
    /// Runs of the characters a value can hold (engine.yml `value_safe_char`).
    value_char_run: Regex,
    /// For values holding `@`, `(` or quotes, which split a `value_char_run`.
    non_whitespace_run: Regex,
    heuristic_pattern: Option<Pattern>,
    heuristic_thresholds: HeuristicConfig,
}

/// The rewritten text plus how many redactions each pattern made.
#[derive(Debug, Default)]
pub struct ScrubResult {
    pub text: String,
    pub count: usize,
    pub counts_by_pattern: BTreeMap<String, usize>,
}

impl ScrubResult {
    pub fn has_redactions(&self) -> bool {
        self.count > 0
    }

    /// Zero adds nothing, so a pattern that never matched stays out of
    /// `counts_by_pattern`.
    fn add_redactions(&mut self, name: &str, redactions: usize) {
        if redactions == 0 {
            return;
        }
        // entry() finds or inserts the key; or_default() starts a new count at 0.
        *self.counts_by_pattern.entry(name.to_string()).or_default() += redactions;
        self.count += redactions;
    }
}

fn compile_go_regex(expr: &str) -> Result<Regex, String> {
    Regex::new(&go_to_rust_regex(expr)).map_err(|e| format!("invalid regex {expr:?}: {e}"))
}

/// The engine.yml patterns followed by the user's, each compiled from Go syntax.
fn compile_vendor_patterns(
    builtin: Vec<BuiltinPatternYaml>,
    user: &[CustomPattern],
    pii: &PiiConfig,
) -> Result<Vec<Pattern>, String> {
    let mut patterns = Vec::new();
    for pattern in builtin {
        // An opt_in row is PII: it runs only when its toggle in `pii` is on.
        let is_toggled_on = match pattern.name.as_str() {
            "email" => pii.email,
            "phone" => pii.phone,
            _ => false,
        };
        if pattern.opt_in && !is_toggled_on {
            continue;
        }
        patterns.push(Pattern {
            regex: compile_go_regex(&pattern.regex)?,
            name: pattern.name,
            includes_key: pattern.includes_key,
            prefilters: pattern.prefilters,
            prefilters_ignore_case: pattern.prefilters_ignore_case,
            is_heuristic: false,
        });
    }
    for pattern in user {
        patterns.push(Pattern::unkeyed(
            pattern.name.clone(),
            compile_go_regex(&pattern.regex)?,
        ));
    }
    Ok(patterns)
}

impl Scrubber {
    pub fn new(config: &Config, user_engine: &EngineConfig) -> Result<Self, String> {
        let builtin: BuiltinEngine =
            serde_yaml::from_str(BUILTIN_ENGINE_YML).map_err(|e| format!("engine.yml: {e}"))?;
        let patterns =
            compile_vendor_patterns(builtin.patterns, &user_engine.patterns, &config.pii)?;
        let allow_values = builtin
            .allow_values
            .iter()
            .chain(&user_engine.allow_values)
            .map(|expr| compile_go_regex(expr))
            .collect::<Result<_, _>>()?;
        let heuristic_pattern = compile_heuristic(&config.heuristic, &builtin.value_safe_char)?;
        let mut learned_shapes = Vec::new();
        let mut learned_name_by_hash = HashMap::new();
        let mut learned_byte_lengths = HashSet::new();
        for learned in &config.learned {
            learned_name_by_hash.insert(learned.sha256.clone(), learned.name.clone());
            learned_byte_lengths.insert(learned.byte_len);
            if let Some(shape) = &learned.shape {
                learned_shapes.push((learned.name.clone(), compile_go_regex(shape)?));
            }
        }
        Ok(Scrubber {
            patterns,
            disabled_patterns: config.disabled_patterns.iter().cloned().collect(),
            allowed_keys_upper: config
                .allowed_keys
                .iter()
                .map(|a| a.to_uppercase())
                .collect(),
            allow_values,
            learned_shapes,
            learned_name_by_hash,
            learned_byte_lengths,
            value_char_run: compile_go_regex(&format!("{}+", builtin.value_safe_char))?,
            non_whitespace_run: compile_go_regex(r"[^ \t\n\x0C\r]+")?,
            heuristic_pattern,
            heuristic_thresholds: config.heuristic.clone(),
        })
    }

    pub fn scrub(&self, text: &str) -> ScrubResult {
        let mut result = ScrubResult {
            text: text.to_string(),
            ..Default::default()
        };
        // Lowered once, like Go 0.7: redaction markers never add a prefilter literal.
        let mut lowercase_text: Option<String> = None;
        for pattern in &self.patterns {
            if self.disabled_patterns.contains(&pattern.name) {
                continue;
            }
            if !pattern.prefilters.is_empty()
                && !pattern
                    .prefilters
                    .iter()
                    .any(|literal| result.text.contains(literal.as_str()))
            {
                continue;
            }
            if !pattern.prefilters_ignore_case.is_empty() {
                // Computes the lowercase copy on first use only, then reuses it.
                let lowercase = lowercase_text.get_or_insert_with(|| result.text.to_lowercase());
                if !pattern
                    .prefilters_ignore_case
                    .iter()
                    .any(|literal| lowercase.contains(literal.as_str()))
                {
                    continue;
                }
            }
            let redactions = self.redact_matches(pattern, &mut result.text);
            result.add_redactions(&pattern.name, redactions);
        }
        self.scrub_learned(&mut result);
        if let Some(pattern) = &self.heuristic_pattern {
            let redactions = self.redact_matches(pattern, &mut result.text);
            result.add_redactions(&pattern.name, redactions);
        }
        result
    }

    /// Returns the redaction count; `text` is rewritten only when it is above zero.
    fn redact_matches(&self, pattern: &Pattern, text: &mut String) -> usize {
        let mut out = String::with_capacity(text.len());
        let (mut copied_until, mut count) = (0, 0);
        for found in pattern.regex.find_iter(text) {
            out.push_str(&text[copied_until..found.start()]);
            copied_until = found.end();
            if self.should_skip_match(pattern, found.as_str(), text, found.end()) {
                out.push_str(found.as_str());
                continue;
            }
            out.push_str(&marker_for(
                &pattern.name,
                found.as_str(),
                pattern.includes_key,
            ));
            count += 1;
        }
        if count > 0 {
            out.push_str(&text[copied_until..]);
            *text = out;
        }
        count
    }
}

fn marker_for(name: &str, matched: &str, includes_key: bool) -> String {
    if includes_key && let Some(separator_at) = matched.find(['=', ':']) {
        let separator = &matched[separator_at..=separator_at];
        let value = matched[separator_at + 1..].trim_start_matches([' ', '\t']);
        let key = &matched[..separator_at];
        return format!("{key}{separator} [REDACTED ...{}]", last_chars(value, 4));
    }
    format!("[REDACTED:{name} ...{}]", last_chars(matched, 4))
}

fn last_chars(text: &str, count: usize) -> &str {
    match text.char_indices().rev().nth(count - 1) {
        Some((start, _)) => &text[start..],
        None => text,
    }
}

/// The opt-in entropy pattern, or None while the heuristic is off.
fn compile_heuristic(
    heuristic: &HeuristicConfig,
    safe_char: &str,
) -> Result<Option<Pattern>, String> {
    if !heuristic.enabled {
        return Ok(None);
    }
    let regex = compile_go_regex(&heuristic_regex(heuristic.min_length, safe_char))?;
    Ok(Some(Pattern {
        includes_key: true,
        is_heuristic: true,
        ..Pattern::unkeyed("secret_value".into(), regex)
    }))
}

/// KEY=value with a value of min_length+ chars that can't start with `/`, so a
/// URL scheme isn't read as one.
fn heuristic_regex(min_length: usize, safe_char: &str) -> String {
    let first_char_class = match safe_char.strip_suffix(']') {
        Some(class) if safe_char.starts_with("[^") => format!("{class}/]"),
        _ => safe_char.to_string(),
    };
    format!(
        r#"(?i)\b[A-Za-z0-9_\-]*[A-Za-z][A-Za-z0-9_\-]*["']?[ \t]*(?:=>?|:)[ \t]*["']?{first_char_class}{safe_char}{{{},}}"#,
        min_length.max(1) - 1
    )
}

#[cfg(test)]
mod tests {
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
    struct PatternCase {
        name: &'static str,
        input: String,
        expected: String,
        secret: String,
    }

    fn builtin_pattern_cases() -> Vec<PatternCase> {
        let mut cases = Vec::new();
        let value_only_secrets = generated_secrets().into_iter().chain(prefixed_secrets());
        for (name, secret) in value_only_secrets {
            cases.push(PatternCase {
                name,
                input: secret.clone(),
                expected: value_only_marker(name, &secret),
                secret,
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

    fn clean_corpus() -> Vec<(String, String)> {
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
}
