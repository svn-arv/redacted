//! Synthetic secrets generated at runtime, ported from internal/testutil/fake.go.
//! Values match engine.yml but never sit in source, so push protection stays quiet.

use std::cell::Cell;
use std::time::{SystemTime, UNIX_EPOCH};

const ALNUM: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const UPPER_ALNUM: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
const BASE64URL: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";

thread_local! {
    static STATE: Cell<u64> = Cell::new(
        SystemTime::now().duration_since(UNIX_EPOCH).map_or(1, |d| d.as_nanos() as u64) | 1,
    );
}

// xorshift64*: enough randomness for fixtures, no crate needed.
fn next() -> u64 {
    STATE.with(|s| {
        let mut x = s.get();
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        s.set(x);
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    })
}

fn from_charset(charset: &str, n: usize) -> String {
    let b = charset.as_bytes();
    (0..n)
        .map(|_| b[(next() % b.len() as u64) as usize] as char)
        .collect()
}

pub fn alnum(n: usize) -> String {
    from_charset(ALNUM, n)
}

pub fn hex(n: usize) -> String {
    from_charset("0123456789abcdef", n)
}

pub fn digits(n: usize) -> String {
    from_charset("0123456789", n)
}

pub fn upper_alnum(n: usize) -> String {
    from_charset(UPPER_ALNUM, n)
}

pub fn base64url(n: usize) -> String {
    from_charset(BASE64URL, n)
}

pub fn hint(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    chars[chars.len().saturating_sub(4)..].iter().collect()
}

pub fn aws_access_key() -> String {
    format!("AKIA{}", upper_alnum(16))
}

pub fn aws_secret_key() -> String {
    format!("{}/{}", alnum(37), alnum(2))
}

pub fn github_token(prefix: &str) -> String {
    format!("{prefix}{}", alnum(40))
}

pub fn github_fine_grained() -> String {
    format!("github_pat_{}", alnum(26))
}

pub fn stripe_key(prefix: &str) -> String {
    format!("{prefix}{}", alnum(24))
}

pub fn twilio_sid(prefix: &str) -> String {
    format!("{prefix}{}", hex(32))
}

pub fn digitalocean_token() -> String {
    format!("dop_v1_{}", hex(64))
}

pub fn digitalocean_spaces_value() -> String {
    format!("{}{}", upper_alnum(4), alnum(16))
}

pub fn sentry_dsn() -> String {
    format!(
        "https://{}@o{}.ingest.sentry.io/{}",
        hex(32),
        digits(6),
        digits(7)
    )
}

pub fn slack_token(prefix: &str) -> String {
    format!("{prefix}-{}-{}", digits(12), digits(12))
}

pub fn sendgrid_key() -> String {
    format!("SG.{}.{}", alnum(22), alnum(43))
}

pub fn hubspot_pat(region: &str) -> String {
    format!(
        "pat-{region}-{}-{}-{}-{}-{}",
        hex(8),
        hex(4),
        hex(4),
        hex(4),
        hex(12)
    )
}

pub fn jwt() -> String {
    format!(
        "eyJ{}.eyJ{}.{}",
        base64url(33),
        base64url(25),
        base64url(43)
    )
}

pub fn database_url(scheme: &str, host: &str) -> String {
    format!("{scheme}://user:{}@{host}:5432/mydb", alnum(12))
}

pub fn private_key(kind: &str) -> String {
    format!(
        "-----BEGIN {kind}PRIVATE KEY-----\n{}\n-----END {kind}PRIVATE KEY-----",
        alnum(14)
    )
}

pub fn private_key_truncated(kind: &str) -> String {
    format!(
        "-----BEGIN {kind}PRIVATE KEY-----\n{}\n{}",
        alnum(64),
        alnum(64)
    )
}

pub fn slack_webhook() -> String {
    format!(
        "https://hooks.slack.com/services/T{}/B{}/{}",
        upper_alnum(8),
        upper_alnum(8),
        alnum(24)
    )
}

/// The `"private_key": "-----BEGIN...` field of a GCP service-account JSON,
/// with the `\n` escapes a dump carries and no END marker.
pub fn gcp_private_key_field() -> String {
    format!(
        r#""private_key": "-----BEGIN PRIVATE KEY-----\n{}\n"#,
        alnum(96)
    )
}
