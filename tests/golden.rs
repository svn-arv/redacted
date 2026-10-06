//! Raw-text output pinned to goldens recorded from the Go 0.7 binary. Fixtures are
//! templates (`{{alnum:40}}`) expanded with a fixed seed, so no secret is committed.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const ROOT: &str = env!("CARGO_MANIFEST_DIR");

fn fixtures() -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = fs::read_dir(Path::new(ROOT).join("tests/fixtures"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "txt"))
        .collect();
    files.sort();
    assert!(!files.is_empty());
    files
}

/// Expands `{{kind:n}}` placeholders with a PRNG seeded from the file name,
/// so every run sees the same bytes.
fn expand_placeholders(path: &Path) -> Vec<u8> {
    let name = path.file_name().unwrap().to_str().unwrap();
    // FNV-1a hash of the file name seeds a xorshift64 (13, 7, 17) generator.
    let mut state = name.bytes().fold(0xcbf2_9ce4_8422_2325_u64, |h, b| {
        (h ^ b as u64).wrapping_mul(0x100_0000_01b3)
    });
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let template = fs::read_to_string(path).unwrap();
    let mut out = String::new();
    let mut rest = template.as_str();
    while let Some(start) = rest.find("{{") {
        out.push_str(&rest[..start]);
        let end = start + rest[start..].find("}}").unwrap();
        let (kind, n) = rest[start + 2..end].split_once(':').unwrap();
        let charset: &[u8] = match kind {
            "alnum" => b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
            "hex" => b"0123456789abcdef",
            "upper" => b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
            "digits" => b"0123456789",
            "b64" => b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-",
            other => panic!("unknown placeholder kind {other}"),
        };
        for _ in 0..n.parse::<usize>().unwrap() {
            out.push(charset[(next() % charset.len() as u64) as usize] as char);
        }
        rest = &rest[end + 2..];
    }
    out.push_str(rest);
    out.into_bytes()
}

/// Runs `bin scrub` in raw-text mode with an empty HOME so no user config leaks in.
fn run_scrub_raw(bin: &Path, input: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let home = std::env::temp_dir().join(format!("redacted-diff-home-{}", std::process::id()));
    fs::create_dir_all(&home).unwrap();
    let mut child = Command::new(bin)
        .arg("scrub")
        .env("HOME", &home)
        .env("REDACTED_STATS_FILE", home.join("stats.jsonl"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(input).unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "{} failed: {:?}", bin.display(), out);
    (out.stdout, out.stderr)
}

#[test]
fn raw_mode_output_matches_the_go_0_7_goldens() {
    let rust = Path::new(env!("CARGO_BIN_EXE_redacted"));
    for path in fixtures() {
        let (stdout, stderr) = run_scrub_raw(rust, &expand_placeholders(&path));
        let want_out = fs::read(path.with_extension("golden")).unwrap();
        let want_err = fs::read(path.with_extension("stderr.golden")).unwrap();
        assert!(
            stdout == want_out,
            "stdout differs from golden for {}",
            path.display()
        );
        assert!(
            stderr == want_err,
            "stderr differs from golden for {}",
            path.display()
        );
    }
}
