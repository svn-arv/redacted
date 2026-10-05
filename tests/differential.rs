//! Raw-text parity with the Go implementation. Fixtures are templates
//! (`{{alnum:40}}`) expanded with a fixed seed, so no secret is committed; the
//! goldens hold the Go binary's output and keep this test alive after Go is gone.
//! Regenerate goldens with: REDACTED_BLESS=1 cargo test --test differential

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
/// so every run (and both binaries) sees the same bytes.
fn expand(path: &Path) -> Vec<u8> {
    let name = path.file_name().unwrap().to_str().unwrap();
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
fn scrub(bin: &Path, input: &[u8]) -> (Vec<u8>, Vec<u8>) {
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

fn golden(path: &Path, ext: &str) -> PathBuf {
    path.with_extension(ext)
}

#[test]
fn raw_mode_matches_committed_goldens() {
    let rust = Path::new(env!("CARGO_BIN_EXE_redacted"));
    for path in fixtures() {
        let (stdout, stderr) = scrub(rust, &expand(&path));
        let want_out = fs::read(golden(&path, "golden")).unwrap();
        let want_err = fs::read(golden(&path, "stderr.golden")).unwrap();
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

#[test]
fn raw_mode_matches_the_go_binary() {
    if Command::new("go").arg("version").output().is_err() {
        println!("skipped: `go` is not on PATH, so only the committed goldens were checked");
        return;
    }
    let go_bin = Path::new(ROOT).join("target/redacted-go");
    let built = Command::new("go")
        .args(["build", "-o", go_bin.to_str().unwrap(), "."])
        .current_dir(ROOT)
        .status()
        .unwrap();
    assert!(built.success(), "go build failed");

    let rust = Path::new(env!("CARGO_BIN_EXE_redacted"));
    let bless = std::env::var_os("REDACTED_BLESS").is_some();
    for path in fixtures() {
        let input = expand(&path);
        let go = scrub(&go_bin, &input);
        if bless {
            fs::write(golden(&path, "golden"), &go.0).unwrap();
            fs::write(golden(&path, "stderr.golden"), &go.1).unwrap();
        }
        let rs = scrub(rust, &input);
        assert!(
            go.0 == rs.0,
            "stdout differs for {}\n go: {}\n rs: {}",
            path.display(),
            String::from_utf8_lossy(&go.0),
            String::from_utf8_lossy(&rs.0)
        );
        assert!(go.1 == rs.1, "stderr differs for {}", path.display());
    }
}
