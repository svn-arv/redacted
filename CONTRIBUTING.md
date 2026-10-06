# Contributing

## Development

```bash
git clone https://github.com/svn-arv/redacted.git
cd redacted
cargo build
cargo test
```

CI runs these on Linux and macOS. All must pass:

| Command | Checks |
| --- | --- |
| `cargo fmt --check` | formatting |
| `cargo clippy --all-targets -- -D warnings` | lints, warnings are errors |
| `cargo test` | unit, CLI, golden and corpus tests |
| `sh scripts/migration-check.sh` | fresh install, v1 upgrade, v2 config |

- A behavior change starts with a test that fails for the right reason. Then change the code until it passes.
- Never commit a real or real-looking secret. Build test secrets at runtime with `src/fake_secrets.rs`, or with a `{{kind:n}}` placeholder in a golden fixture.

How the code fits together: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Adding or changing a detection rule

Built-in patterns live in `src/engine.yml`, not in Rust.

1. Add or edit the row in `src/engine.yml`:
   - `name`, `regex` (Go RE2 syntax, translated by `src/scrub/go_regex.rs`);
   - `prefilters` or `prefilters_ignore_case`: literals that must appear before the regex runs;
   - `includes_key: true` when the match includes the key, so the output keeps `KEY=`.
   - Order matters: specific patterns before catch-alls.
2. Add a generator to `src/fake_secrets.rs` when the secret needs one (`fake_secrets` is test-only).
3. Add a case to `builtin_pattern_cases` in `src/scrub.rs`. `every_builtin_pattern_has_a_test_case` fails until you do. The case gives the input, the exact expected output and the secret that must not survive.
4. Run `cargo test`:
   - recall: the new secret is caught when planted in every `corpus/clean/*.txt` file;
   - precision: no clean corpus file gets a redaction.
5. A false positive from real output becomes a new `corpus/clean/*.txt` file.
6. Golden fixtures (`tests/fixtures/*.txt` with `.golden` and `.stderr.golden`) pin raw-mode output recorded from the Go 0.7 binary.
   - There is no script to regenerate them.
   - A change that alters existing golden output breaks 0.7 parity on purpose or by mistake. Say which in the PR, and edit the golden by hand.

## Pull requests

- Branch off `main` (`feat/...`, `fix/...`, `chore/...`).
- Use [Conventional Commits](https://www.conventionalcommits.org/).
- Fill in `.github/pull_request_template.md`, including the linked issue.
- CI (fmt, clippy, test, migration check) must pass.
- A maintainer reviews and merges. External PRs need a maintainer approval.
