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
| `cargo clippy --locked --all-targets -- -D warnings` | lints, warnings are errors |
| `cargo test --locked` | unit, CLI, and golden tests |
| `cargo package --locked --list` | files included in the CLI package |
| `sh scripts/migration-check.sh` | fresh install, v1 upgrade, v2 config |

The OpenCode plugin has a smoke test outside CI. It needs [Bun](https://bun.sh), which OpenCode runs on:

```bash
cargo build && bun plugins/opencode/smoke.mjs
```

- A behavior change starts with a test that fails for the right reason. Then change the code until it passes.
- Never commit a real or real-looking secret. Build test secrets at runtime with `redacted_core::fake_secrets`, or with a `{{kind:n}}` placeholder in a golden fixture.

How the code fits together: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Adding or changing a detection rule

Send detection changes to the shared engine repository, which owns the
rules, synthetic fixtures, clean corpus, and precision and recall tests.
The CLI's golden tests pin both raw output and stderr to the Go 0.7
fixtures. [Engine contributing guide](https://github.com/rmaw22/redacted-core/blob/main/CONTRIBUTING.md)

## Pull requests

- Branch off `main` (`feat/...`, `fix/...`, `chore/...`).
- Use [Conventional Commits](https://www.conventionalcommits.org/).
- Fill in `.github/pull_request_template.md`, including the linked issue.
- CI (fmt, clippy, test, migration check) must pass.
- A maintainer reviews and merges. External PRs need a maintainer approval.

## Releasing

Before releasing the split CLI, verify that the required
`redacted-core` version is available on crates.io. The development dependency
uses Git for source builds and its exact `version` for packaging. Once the
core version is published, switch both dependency entries to the registry
version, refresh `Cargo.lock`, and run `cargo package --locked` so all release
artifacts use the registry source.

Bump `version` in `Cargo.toml` to match the tag (it is what `--version` prints), then tag and push. The workflow checks the version and verifies the Cargo package before distribution. GoReleaser builds binaries for all platforms, creates the GitHub release and updates the Homebrew tap, then `cargo publish` pushes the crate to crates.io (needs the `CARGO_REGISTRY_TOKEN` secret).

```bash
git tag vX.Y.Z
git push origin vX.Y.Z
```
