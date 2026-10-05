# Contributing

Thanks for helping improve `redacted`.

## Development

```bash
git clone https://github.com/svn-arv/redacted.git
cd redacted
cargo build
cargo test
```

`cargo clippy --all-targets -- -D warnings`, `cargo fmt --check` and
`sh scripts/migration-check.sh` should come back clean.

## Detection rules

Vendor patterns live in `src/engine.yml`. Add or tune rules there, not in Rust.
A new pattern needs:

- a synthetic generator in `src/fake.rs` (never commit a real key),
- a row in `builtin_rows` in `src/scrub.rs` (recall), and
- no regression in the clean-corpus precision tests (`corpus/clean/` stays clean).

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for how the engine fits together.

## Pull requests

- Branch off `main` (`feat/...`, `fix/...`, `chore/...`).
- Use [Conventional Commits](https://www.conventionalcommits.org/).
- CI (fmt, clippy, test, migration check) must pass.
- A maintainer reviews and merges; external PRs need a maintainer approval.
