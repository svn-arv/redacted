# Architecture

`redacted` is a hook that scrubs secrets out of AI-tool output before the model
sees them. This doc explains how it fits together. Code references are by file
and function name so they stay accurate as line numbers move.

## Data flow

```
tool output -> Claude Code PostToolUse hook -> `redacted scrub` (stdin)
            -> hook::process_safely -> hook::process -> Scrubber::scrub
            -> block JSON with updatedToolOutput (redacted) | nothing (pass-through)
```

1. `src/main.rs` calls `cli::run`, which dispatches the subcommand.
2. `cli::scrub` reads stdin, loads both config files, and builds a `Scrubber`.
   `looks_like_hook_payload` picks hook mode (a JSON object) or raw-text mode
   (anything else, scrubbed as text with a count on stderr; for manual testing).
3. `hook::process_safely` (`src/hook.rs`) runs `hook::process`, which parses the
   payload and calls `Scrubber::scrub` on the tool output.
4. A hit writes the block envelope; no hit writes nothing and the original
   output passes through.

## Config

| File | Purpose | Fields | Loaded by |
| --- | --- | --- | --- |
| `engine.yml` / `.redacted.engine.yml` | Extra vendor patterns and allow rows | `patterns`, `allow_values`, `override` | built-in `src/engine.yml` + `config::load_engine` |
| `config.yaml` / `.redacted.yaml` | Policy, learned secrets, heuristic | `version`, `learned`, `heuristic`, `whitelist`, `allow`, `ignore_internal_tools`, `override` | `config::load` |

- The built-in `src/engine.yml` is compiled in with `include_str!` and parsed by
  `Scrubber::new`. A user `engine.yml` adds patterns and allow rows at runtime.
  0.7 keys (`keywords`, `heuristic`, `value_safe_char`) still parse and are ignored.
- A project file merges list fields over the global one; `override: true` in a
  project file drops the global file.
- Config v2 is `version: 2` plus `learned:` and `heuristic:`. Both are read from
  the global `~/.config/redacted/config.yaml` only, even under a project
  `override`: a committed project file must not carry hashes. `verify` warns when
  a project file has `learned` entries.
- A global config without `version` is a 0.7 install: vendor tier only, and the
  hook prepends a one-line "run `redacted init`" notice to the reason, once per
  `session_id` (stamped in `notified.txt` beside the stats file).

## Detection tiers

`Scrubber::scrub` runs the tiers in order on the same text. Each tier sees the
previous tier's markers, so a redacted span is never matched again.

1. **Vendor signatures**: one regex per provider in `src/engine.yml` (`AKIA...`,
   `ghp_...`, `sk_live_...`, JWTs, `database_url`, `credentialed_url`) plus user
   patterns. Literal `prefilters` skip a regex when its prefix is absent. Go RE2
   syntax is translated by `go_regex` so the patterns keep their 0.7 meaning.
2. **Learned secrets** (`scrub_learned`), from `config.yaml` `learned:`.
3. **Entropy heuristic** (`secret_value`), only with `heuristic.enabled: true`.

## Learned matching

`init` (`src/init.rs`) parses a `.env`, and `learn` turns each picked value into
`{name, sha256, len, shape}`; the value itself is never written. Values under 8
characters or with whitespace are refused. `derive_shape` emits a shape only
when the value has a literal prefix of 3+ characters ending in `_` or `-` within
its first 12 characters: prefix + the rest's charset + a length band of ±4.

`scrub_learned` matches in this order:

1. Each shape regex, so a rotated key with the same prefix is caught.
2. Exact hashes over candidate runs: runs of safe token characters, then (on the
   rewritten text) whitespace-delimited runs, which catch values holding `@`,
   `(` or quotes.
3. Per run, `exact_spans` tries the run and every suffix after `=` or `:`, and
   `unwrap_candidates` peels each one: trailing `.:!?,;)}]`, then one matching
   pair of `"` or `'`, then trailing punctuation again. Every stage is a
   candidate, so `"password":"value",` and `KEY="value(x)"` both match.
4. A candidate is hashed only when its byte length equals some learned `len`.

A hit becomes `[REDACTED:name ...hint]`; the 4-character hint is left out for
values under 12 characters, where it would give away a third or more.

## The heuristic

`heuristic_regex` finds `KEY=value` / `key: value` candidates; `secret_like`
keeps a value only when all hold (thresholds from `config.yaml` `heuristic:`,
zero means the default):

- length within `min_length`..`max_length` (16..128),
- at least `min_char_classes` of {lowercase, uppercase, digit} (3). UUIDs and git
  SHAs are single-case, so they pass through.
- Shannon entropy at least `min_entropy` bits per character (3.5).

`skip_match` drops a keyed match that is allow-listed, followed by `(` or `[`,
an identifier or code reference, a URL, or under an identifier key such as `id`.

## Hook protocol

`hook::process` reads `tool_name` and `tool_response`. `process_bash` scrubs
stdout and stderr separately; `process_generic` handles every other tool by
scrubbing all string leaves and object keys (`walk_strings`, `scrub_json`).

A hit writes:

```json
{"decision":"block","reason":"[redacted] N secret(s) scrubbed from ... output.\n\n<redacted text>",
 "hookSpecificOutput":{"hookEventName":"PostToolUse","updatedToolOutput":"<redacted output>"}}
```

`updatedToolOutput` replaces the tool result the model reads; for structured
responses it is the scrubbed JSON, while `reason` may summarize.

`hook::process_safely` is the safety boundary: any error or panic returns
`withheld()`, a block envelope that carries no output at all. A user regex that
fails to compile also withholds. PostToolUse is fail-open by nature, so the
scrubber fails closed. `ignore_internal_tools` skips only a well-formed non-Bash
`tool_name`; a missing or bad one still goes through and fails closed.

## Stats

`hook::process` passes per-pattern counts to `cli::record`, which calls
`stats::record` to append `{t, tool, by}` as one JSONL line to
`~/.config/redacted/stats.jsonl` (`REDACTED_STATS_FILE` overrides). Errors are
swallowed so stats never break the hook. `redacted stats` prints totals and
per-pattern counts (`stats::aggregate`, `stats::render`). Only pattern names and
counts are stored, never values. Raw-text mode records nothing.

## Testing

- `src/fake.rs` generates synthetic secrets at runtime, so no real-looking
  secret is ever committed (which would trip push protection).
- Unit tests sit beside the code: one row per vendor pattern, learned matching,
  shape derivation, config merge, hook envelope and fail-closed cases.
- The clean corpus (`corpus/clean/*.txt`) is the accuracy benchmark: precision
  fails on any redaction of clean input, recall fails on any missed synthetic
  secret, both with and without learned entries loaded.
- `tests/cli.rs` runs the binary end to end (raw mode, hook mode, stats,
  verify, init without a terminal, uninstall, the 0.7 notice).
- `tests/golden.rs` pins raw-mode output to goldens recorded from the Go 0.7
  binary on seeded fixture templates in `tests/fixtures/`.
- `scripts/migration-check.sh` checks a fresh install, a 0.7 upgrade and a v2
  config in a throwaway HOME.

## File map

```
src/
  main.rs                        entry point
  cli.rs                         commands: scrub, verify, stats, init, uninstall
  init.rs                        `init` (learn + install hook), `uninstall`
  hook.rs                        hook protocol, fail-closed wrapper
  scrub.rs                       Scrubber: vendor, learned and heuristic tiers
  engine.yml                     built-in vendor patterns (compiled in)
  config.rs                      config.yaml and engine.yml loading
  stats.rs                       redaction stats (record + aggregate)
  fake.rs                        synthetic secret generators for tests
corpus/clean/                    clean inputs for precision tests
tests/
  cli.rs                         end-to-end binary tests
  golden.rs                      raw-mode golden test
  fixtures/                      golden fixture templates and outputs
scripts/migration-check.sh       install and upgrade scenarios
```
