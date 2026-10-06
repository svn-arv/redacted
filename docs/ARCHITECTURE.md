# Architecture

`redacted` reads tool output on stdin, removes secrets and writes the result on stdout. Code is referenced by file and function name, not line number.

## Data flow

```
stdin -> cli::scrub -> looks_like_hook_payload?
  yes (JSON object) -> hook::process_safely -> hook::process -> Scrubber::scrub
                    -> block envelope on stdout, or nothing
  no                -> cli::scrub_raw_text -> Scrubber::scrub
                    -> scrubbed text on stdout, count on stderr
```

1. `main` calls `cli::run`, which parses arguments with clap and dispatches the subcommand.
2. `cli::scrub` reads all of stdin, then loads config with `config::load` and `config::load_engine` and builds a `Scrubber`.
3. `looks_like_hook_payload` picks the mode:
   - Hook mode: stdin, after leading space, tab, CR or LF, starts with `{` and parses as JSON (or only fails the JSON depth limit).
   - Raw-text mode: anything else.

| | Hook mode | Raw-text mode |
| --- | --- | --- |
| Project config | from the payload's `cwd` | none (global files only) |
| `ignore_internal_tools` | honored | not applied |
| Output on a hit | block envelope (JSON) | scrubbed text, `[redacted] N secret(s) scrubbed` on stderr |
| Output with no hit | nothing | the input, unchanged for UTF-8 input |
| Scrubber fails to build | withheld envelope, exit 0 | error on stderr, exit 1 |
| Stats and pre-v2 notice | yes | no |

## Module map

| File | Contents |
| --- | --- |
| `src/main.rs` | Module list and `fn main() -> ExitCode`. |
| `src/cli.rs` | clap commands, `scrub` (mode choice, stats, pre-v2 notice), `show_stats`, the one place an `Err` becomes exit 1. |
| `src/config.rs` | `Config`, `Learned`, `Heuristic`, `EngineConfig`; global and project loading and merging; `vendor_only`. |
| `src/settings.rs` | Claude Code `settings.json`: read, `install_hook`, `remove_hook`, find our entry. |
| `src/init.rs` | `redacted init` (env file pick, `parse_dotenv`, `learn`, `derive_shape`, `merge_config`, hook install) and `uninstall`. |
| `src/verify.rs` | `redacted verify`: one `Check` per line, exit 1 on any FAIL. |
| `src/scrub.rs` | `Scrubber`: builds every tier, runs vendor patterns and the heuristic, writes markers. |
| `src/scrub/learned.rs` | Learned tier: shape and exact-hash matching, `sha256_hex`, `learned_hint`. |
| `src/scrub/skip.rs` | `skip_match`: allow lists and the guards that keep identifiers, code and URLs. |
| `src/scrub/go_regex.rs` | `go_regex`: rewrites Go RE2 syntax so patterns keep their 0.7 meaning under Rust `regex`. |
| `src/engine.yml` | Built-in patterns and `allow_values`, compiled in with `include_str!`. |
| `src/hook.rs` | PostToolUse protocol: payload parsing, block envelope, fail closed. |
| `src/stats.rs` | `stats.jsonl`: `record`, `aggregate`, `render`. |
| `src/fake.rs` | Test only (`#[cfg(test)]`): synthetic secret generators. |

Other paths:

| Path | Contents |
| --- | --- |
| `tests/cli.rs` | End-to-end tests of the binary. |
| `tests/golden.rs`, `tests/fixtures/` | Raw-mode output pinned to goldens. |
| `corpus/clean/` | Clean text for the precision and recall tests. |
| `scripts/migration-check.sh` | Fresh install, v1 upgrade and v2 config in a throwaway `HOME`. |

## Config loading

- `config::load` merges `~/.config/redacted/config.yaml` with `<cwd>/.redacted.yaml`.
- `config::load_engine` merges `~/.config/redacted/engine.yml` with `<cwd>/.redacted.engine.yml`.
- Merge rules: lists concatenate, `ignore_internal_tools` is ORed, a project `override: true` drops the global file.
- `version`, `learned` and `heuristic` always come from the global config, even under `override`.
- A missing, unreadable or malformed file is treated as absent.
- `config::home` returns `None` for an unset or empty `HOME`, so no path is built under the working directory.
- `EngineConfig` ignores the 0.7 keys `keywords`, `heuristic` and `value_safe_char` like any unknown key.

## Detection tiers

`Scrubber::scrub` runs the tiers in this order on one string. Each tier sees the markers of the one before.

1. Vendor signatures: every pattern from `src/engine.yml`, then user `patterns` from `engine.yml`.
   - A name in `whitelist` is skipped.
   - `prefilters` (case-sensitive) and `prefilters_fold` (against a lowercased copy) skip a regex when none of its literals appear.
   - `apply_pattern` replaces each match unless `skip_match` keeps it.
2. Learned secrets: `scrub_learned` in `src/scrub/learned.rs`.
3. Entropy heuristic: the `secret_value` pattern, built by `compile_heuristic` only when `heuristic.enabled` is true.

`redact` writes the marker:

| Match | Marker |
| --- | --- |
| value-only pattern | `[REDACTED:<name> ...<last 4>]` |
| keyed pattern (`includes_key: true`) or heuristic | `<key><sep> [REDACTED ...<last 4>]` |
| learned, value of 12+ characters | `[REDACTED:<name> ...<last 4>]` |
| learned, shorter value | `[REDACTED:<name>]` |

The hint counts characters, not bytes.

## Learned matching

`init::learn` turns a picked `.env` value into `Learned {name, sha256, len, shape}`:

- `name` is the key lowercased, `len` is the byte length. The value is never written.
- Values under 8 characters or with whitespace are refused.
- `derive_shape` returns a shape only when the value has a literal prefix of 3+ characters ending in the last `_` or `-` of its first 12 characters, and the rest holds only `[A-Za-z0-9_-]`.
- The shape is `\b<prefix>[<charset of the rest>]{n-4,n+4}\b`, lower bound at least 1.

`Scrubber::scrub_learned` then:

1. Runs every shape regex and replaces its matches.
2. Returns early when there are no exact hashes.
3. Collects candidate runs from the rewritten text, twice:
   - `safe_run`: runs of `value_safe_char` from `src/engine.yml`;
   - `word_run`: whitespace-delimited runs, for values holding `@`, `(` or quotes.
4. For each run, `exact_spans` tries the run start and every position after `=` or `:`.
5. `unwrap_candidates` gives four stages per start: as is; trailing `.:!?,;)}]` removed; one matching pair of `"` or `'` removed; trailing punctuation removed again.
6. A candidate is hashed only when its byte length is in `exact_lens`. The first hit ends that run (`continue 'runs`).

## Heuristic and skip guards

`heuristic_regex` matches `KEY=value`, `KEY: value` or `KEY => value`, with an optional quote around the key or value. The key must contain a letter. The value has at least `min_length` characters from `value_safe_char` and cannot start with `/`.

`skip_match` keeps a match unredacted when any of these holds:

| Guard | Applies to |
| --- | --- |
| text contains an `allow` name (`name_allowed`) | all regex tiers |
| value fits an `allow_values` regex (`value_allowed`) | all regex tiers |
| followed by `(` or `[` | keyed and heuristic |
| key equals value, ignoring case | keyed and heuristic |
| `looks_like_identifier`, or `looks_like_code_reference` without a random segment | keyed and heuristic |
| lenient separator (`:`, `=>`, ` = `) with `looks_like_lenient_identifier` | keyed and heuristic |
| 1 to 12 lowercase ASCII letters | keyed and heuristic |
| `skip_scored` | heuristic only |

`skip_scored` keeps the value when:

- the key names an id (`is_identifier_key`), or the match sits inside a URL (`inside_url`); or
- `secret_like` fails and `hex_under_key_suffix` does not apply.

`secret_like` checks the percent-decoded value against the `heuristic` thresholds:

| Threshold | Default |
| --- | --- |
| `min_length` | 16 |
| `max_length` | 128 |
| `min_char_classes` (of lowercase, uppercase, digit) | 3 |
| `min_entropy` (bits per character) | 3.5 |

- An absent threshold takes its default (`#[serde(default = "...")]`). An explicit 0 is used as written.
- `has_random_segment` uses the fixed constants `MIN_CHAR_CLASSES` and `MIN_ENTROPY`, whatever the config says.

## Hook protocol

`hook::process` reads these payload fields:

| Field | Use |
| --- | --- |
| `tool_name` | `"Bash"` takes `process_bash`; anything else `process_generic`. A non-string fails closed. |
| `tool_response` | The text to scrub. |
| `cwd` | Read by `cli::scrub` for project config. |
| `session_id` | Read by `cli::scrub` for the pre-v2 notice. |

- `process_bash` scrubs `tool_response.stdout` and `.stderr` separately.
- `process_generic` scrubs a string response directly. For structured responses it collects every string leaf and object key (`walk_strings`) and rewrites them in place (`scrub_json`).
- For a Read `{"type":"text","file":{"content":...}}` response, the `reason` shows the scrubbed file content.

A hit prints one line:

```json
{"decision":"block","reason":"[redacted] N secret(s) scrubbed from <command|tool_name> output.\n\n<text>","hookSpecificOutput":{"hookEventName":"PostToolUse","updatedToolOutput":"<scrubbed output>"}}
```

- `updatedToolOutput` replaces the tool result the model reads. For structured responses it is the scrubbed JSON with the same shape.
- `reason` may summarize: lines holding a marker, prefixed `- `.
- Key order and escaping match the Go 0.7 encoder: typed `Serialize` structs, U+2028 and U+2029 escaped, trailing newline.
- No hit: nothing is printed and Claude Code keeps the original output.
- Fail closed: a parse error, a wrong field type, a scrubber that failed to build, or a panic (`catch_unwind` in `process_safely`) prints `withheld()`, an envelope whose `reason` and `updatedToolOutput` carry no tool output.
- `ignore_internal_tools` skips only a `tool_name` that is a string other than `"Bash"`. A missing or bad name is still scrubbed or fails closed.
- Exit code: always 0 once stdin is read. Only a failed stdin read exits 1.
- Pre-v2 notice: when the global config exists with no `version`, the first hit in each `session_id` gets `[redacted] config is v1: run `redacted init` to learn your secrets.` above its `reason` (`hook::prepend_reason`). Seen sessions are stored in `notified.txt` next to the stats file.

## Stats file

- Path: `~/.config/redacted/stats.jsonl`, or `REDACTED_STATS_FILE`.
- `cli::record` calls `stats::record` after each hook run with at least one hit.
- One JSON line per run: `{"t":"<RFC 3339 UTC>","tool":"<tool_name>","by":{"<pattern>":<count>}}`. Created with mode 0600.
- Every write error is ignored, so stats never break the hook.
- `stats::aggregate` skips malformed lines. `stats::render` sorts by count, then name.

## Testing

| Layer | Where | What it pins |
| --- | --- | --- |
| Unit | `#[cfg(test)] mod tests` in each file | one row per built-in pattern (`builtin_rows`), learned matching, shape derivation, config merge, settings round trip, hook envelope bytes, fail closed |
| CLI | `tests/cli.rs` | the binary end to end: raw mode, hook mode, stats, verify, init without a terminal, uninstall, pre-v2 notice, empty `HOME` |
| Golden | `tests/golden.rs`, `tests/fixtures/` | raw-mode stdout and stderr byte for byte against goldens recorded from the Go 0.7 binary |
| Corpus | `corpus/clean/*.txt`, tests in `src/scrub.rs` | precision: no redaction in clean files; recall: every `builtin_rows` secret and learned secret is caught when planted in each file |
| Migration | `scripts/migration-check.sh` | fresh install, v1 upgrade (notice once per session), v2 config |

- `src/fake.rs` builds synthetic secrets at test time, so no real-looking secret is committed.
- Golden fixtures are templates (`{{alnum:40}}`) expanded with a PRNG seeded from the file name.
- `every_engine_pattern_has_a_row` fails when a pattern in `src/engine.yml` has no `builtin_rows` entry.

## Reading order

For someone learning Rust from this repo, read in this order. Each line names an idiom the file shows.

1. `src/main.rs`: `mod` declarations, `#[cfg(test)]` on a module, `fn main() -> ExitCode`.
2. `src/cli.rs`: clap derive (`Parser`, `Subcommand`); commands return `Result<(), String>` and `run` maps it to `ExitCode`; `?` with `map_err`; `matches!` with an `if` guard.
3. `src/config.rs`: `#[serde(default)]` and per-field `#[serde(default = "fn")]`; a hand-written `impl Default`; a generic `fn read<T: DeserializeOwned>`; `match` on a tuple with a guard; struct update syntax (`..cfg`).
4. `src/settings.rs`: `serde_json::Value` instead of a typed struct, so unknown keys survive a rewrite; `let ... else`; `Value::take`; a match guard on `io::ErrorKind`.
5. `src/stats.rs`: importing a trait (`OpenOptionsExt`) to get its methods, behind `#[cfg(unix)]`; `BTreeMap` for sorted keys; ignoring errors with `let _ =`.
6. `src/verify.rs`: a `Copy` enum with a method; a parameter of type `impl Into<String>`.
7. `src/init.rs`: `Result<Learned, &'static str>`; `char_indices` to slice UTF-8 safely; `split_once` and `strip_prefix`; `serde_yaml::Value` to edit a file and keep unknown keys.
8. `src/scrub.rs`: child modules (`mod learned;`) and a `pub use` re-export; `include_str!`; `collect::<Result<_, _>>()`; `Option::get_or_insert_with`; `entry().or_default()`.
9. `src/scrub/go_regex.rs`: a `Peekable` char iterator driven by `while let`; returning `Option<&'static str>`.
10. `src/scrub/learned.rs`: an `impl Scrubber` block in a child module, with `pub(super)` methods; a labeled `continue 'runs`; slice patterns with bindings (`[q @ (b'"' | b'\''), .., l]`).
11. `src/scrub/skip.rs`: a child module using its parent's private items (`use super::{Pattern, Scrubber}`); `matches!` on bytes; destructuring assignment (`(lower, letter) = (true, true)`).
12. `src/hook.rs`: `panic::catch_unwind` with `AssertUnwindSafe`; `#[derive(Serialize)]` structs with a lifetime `'a` and `#[serde(rename)]`; `&dyn Fn`; a `type` alias.
13. `src/fake.rs`: `thread_local!` with a `Cell<u64>` for a tiny PRNG.
14. `tests/cli.rs`: integration tests with `env!("CARGO_BIN_EXE_redacted")` and `Command` with piped stdin.
15. `tests/golden.rs`: a `move` closure that owns mutable PRNG state.
