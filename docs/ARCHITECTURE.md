# Architecture

`redacted` reads tool output on stdin, removes secrets and writes the result on stdout. The CLI handles commands, configuration I/O, hooks, streaming, statistics, integrations, and distribution. Detection rules, shared configuration types, and secret learning live in [`redacted-core`](https://github.com/rmaw22/redacted-core/blob/main/docs/ARCHITECTURE.md).

## Data flow

```
stdin -> cli::run_scrub -> looks_like_hook_payload?
  yes (JSON object) -> hook::scrub_payload_or_withhold -> hook::scrub_payload -> Scrubber::scrub
                    -> block envelope on stdout, or nothing
  no                -> cli::scrub_raw_text -> Scrubber::scrub
                    -> scrubbed text on stdout, count on stderr
```

1. `main` calls `cli::run`, which parses arguments with clap and dispatches the subcommand.
2. `cli::run_scrub` reads all of stdin, then loads config with `config::load` and `config::load_engine` and builds a `Scrubber`.
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
| `src/config.rs` | Loads and merges global and project files using the shared configuration types. |
| `src/settings.rs` | Claude Code `settings.json`: read, `install_hook`, `remove_hook`, find our entry. |
| `src/init.rs` | `redacted init` (env file pick, `parse_dotenv`, `with_url_passwords`, rotated-key opt-in, `merge_learned_into_config`, hook install) and `uninstall`. |
| `src/verify.rs` | `redacted verify`: one `Check` per line, exit 1 on any FAIL. |
| `src/hook.rs` | PostToolUse protocol: payload parsing, block envelope, fail closed. |
| `src/opencode.rs` | `redacted scrub --format opencode`: OpenCode's `tool.execute.after` contract, fail closed with the withheld shape; the plugin file `init --format opencode` writes. |
| `src/stream.rs` | `redacted scrub --stream`: line-by-line scrub with PEM block buffering, fail closed per line. |
| `src/pre_hook.rs` | PreToolUse protocol: rewrites a Monitor command to pipe through `scrub --stream`, denies `ws` monitors, fails closed with a deny. |
| `src/stats.rs` | `stats.jsonl`: `record`, `aggregate`, `render`. |
| `src/<module>/tests.rs` | Unit tests for `src/<module>.rs`, declared there as `#[cfg(test)] mod tests;` (for example `src/config/tests.rs`). |

Other paths:

| Path | Contents |
| --- | --- |
| `tests/cli.rs` | End-to-end tests of the binary. |
| `plugins/opencode/redacted.ts` | The OpenCode plugin, compiled into the binary with `include_str!`; `smoke.mjs` runs it under Bun. |
| `tests/golden.rs`, `tests/fixtures/` | Raw-mode output pinned to goldens. |
| `scripts/migration-check.sh` | Fresh install, v1 upgrade and v2 config in a throwaway `HOME`. |

## Config loading

- `config::load` merges `~/.config/redacted/config.yaml` with `<cwd>/.redacted.yaml`.
- `config::load_engine` merges `~/.config/redacted/engine.yml` with `<cwd>/.redacted.engine.yml`.
- Merge rules: lists concatenate, `ignore_internal_tools` is ORed, a project `override: true` drops the global file.
- `version`, `learned`, `heuristic` and `pii` always come from the global config, even under `override`.
- A missing file is treated as absent. One that exists but does not read or parse is an error naming the file: hook mode withholds and names only the file in the notice (the message, which can quote the file, goes to stderr), raw-text and stream modes exit 1, `verify` fails `config files`.
- `config::home_dir` returns `None` for an unset or empty `HOME`, so no path is built under the working directory.
- `EngineConfig` ignores the 0.7 keys `keywords`, `heuristic` and `value_safe_char` like any unknown key.

## Engine dependency

The CLI calls `redacted_core::scrub::Scrubber` in raw, hook, and streaming
modes. The engine owns matching and replacement. The CLI decides how to read
input, apply local policy, report counts, and handle errors.

`init` parses `.env` files and offers URL passwords as separate entries.
`redacted_core::scrub::learn` creates an exact-hash entry. For eligible new
entries, `init` offers a separate rotated-key picker with every row unchecked.
Each row shows the prefix that would be stored. `init` calls the core's shape
derivation only for rows the user selects. Previously saved shapes still
take effect, and `verify` identifies their entries.

The development dependency pins an exact core version and a full Git
revision. Cargo uses the version from crates.io when packaging the CLI.
See [Releasing](../CONTRIBUTING.md#releasing) for the registry dependency.

## Hook protocol

`hook::scrub_payload` reads these payload fields:

| Field | Use |
| --- | --- |
| `tool_name` | `"Bash"` takes `scrub_bash_response`; anything else `scrub_tool_response`. A non-string fails closed. |
| `tool_response` | The text to scrub. |
| `cwd` | Read by `cli::run_scrub` for project config. |
| `session_id` | Read by `cli::run_scrub` for the pre-v2 notice. |

- `scrub_bash_response` scrubs `tool_response.stdout` and `.stderr` separately.
- `scrub_tool_response` scrubs a string response directly. For structured responses it collects every string leaf and object key (`collect_strings`) and rewrites them in place (`scrub_json`).

A hit prints one line:

```json
{"decision":"block","reason":"[redacted] N secret(s) scrubbed from <command|tool_name> output: <pattern ×k, ...>\n\n- <line holding a marker>","hookSpecificOutput":{"hookEventName":"PostToolUse","updatedToolOutput":<tool_response with its strings scrubbed>}}
```

- `updatedToolOutput` replaces the tool result the model reads. It mirrors the `tool_response` shape, because Claude Code applies it only when it matches the tool's output schema (a string is ignored on Bash).
- Bash: the incoming object with `stdout` and `stderr` replaced by their scrubbed text. Other fields (`interrupted`, `isImage`) stay. Other tools: the scrubbed JSON value, or the scrubbed string for a string response.
- `reason` only names the hits, since `updatedToolOutput` already carries the output. Header: per-pattern counts, most hits first then by name, `×k` only when k > 1. Claude Code shows it collapsed. Body: each line holding a marker, prefixed `- ` (Bash: stdout lines, then stderr).
- Key order and escaping match the Go 0.7 encoder: typed `Serialize` structs, U+2028 and U+2029 escaped, trailing newline.
- No hit: nothing is printed and Claude Code keeps the original output.
- Fail closed: a parse error, a wrong field type, a scrubber that failed to build, or a panic (`catch_unwind` in `scrub_payload_or_withhold`) prints `withheld_output(stdin)`, an envelope whose `reason` and `updatedToolOutput` carry no tool output. `updatedToolOutput` mirrors `tool_response` with every string leaf withheld (object keys are kept); unparsable input or no `tool_response` gets the bare `WITHHELD` sentence.
- `ignore_internal_tools` skips only a `tool_name` that is a string other than `"Bash"`. A missing or bad name is still scrubbed or fails closed.
- Exit code: always 0 once stdin is read. Only a failed stdin read exits 1.
- PreToolUse: `cli::run_scrub` sends a payload whose `hook_event_name` is `"PreToolUse"` to `pre_hook::respond` before any config loads. Only `tool_name` `"Monitor"` gets an answer; any other prints nothing. The rewrite (no `permissionDecision`, so Claude Code still asks as usual):
  ```json
  {"hookSpecificOutput":{"hookEventName":"PreToolUse","updatedInput":{<tool_input with command = "bash -c '<command>' 2>&1 | '<exe>' scrub --stream --cwd '<cwd>'">}}}
  ```
  A `ws` call, or one that cannot be rewritten (bad `tool_input`, no `command`, no `cwd`, no binary path), gets `"permissionDecision":"deny"` with a `permissionDecisionReason` that names fields only, never payload content. The command is one single-quoted word (`shell_quote`), never interpolated into shell syntax, and every Monitor command is wrapped.
- Pre-v2 notice: when the global config exists with no `version`, the first hit in each `session_id` gets `[redacted] config is v1: run `redacted init` to learn your secrets.` above its `reason` (`hook::prepend_reason`). Seen sessions are stored in `notified.txt` next to the stats file.

## OpenCode format

`--format <claude|opencode>` on `scrub`, `init`, `uninstall` and `verify` picks the tool; `claude` is the default.

- stdin: `{"tool", "sessionID", "callID", "args", "output"}` from the plugin. `--cwd` loads the project config, as `scrub --stream` does.
- stdout: `output` as JSON, hit or not, with every string leaf and key scrubbed by `hook::scrub_json`. Exit 0.
- `ignore_internal_tools` passes every tool but `bash` through unchanged.
- Fail closed: a bad payload, a config or scrubber error, or a panic prints `output` with every string withheld (`hook::withhold_strings`), or the bare `WITHHELD` string without a usable `output`.
- Stats record `tool`. No pre-v2 notice: OpenCode has no field for it.
- The plugin throws on a non-zero exit or unparsable stdout, which fails the tool call.

## Stats file

- Path: `~/.config/redacted/stats.jsonl`, or `REDACTED_STATS_FILE`.
- `cli::record_stats` calls `stats::record` after each hook run with at least one hit.
- One JSON line per run: `{"t":"<RFC 3339 UTC>","tool":"<tool_name>","by":{"<pattern>":<count>}}`. Created with mode 0600.
- Every write error is ignored, so stats never break the hook.
- `stats::aggregate` skips malformed lines. `stats::render` sorts by count, then name.

## Testing

| Layer | Where | What it pins |
| --- | --- | --- |
| Unit | `src/<module>/tests.rs`, a sibling of each implementation file | config merge, learning prompts, settings round trip, hook envelope bytes, fail-closed behavior |
| CLI | `tests/cli.rs` | the binary end to end: raw mode, hook mode, stats, verify, init without a terminal, uninstall, pre-v2 notice, empty `HOME` |
| Golden | `tests/golden.rs`, `tests/fixtures/` | raw-mode stdout and stderr byte for byte against goldens recorded from the Go 0.7 binary |
| Migration | `scripts/migration-check.sh` | fresh install, v1 upgrade (notice once per session), v2 config |

- Tests use the core crate's `test-support` feature for synthetic secrets. Core CI owns precision, recall, and benchmark coverage.
- Golden fixtures are templates (`{{alnum:40}}`) expanded with a PRNG seeded from the file name.

## Reading order

For someone learning Rust from this repo, read in this order. Each line names an idiom the file shows.

1. `src/main.rs`: `mod` declarations, `#[cfg(test)]` on a module, `fn main() -> ExitCode`.
2. `src/cli.rs`: clap derive (`Parser`, `Subcommand`); commands return `Result<(), String>` and `run` maps it to `ExitCode`; `?` with `map_err`; `matches!` with an `if` guard.
3. `src/config.rs`: a generic `fn read_yaml<T: DeserializeOwned>`; `match` on a tuple with a guard; struct update syntax (`..merged`).
4. `src/settings.rs`: `serde_json::Value` instead of a typed struct, so unknown keys survive a rewrite; `let ... else`; `Value::take`; a match guard on `io::ErrorKind`.
5. `src/stats.rs`: importing a trait (`OpenOptionsExt`) to get its methods, behind `#[cfg(unix)]`; `BTreeMap` for sorted keys; ignoring errors with `let _ =`.
6. `src/verify.rs`: a `Copy` enum with a method; a parameter of type `impl Into<String>`.
7. `src/init.rs`: `Result<LearnedSecret, &'static str>`; `char_indices` to slice UTF-8 safely; `split_once` and `strip_prefix`; `serde_yaml::Value` to edit a file and keep unknown keys.
8. `src/hook.rs`: `panic::catch_unwind` with `AssertUnwindSafe`; `#[derive(Serialize)]` structs with a lifetime `'a` and `#[serde(rename)]`; `&dyn Fn`; a `type` alias.
9. `tests/cli.rs`: integration tests with `env!("CARGO_BIN_EXE_redacted")` and `Command` with piped stdin.
10. `tests/golden.rs`: a `move` closure that owns mutable PRNG state.
