# Architecture

`redacted` is a hook that scrubs secrets out of AI-tool output before the model
sees them. This doc explains how it fits together. Code references are by file
and function name so they stay accurate as line numbers move.

## Data flow

```
tool output -> Claude Code PostToolUse hook -> `redacted scrub` (stdin JSON)
            -> hook.ProcessSafely -> hook.Process -> patterns.Scrub
            -> block JSON (redacted) | nothing (pass-through)
```

1. `main.go` calls `cmd.Execute` (`cmd/root.go`).
2. `cmd/scrub.go` reads stdin, loads config, and decides test mode (raw text)
   vs hook mode (JSON payload) via `looksLikeHookPayload`.
3. `hook.ProcessSafely` (`internal/hook/hook.go`) runs `hook.Process`, which
   parses the payload and calls `patterns.Scrub` on the tool output.
4. If something was redacted it writes a `decision: "block"` response; if not it
   writes nothing and the original output passes through.

## Two config layers

The split is by concern, so it stays clear what belongs where.

| File | Purpose | Fields | Loaded by |
| --- | --- | --- | --- |
| `engine.yml` | Detection rules (what is a secret) | `heuristic`, `keywords`, `patterns`, `value_safe_char` | embedded default + `config.LoadEngine` |
| `config.yaml` / `.redacted.yaml` | App / operational policy | `whitelist`, `allow`, `ignore_internal_tools`, `override` | `config.Load` |

- The built-in `engine.yml` is embedded into the binary with `//go:embed`
  (`internal/patterns/secrets.go`) and parsed once into `config` at package init.
- A user `engine.yml` (global `~/.config/redacted/engine.yml`, project
  `.redacted.engine.yml`) overrides the heuristic and adds keywords/patterns at
  runtime, no rebuild. See `engine.example.yml`.
- `config.yaml` / `.redacted.yaml` carry operational policy. See
  `config.example.yaml`.
- `cmd/scrub.go:buildScrubberFromConfig` composes both into a `Scrubber`.

## The detection engine

`patterns.builtins` compiles the embedded patterns, then appends three
catch-alls. `Scrubber.Scrub` runs every pattern in order; once a pattern redacts
a span, later patterns can't re-match it. Three tiers, most specific first:

1. **Vendor signatures** (in `engine.yml`): one regex per provider (`AKIA...`,
   `ghp_...`, `sk_live_...`, JWT `eyJ...`, `credentialed_url`, `database_url`).
   Near-zero false positives.
2. **Keyword catch-alls** (`env_secret`, `yaml_secret`, built by
   `envSecretRegex` / `yamlSecretRegex`): redact `KEY=value` when the key
   contains a keyword (`SECRET`, `TOKEN`, ...).
3. **Heuristic** (`secret_value`, built by `heuristicAssignmentRegex`): redact
   `KEY=value` when the value scores as random, whatever the key is named.

## The heuristic

`Scrubber.secretLike` decides if a value looks like a random credential. All of
these must hold (thresholds from `engine.yml`, overridable at runtime):

- length within `min_length`..`max_length`,
- at least `min_char_classes` of {lowercase, uppercase, digit}. This is the main
  discriminator: UUIDs and git SHAs are high-entropy but single-case, so they
  fail here and pass through.
- Shannon entropy (`shannonEntropy`) at least `min_entropy` bits per character.

Plus a guard: a value containing `://` is a URL, not a credential (real
credentialed URLs are caught earlier by the `credentialed_url` vendor pattern).

Thresholds are per-Scrubber (`Scrubber.heuristic`, set by `WithHeuristic`), so a
user `engine.yml` can raise them. Lowering `min_length` below the built-in floor
needs a rebuild, because the candidate regex floor is compiled in.

## False-positive avoidance

`Scrubber.skipMatch` drops a catch-all match when the value is allow-listed
(`isAllowed`), is followed by `(` or `[` (a method call), is an identifier path
(`looksLikeIdentifier`, e.g. `other_token`), or a code reference
(`looksLikeCodeReference`, e.g. `ENV.fetch`). Two regex-level guards also help:
`value_safe_char` keeps a match inside one token, and `excludeSlash` blocks a
value that starts with `/` (a bare URL scheme).

## Redaction

`redact` produces `[REDACTED:type ...hint]` for vendor matches and
`KEY= [REDACTED ...hint]` for catch-alls, preserving the key and the `=`/`:`
separator. The last 4 characters are kept as a hint (`tail`) so you can tell
which secret was hit without exposing it.

## Hook protocol

`hook.Process` parses the payload and branches on `tool_name`. `processBash`
scrubs stdout and stderr separately; `processGeneric` handles Read/Grep/WebFetch
by walking the JSON for string leaves (`walkStrings`). `writeBlock` emits the
block response.

`hook.ProcessSafely` is the safety boundary: it buffers Process's output and, on
any error or panic (`recoverToError`), withholds the output (`writeWithheld`)
instead of letting raw, unscrubbed bytes through. PostToolUse is fail-open by
nature, so the scrubber fails closed.

## Stats

`Scrub` returns `Result.ByPattern` (per-pattern counts). The hook calls `record`
through the `Recorder` function variable, which `cmd/scrub.go` wires to
`stats.Record`. `Record` appends a JSONL line to `~/.config/redacted/stats.jsonl`.
`redacted stats` calls `stats.Aggregate` and `stats.Tier` to show a per-pattern
breakdown and a confidence tier (vendor / keyword / heuristic), where the
heuristic share is the false-positive-risk proxy. Only pattern names and counts
are stored, never values.

## Testing

- `internal/testutil/fake.go` generates synthetic secrets at runtime, so no
  real-looking secret is ever committed (which would trip push protection).
- `TestScrub_BuiltinPatterns` (`secrets_test.go`) is a table test, one row per
  pattern, asserting redaction, label, and hint.
- The golden corpus (`corpus_test.go` + `corpus/clean/*.txt`) is the accuracy
  benchmark: `TestCorpus_Precision` fails on any redaction of clean input,
  `TestCorpus_Recall` fails on any missed synthetic secret. `knownResidualFPs`
  is a tripwire that flags when a known false positive gets fixed.
- `FuzzScrub` (`fuzz_test.go`) asserts Scrub never panics and keeps its
  accounting consistent on arbitrary input.
- `BenchmarkScrub` (`bench_test.go`) measures per-call latency.
- `hook_safe_test.go` and `cmd/integration_test.go` cover fail-closed behavior
  and the hook-to-stats wiring.

## File map

```
main.go                          entry point
cmd/
  root.go                        CLI root + version
  init.go / uninstall.go         install / remove the hook
  scrub.go                       the hook handler; composes the Scrubber
  stats.go                       `redacted stats`
  verify.go                      `redacted verify`
internal/
  config/config.go               app config (Config) + engine config (EngineConfig)
  hook/hook.go                    hook protocol, fail-closed wrapper, stats Recorder
  patterns/secrets.go            Scrubber, tiers, heuristic, options
  patterns/engine.yml            built-in detection rules (embedded default)
  patterns/corpus/               golden corpus (clean inputs)
  stats/stats.go                 redaction stats (record + aggregate + tiers)
  testutil/fake.go               synthetic secret generators for tests
```
