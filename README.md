# redacted

Removes secrets from tool output before your AI coding assistant reads it.

## Why

Secrets reach the model through normal work, not only through `cat .env`:

- Ordinary output carries them: a committed key in `git diff`, a token in a log, a stack trace that prints the environment.
- Some commands exist to print them: `heroku config`, `kubectl get secret -o yaml`, `aws secretsmanager get-secret-value`.
- Command deny lists read the command string. An npm script, a make target or a wrapper CLI changes the string, not the output.
- Once in context, a secret sits in the transcript on disk and in every later request.

`redacted` does not judge commands. It scrubs the output, whatever produced it.

## How it works

- Runs as a Claude Code PostToolUse hook: `redacted scrub` reads each tool result on stdin.
- Scanning happens on your machine. No network calls.
- A secret is replaced inline by a marker that keeps its last 4 characters.
- Clean output passes through unchanged.

Tool output:

```
DATABASE_URL=postgres://admin:secret@db.example.com:5432/prod
AWS_ACCESS_KEY_ID=AKIAEXAMPLEKEYID0001
DB_PASSWORD="P@ssw0rd2024"
APP_NAME=myapp
```

What the model reads (the third line needs `DB_PASSWORD` learned by `redacted init`):

```
DATABASE_URL=[REDACTED:database_url ...prod]
AWS_ACCESS_KEY_ID=[REDACTED:aws_access_key ...0001]
DB_PASSWORD="[REDACTED:db_password ...2024]"
APP_NAME=myapp
```

## Install

### curl (recommended)

```bash
curl -sSL https://raw.githubusercontent.com/svn-arv/redacted/main/install.sh | sh
redacted init
```

### Homebrew

```bash
brew tap svn-arv/tap
brew install redacted
redacted init
```

### Pre-built binaries

Download from [GitHub Releases](https://github.com/svn-arv/redacted/releases) for Linux and macOS (amd64/arm64) and Windows (amd64).

## Setup: `redacted init`

```bash
redacted init                      # learn from .env*, hook in ~/.claude/settings.json
redacted init --local              # hook in .claude/settings.local.json instead
redacted init --env .env.production
```

| Flag | Effect |
| --- | --- |
| *(none)* | Hook goes to `~/.claude/settings.json` (all projects). |
| `--local` | Hook goes to `.claude/settings.local.json` (this project). Learned entries still go to the global config. |
| `--env PATH` | Learn from this file and skip the `.env*` search. |

What `init` does, in order:

1. Requires an interactive terminal. Without one it exits 1 with `init needs an interactive terminal`.
2. Picks the env file: `--env PATH`, or the `.env*` files in the current directory.
   - Names containing `example`, `sample` or `template` are skipped.
   - One file is used directly. Several open a picker.
   - None found: it installs the hook only.
3. Reads `KEY=value` lines. Handles `export`, quotes and `#` comments. Skips empty values.
4. Shows a multi-select, `Secrets to learn:`. Each row shows the key, the last 4 characters (values of 12+ characters only) and the shape, or `exact only`. Never the value.
   - Pre-ticked: values with at least 2 of {lowercase, uppercase, digit, other}. So `development` and `3000` start unticked.
   - Not learnable, shown with the reason: under 8 characters (`too short`) or containing whitespace (`cannot match (contains spaces)`).
5. Prints the merged `~/.config/redacted/config.yaml` and asks `Write it?` (default No).
   - No: exits 1 with `init: nothing written`. The hook is not installed.
   - Yes: writes the file with mode 0600, sets `version: 2`, merges `learned` entries by name and keeps every other key.
6. Registers `<absolute path of this binary> scrub` as a PostToolUse hook. An existing `redacted scrub` entry is replaced. Other hooks and settings are kept.
7. Prints a notice when only vendor signatures are active (no learned entries, heuristic off).

Safe to run again.

## What it detects

Three tiers run in this order on the same text. Each tier sees the markers the previous one wrote, so a span is never redacted twice.

| Tier | Source | Default | Marker |
| --- | --- | --- | --- |
| 1. Vendor signatures | built-in `src/engine.yml`, then your `engine.yml` `patterns` | on | `[REDACTED:<name> ...abcd]`; keyed patterns write `KEY= [REDACTED ...abcd]` |
| 2. Learned secrets | `learned` in `~/.config/redacted/config.yaml` | on once `init` writes entries | `[REDACTED:<name> ...abcd]`, no hint for values under 12 characters |
| 3. Entropy heuristic | `heuristic` in `~/.config/redacted/config.yaml` | off | `KEY= [REDACTED ...abcd]` |

The 0.7 keyword tier (`env_secret`, `yaml_secret`) is removed. Learned secrets replace it.

### Vendor signatures

The `name` column is what `whitelist` takes. Keyed patterns match `KEY=value` or `KEY: value` and keep the key in the output.

| `name` | Matches |
| --- | --- |
| `aws_access_key` | `AKIA` or `ASIA` + 16 uppercase letters or digits |
| `aws_secret_key` | `aws_secret_access_key=` + 40 characters (keyed) |
| `github_fine_grained` | `github_pat_...` |
| `github_token` | `ghp_`, `ghs_`, `ghu_` |
| `github_oauth` | `gho_` |
| `github_refresh` | `ghr_` |
| `stripe_live` | `sk_live_`, `pk_live_`, `rk_live_` |
| `stripe_test` | `sk_test_`, `pk_test_`, `rk_test_` |
| `stripe_webhook_secret` | `whsec_` |
| `twilio_api_key` | `SK` + 32 hex |
| `twilio_account_sid` | `AC` + 32 hex |
| `digitalocean_token` | `dop_v1_` + 64 hex |
| `digitalocean_spaces` | `SPACES_ACCESS_KEY=`, `SPACES_SECRET_KEY=` (keyed) |
| `sentry_dsn` | `https://<32 hex>@<host>.ingest.sentry.io/<id>` |
| `sentry_user_token` | `sntryu_` |
| `slack_token` | `xoxa-`, `xoxb-`, `xoxe-`, `xoxp-`, `xoxr-`, `xoxs-` |
| `slack_webhook` | `https://hooks.slack.com/services/...` |
| `sendgrid_key` | `SG.<22+>.<22+>` |
| `hubspot_key` | `pat-<region>-<uuid>` |
| `anthropic_key` | `sk-ant-` |
| `openai_key` | `sk-proj-`, `sk-svcacct-`, `sk-admin-` |
| `openai_classic_key` | `sk-` + exactly 48 letters or digits |
| `google_api_key` | `AIza` + 35 characters |
| `google_api_key_v2` | `AQ.` + 40+ characters |
| `huggingface_token` | `hf_` |
| `groq_key` | `gsk_` |
| `openrouter_key` | `sk-or-v1-` |
| `xai_key` | `xai-` |
| `perplexity_key` | `pplx-` |
| `tavily_key` | `tvly-`, `tvly-dev-` |
| `langsmith_key` | `lsv2_pt_`, `lsv2_sk_` |
| `circleci_token` | `CCIPAT_` |
| `rubygems_key` | `rubygems_` |
| `newrelic_key` | `NRAK-` |
| `gitlab_pat` | `glpat-` |
| `npm_token` | `npm_` + 36 characters |
| `pypi_token` | `pypi-` |
| `private_key` | PEM block from `-----BEGIN ... PRIVATE KEY-----` to its END line |
| `private_key_truncated` | PEM block cut off before its END line |
| `gcp_sa_private_key` | `private_key` field of service-account JSON whose value starts with `-----BEGIN` (keyed) |
| `gcp_sa_key_id` | `"private_key_id": "<hex>"` (keyed) |
| `jwt` | `eyJ...` with three base64url segments |
| `auth_header` | `Authorization:` or `Proxy-Authorization:` + `Bearer`, `Basic` or `Token` + value (keyed) |
| `database_url` | `postgres://`, `postgresql://`, `mysql://`, `mongodb://`, `mongodb+srv://`, `redis://`, `rediss://`, `amqp://`, `amqps://` |
| `credentialed_url` | `scheme://user:pass@host` for any other scheme (for example `postgis://`) |
| `password_assignment` | a key ending in `password` or `passwd`, then `=` or `:`, then a value of 8+ characters (keyed). Covers `DB_PASSWORD=`, `db.password=`, `password: `, `"password": ` and libpq `password=` |

Built-in `allow_values` leave these alone: Anthropic transcript ids (`toolu_`, `msg_`, `req_`), placeholder URL passwords (`pass`, `password`, `USER:PASSWORD`, `<password>`), `org/repo#123` refs, version strings, credential-free localhost database URLs, and filler password values (`********`, `your-password-here`, lowercase `password` followed by digits).

### Learned secrets

- `init` stores, per value: `name` (the env key, lowercased), `sha256` of the value, `len` in bytes and an optional `shape`. Never the value.
- A URL value with a password, such as `DATABASE_URL=postgres://admin:pw@host/db`, adds a second row, `database_url_password`. It holds the password alone, percent-decoded, so a log that prints only the password is caught too.
- A `shape` is derived when the value has a literal prefix of 3+ characters ending in `_` or `-` within its first 12 characters, and the rest holds only letters, digits, `_` and `-`.
- The shape is the prefix, the rest's character set and a length band of plus or minus 4, for example `\bsk_live_[a-zA-Z0-9]{20,28}\b`. It also catches a rotated key with the same prefix.
- Matching runs shapes first, then exact hashes.
- Exact candidates: whole tokens, the part after each `=` or `:`, with trailing punctuation and one pair of quotes removed. A candidate is hashed only when its byte length equals some learned `len`.
- Learned entries are read from the global config only. `learned` in a project `.redacted.yaml` is ignored, and `verify` warns about it.

### Entropy heuristic (opt-in)

Off by default. With `heuristic.enabled: true` in the global config, a `KEY=value`, `KEY: value` or `KEY => value` is redacted when the value passes every threshold:

| Key | Default | Check |
| --- | --- | --- |
| `min_length` | 16 | value has at least this many characters |
| `max_length` | 128 | value has at most this many characters |
| `min_char_classes` | 3 | value has at least this many of {lowercase, uppercase, digit} |
| `min_entropy` | 3.5 | Shannon entropy of the value, in bits per character, is at least this |

- Each absent threshold takes its default. An explicit value is used as written, so an explicit 0 means 0, not the default.
- Read from the global config only.
- Skipped even when the thresholds pass:
  - keys that name an id: `id`, `uuid`, `*_id`, `*-id`, `*Id`, `*_uuid`, `*Uuid`
  - values inside a URL, values followed by `(` or `[`, and values equal to the key
  - values shaped like identifiers or code (`spaces.secret_key`, `Foo::Bar`)
  - lowercase words of 12 characters or fewer, and percent-encoded text that decodes to spaces
- A hex value of 24+ characters under a key ending in `_KEY` or `-KEY` is redacted even though hex has only 2 character classes.

## Configuration

Two kinds of file. Each has a global copy and a project copy.

| File | Global | Project | Keys |
| --- | --- | --- | --- |
| config.yaml | `~/.config/redacted/config.yaml` | `.redacted.yaml` | `version`, `learned`, `heuristic`, `whitelist`, `allow`, `ignore_internal_tools`, `override` |
| engine.yml | `~/.config/redacted/engine.yml` | `.redacted.engine.yml` | `patterns`, `allow_values`, `override` |

- The project file is read from the hook payload's `cwd`. Raw-text mode has no `cwd` and reads the global files only.
- A project file adds to the global one: lists are concatenated, `ignore_internal_tools` is on if either file sets it.
- `override: true` in a project file drops the global file. `version`, `learned` and `heuristic` still come from the global file.
- A missing or malformed file is skipped.

Full examples: [config.example.yaml](config.example.yaml), [engine.example.yml](engine.example.yml).

### config.yaml

```yaml
version: 2
learned: # written by `redacted init`, global file only
  - name: db_password
    sha256: <hex>
    len: 12
heuristic:
  enabled: true # thresholds use the defaults above
whitelist: # turn off built-in patterns by name
  - jwt
allow: # skip keyed matches that contain these names
  - SPACES_SECRET_KEY
ignore_internal_tools: false
```

| Key | Effect |
| --- | --- |
| `version` | `2` once `init` has run. A global file without it is a 0.7 config (see Upgrading from 0.7). |
| `learned` | List of `{name, sha256, len, shape}`. Global file only. |
| `heuristic` | `enabled` plus the four thresholds above. Global file only. |
| `whitelist` | Vendor or `engine.yml` pattern names to turn off. No effect on learned names or the heuristic (`secret_value`). |
| `allow` | Skips a vendor or heuristic match whose text contains one of these names (case-insensitive). Only keyed matches contain the key, so value-only patterns and learned secrets ignore this list. |
| `ignore_internal_tools` | Scrub Bash output only; every other tool passes through. |
| `override` | Project file only, see above. |

### engine.yml

```yaml
patterns: # run after the built-in patterns
  - name: acme_key
    regex: 'acme_[A-Za-z0-9]{32,}'
allow_values: # a match whose value fits one of these is kept
  - '^svc_[A-Za-z0-9]+$'
```

- `patterns` use Go RE2 syntax, as in 0.7. They are value-only: the whole match is replaced.
- `allow_values` is checked against the value of a keyed match, or the whole match of a value-only pattern. It does not apply to learned secrets.
- A pattern that fails to compile withholds every hook output. `redacted verify` reports it.
- `keywords`, `heuristic` and `value_safe_char` from a 0.7 `engine.yml` are ignored.

## Verify

```bash
redacted verify
```

Prints one line per check and exits 1 when any check fails.

| Check | Result |
| --- | --- |
| `binary` | Path of the running binary. |
| `global hook`, `local hook` | FAIL when the settings file is missing or invalid JSON, has no `redacted scrub` entry, or the entry's binary is gone. When one passes, the other shows SKIP. |
| `hook registered` | FAIL when neither file has the hook. |
| `config files` | Which of the four files exist. |
| `patterns load` | FAIL when a pattern or learned shape does not compile. |
| `test scrub` | FAIL when the built-in patterns miss a sample database URL. |
| `learned secrets` | Config version, number of learned entries, heuristic on or off. |
| `protection` | WARN when only vendor signatures are active. |
| `project learned` | WARN when `.redacted.yaml` holds `learned` entries, which are ignored. |

## Stats

```bash
redacted stats
```

```
Redactions: 1 across 1 hook runs

By pattern:
  aws_access_key         1
```

- Each hook run with a hit appends one line to `~/.config/redacted/stats.jsonl`: `{"t":"<UTC time>","tool":"<tool_name>","by":{"<pattern>":<count>}}`.
- Pattern names and counts only, never values. The file is created with mode 0600.
- `REDACTED_STATS_FILE` overrides the path.
- Raw-text mode records nothing.

## Uninstall

```bash
redacted uninstall           # both settings files
redacted uninstall --local   # .claude/settings.local.json only
```

- Removes the `redacted scrub` entry from `~/.claude/settings.json` and `./.claude/settings.local.json`.
- Other hooks and settings are kept. A `PostToolUse` or `hooks` key left empty is removed.
- The binary and `~/.config/redacted/config.yaml` stay.

## Upgrading from 0.7

1. Update the binary: run `install.sh` again or `brew upgrade redacted`.
2. Run `redacted verify`. If `global hook` says the hook's binary does not exist, `redacted init` registers the current one.
3. A global config without `version` is a v1 config. It has no `learned` entries, so only vendor signatures run.
4. While the config is v1, the first redaction in each session puts this line above the block `reason` (not in `updatedToolOutput`):
   ```
   [redacted] config is v1: run `redacted init` to learn your secrets.
   ```
5. Run `redacted init` to learn your secrets. It writes `version: 2` and keeps your other keys.

- The entropy heuristic now lives in `config.yaml` and stays off until `heuristic.enabled: true`.
- A 0.7 `engine.yml` still loads. Its `keywords`, `heuristic` thresholds and `value_safe_char` are ignored.

## Other tools

`redacted scrub` has two modes, picked from stdin:

| Mode | Input | Output | Exit |
| --- | --- | --- | --- |
| Hook (JSON) | a JSON object | block envelope on a hit, nothing otherwise | 0 once stdin is read |
| Raw text | anything else | scrubbed text on stdout, `[redacted] N secret(s) scrubbed` on stderr | 0, or 1 when a pattern does not compile |

- The JSON mode is Claude Code's PostToolUse contract. Other tools speak other contracts.
- Raw-text mode is the portable path: pipe text in, read scrubbed text out.
- Raw-text mode reads global config only, records no stats and ignores `ignore_internal_tools`.
- Text that is itself a JSON object is read as a hook payload. Without a `tool_response` field nothing is printed, even when it holds a secret. Wrap such text first, for example `{"tool_response":"<text>"}`, and read `hookSpecificOutput.updatedToolOutput`.

```bash
printf 'key AKIAEXAMPLEKEYID0001\n' | redacted scrub
# key [REDACTED:aws_access_key ...0001]
# stderr: [redacted] 1 secret(s) scrubbed
```

| Tool | Status |
| --- | --- |
| Claude Code | Works today. |
| OpenCode, Gemini CLI, GitHub Copilot CLI, Codex CLI, Amp | Hooks can replace tool output. Adapters are planned. |
| Cursor | Hooks can replace MCP tool output only. |
| Windsurf, Cline, Roo Code, Kiro, Zed | No hook can replace tool output. |

The 0.7 OpenCode plugin was a separate TypeScript port of the patterns. 1.0.0 removes it: the `redacted` binary is the only scrubber. An OpenCode adapter that calls the binary is planned.

## Known limitations

- Learned secrets match as whole tokens. One embedded mid-token, such as in a URL path, passes unless a vendor pattern catches it.
- A learned shape also matches a non-secret with the same prefix and similar length. Check the shape `init` shows before confirming.
- With the heuristic on, a high-entropy identifier that mixes case and digits (some tool or request ids) may be redacted. The 4-character hint makes these easy to spot.
- A malformed config file is skipped as if it were absent. `verify` still lists it under `config files`.
- Every pattern scans the full output in turn, after a substring prefilter. Multi-megabyte output adds noticeable latency per call.

## Development

```bash
git clone https://github.com/svn-arv/redacted.git
cd redacted
cargo build --release
cargo test
```

- How the code fits together: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).
- Checks, tests and adding a detection rule: [CONTRIBUTING.md](CONTRIBUTING.md).

### Releasing

Bump `version` in `Cargo.toml` to match the tag (it is what `--version` prints), then tag and push. GoReleaser builds binaries for all platforms, creates the GitHub release and updates the Homebrew tap.

```bash
git tag vX.Y.Z
git push origin vX.Y.Z
```

## License

MIT
