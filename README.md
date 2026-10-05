# redacted

Redacts secrets from tool output before your AI coding assistant sees them.

## Why

"Models are smart enough not to run `cat .env`." True. Also not the problem. Secrets reach the model through normal work:

- **They ride along in ordinary output.** A committed key in `git diff`. A token in a log. A stack trace that dumps ENV.
- **Some commands exist to print them.** `heroku config`, `kubectl get secret -o yaml`, `aws secretsmanager get-secret-value`. Running them is the job.
- **Command guards are easy to sidestep.** Deny lists and model judgment read the command string. An npm script, a make target, or a proxy CLI changes the string, not the output.

Once in context, a secret is in the transcript on disk and in every request that follows. `redacted` doesn't judge commands. It scrubs the output, whatever produced it.

## How

A Claude Code PostToolUse hook, the last stop before tool output enters context. Every tool result is scanned on your machine. Secrets are replaced inline; the last 4 characters stay as a hint. Clean output passes through untouched.

`cat .env` would normally expose:

```
DATABASE_URL=postgres://admin:secret@db.example.com:5432/prod
STRIPE_SECRET_KEY=<your-stripe-live-key>
APP_NAME=myapp
```

Your assistant sees:

```
DATABASE_URL=[REDACTED:database_url .../prod]
STRIPE_SECRET_KEY=[REDACTED:stripe_live ...8STU]
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

## Setup

### Claude Code

```bash
# Install globally (default)
redacted init

# Install for this project only
redacted init --local
```

Finds the `.env*` files in the current directory (or reads `--env PATH`), lets you pick which values to learn, prints the config it will write, and asks before writing it. Then registers `redacted scrub` as a PostToolUse hook. Safe to run multiple times: learned entries merge by name.

| Flag       | Settings file                 | Scope        |
| ---------- | ----------------------------- | ------------ |
| *(default)* | `~/.claude/settings.json`     | All projects |
| `--local`  | `.claude/settings.local.json` | This project |

### Other tools

`redacted scrub` reads a Claude-Code-style JSON payload on stdin and writes to stdout, so any hook-capable tool can wire it in:

```bash
echo '{"tool_name":"Bash","tool_response":{"stdout":"<command output>"}}' | redacted scrub
```

Secrets found: a JSON response with `decision: "block"`, a reason, and the redacted text in `hookSpecificOutput.updatedToolOutput`, which replaces the tool result the model reads. Nothing found: no output (pass-through). Anything that fails to parse or scrub is withheld, never passed through raw. Bash stdout and stderr are scrubbed separately; other tools (Read, Grep, WebFetch) are scrubbed on the raw response.

## What it detects

Three tiers: vendor signatures, learned secrets, and an opt-in entropy heuristic.

### Vendor signatures

| Pattern         | Example                                       |
| --------------- | --------------------------------------------- |
| AWS access keys | `AKIA...`                                     |
| AWS secret keys | `aws_secret_access_key=...`                   |
| GitHub tokens   | `ghp_`, `gho_`, `ghs_`, `ghr_`, `github_pat_` |
| Stripe keys     | `sk_live_`, `sk_test_`, `pk_live_`, `rk_live_` |
| Twilio          | `SK...` (API key), `AC...` (Account SID)      |
| DigitalOcean    | `dop_v1_...`, `SPACES_ACCESS_KEY`             |
| Sentry DSN      | `https://<key>@*.ingest.sentry.io/*`          |
| Slack tokens    | `xoxb-`, `xoxp-`, `xoxa-`                    |
| SendGrid        | `SG.*.*`                                      |
| HubSpot         | `pat-<region>-<uuid>`                         |
| Anthropic       | `sk-ant-...`                                  |
| CircleCI        | `CCIPAT_...`                                  |
| Sentry tokens   | `sntryu_...`                                  |
| RubyGems        | `rubygems_...`                                |
| New Relic       | `NRAK-...`                                    |
| OpenAI          | `sk-proj-...`, `sk-svcacct-...`, classic `sk-...` |
| Google          | `AIza...`                                      |
| GitLab          | `glpat-...`                                    |
| npm             | `npm_...`                                      |
| Slack webhook   | `https://hooks.slack.com/services/...`        |
| PyPI            | `pypi-...`                                     |
| Private keys    | `-----BEGIN RSA PRIVATE KEY-----`             |
| JWTs            | `eyJ...` (three base64url segments)           |
| Database URLs   | `postgres://`, `mysql://`, `mongodb://`, `redis://`, `amqp://` |
| Credentialed URLs | `scheme://user:pass@host` for any scheme (e.g. `postgis://`) |

### Learned secrets

`redacted init` reads your `.env` and learns the values you pick. For each one it stores the name, the value's sha256, its length, and, when the value starts with a literal prefix of 3+ characters (`sk_live_`, `ghp_`), a shape regex that also catches the rotated key. Never the value. Values under 8 characters or containing spaces are not learned.

A learned value is redacted wherever it shows up as a token, after `=` or `:`, or inside quotes: `[REDACTED:db_password ...2024]`. Learned entries live in the global config only; a project file never holds hashes.

### Entropy heuristic (opt-in)

Off by default. With `heuristic.enabled: true` in `config.yaml`, any `KEY=value` / `key: value` assignment is also redacted when the value looks like a credential:

- 16–128 characters,
- lowercase + uppercase + digits, and
- high Shannon entropy (random, not structured).

Strict on purpose. UUIDs, git SHAs, versions, and timestamps use a single case or skip a character class, so they pass. Thresholds live under `heuristic:` in `config.yaml`.

### Upgrading from 0.7

Update the binary (same `install.sh` or `brew upgrade`), then run `redacted init`. A 0.7 config keeps working with vendor signatures only; until you run `init`, the hook says so the first time it redacts something in each session.

## Configuration

Two files. Vendor patterns in `engine.yml`; policy, learned secrets and the heuristic in `config.yaml`. Each loads a global copy and a per-project copy. See `engine.example.yml`, `config.example.yaml`, and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

### engine.yml (detection)

Global `~/.config/redacted/engine.yml`, project `.redacted.engine.yml`.

```yaml
# Add vendor patterns.
patterns:
  - name: openai_key
    regex: 'sk-proj-[A-Za-z0-9_-]{20,}'

# Value shapes never redacted: a match whose value (key=value) or whole match
# (value-only) matches one of these passes through.
allow_values:
  - '^svc_[A-Za-z0-9]+$'
```

`keywords` and `heuristic` from a 0.7 `engine.yml` are ignored.

### config.yaml (operational)

Global `~/.config/redacted/config.yaml`, project `.redacted.yaml`.

```yaml
version: 2
learned: # written by `redacted init`, global file only
  - name: db_password
    sha256: <hex>
    len: 12
heuristic:
  enabled: true # opt in to the entropy tier
whitelist: # turn off built-in patterns by name
  - jwt
allow: # names that aren't secrets
  - TWILIO_WORKFLOW_SID
  - APP_URL
```

`override: true` in a project file ignores the global file. Patterns go in `engine.yml`, not here.

To scrub Bash output only:

```yaml
ignore_internal_tools: true
```

## Known limitations

- Learned secrets match as whole tokens. One embedded mid-token, such as in a URL path, passes unless a vendor pattern catches it.
- A learned shape also matches a non-secret with the same prefix and similar length. Check the shape `init` shows before confirming.
- With the heuristic on, a high-entropy identifier that mixes case and digits (some tool or request IDs) may be redacted. The 4-character hint makes these easy to spot.
- Every pattern scans the full output in sequence; multi-megabyte output adds noticeable per-call latency.

## Verify

```bash
redacted verify
```

Health checks: binary in PATH, hook registered, config loaded, patterns compiled, test scrub passes, learned secrets present.

## Stats

```bash
redacted stats
```

Total redactions and per-pattern counts. Data lives at `~/.config/redacted/stats.jsonl`: pattern names and counts only, never values.

## Uninstall

```bash
redacted uninstall
```

Removes the hook from the global and project settings. `--local` removes the project one only. The binary and the config stay.

## Development

```bash
git clone https://github.com/svn-arv/redacted.git
cd redacted
cargo build --release
cargo test
```

### Project structure

```
src/
  main.rs                       Entry point
  cli.rs                        Commands: scrub, verify, stats, init, uninstall
  init.rs                       `redacted init` (learns secrets, installs the hook)
  hook.rs                       Hook protocol (JSON in/out, fail-closed)
  scrub.rs                      Scrubber: vendor, learned and heuristic tiers
  engine.yml                    Vendor pattern definitions (compiled in)
  config.rs                     Config file loading (global + project)
  stats.rs                      Redaction stats (record + aggregate)
  fake.rs                       Runtime secret generators for tests
corpus/clean/                   Clean inputs for precision tests
tests/                          CLI and golden-output tests
scripts/migration-check.sh      Fresh, v1-upgrade and v2 install checks
```

### Releasing

Bump `version` in `Cargo.toml` to match the tag (it is what `--version` prints), then tag and push. GoReleaser builds binaries for all platforms, creates the GitHub release, and updates the Homebrew tap.

```bash
git tag vX.Y.Z
git push origin vX.Y.Z
```

## License

MIT
