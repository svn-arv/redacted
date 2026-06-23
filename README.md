# redacted

A hook that redacts secrets from tool output before your AI coding assistant sees them.

When an AI tool runs a command or reads a file, the full output goes into conversation context. If that output contains API keys, database URLs, or tokens, they end up on the wire. `redacted` prevents this by scanning the output and replacing secrets before they leave your machine.

Built for Claude Code's PostToolUse hook, which is the tested integration. `redacted scrub` also runs standalone: pipe a Claude-Code-style JSON payload (or, in test mode, any raw text) through stdin and it writes back the scrubbed result, so other hook-capable tools can wire it in.

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

### Go

```bash
go install github.com/svn-arv/redacted@latest
redacted init
```

### Pre-built binaries

Download from [GitHub Releases](https://github.com/svn-arv/redacted/releases) for Linux, macOS, and Windows (amd64/arm64).

## Setup

### Claude Code

```bash
# Install globally (default)
redacted init

# Install for this project only
redacted init --local
```

This registers `redacted scrub` as a PostToolUse hook. All tool output (Bash, Read, Grep, WebFetch, etc.) gets scanned before it reaches the model. Safe to run multiple times.

| Flag       | Settings file                 | Scope        |
| ---------- | ----------------------------- | ------------ |
| *(default)* | `~/.claude/settings.json`     | All projects |
| `--local`  | `.claude/settings.local.json` | This project |

### Other tools

`redacted scrub` reads a JSON payload from stdin and writes to stdout. Pipe any tool output through it:

```bash
echo '{"tool_name":"Bash","tool_response":{"stdout":"DB_PASSWORD=SUPER-SECRETPASSWORD"}}' | redacted scrub
```

If secrets are found, it outputs a JSON response with `decision: "block"` and the redacted text. If no secrets are found, it outputs nothing (pass-through).

## What it detects

### Specific patterns

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

### Generic catch-alls

Any environment variable whose name contains these keywords gets its value redacted:

`SECRET`, `TOKEN`, `PASSWORD`, `API_KEY`, `CREDENTIAL`, `PRIVATE_KEY`, `ACCESS_KEY`, `ENCRYPTION_KEY`, `SIGNING_KEY`, `LICENSE_KEY`, `CLIENT_ID`, `DB_PASS`, `DB_URL`, `DATABASE_URL`, `REDIS_URL`, `_DSN`, `_SID`, `ACCOUNT_ID`, `AUTH_KEY`, `MASTER_KEY`, `SERVICE_KEY`

Works in env files (`SECRET_KEY=value`), shell exports, and YAML configs.

### Heuristic value detection

The keyword list above can't name every secret-bearing variable. So any `KEY=value` / `key: value` assignment is also redacted when the **value itself** looks like a random credential, regardless of the key name. A value qualifies only when it:

- is 16–128 characters long,
- mixes lowercase, uppercase, and digits, and
- has high enough Shannon entropy (it looks random, not structured).

These rules are deliberately strict to avoid false positives: structured high-entropy strings such as UUIDs, git/SHA hashes, version numbers, and timestamps use a single case (or omit a class), so they pass through untouched. Thresholds live under `heuristic:` in `engine.yml`.

The trade-off is precision over recall: a secret under an unknown key that is single-case (e.g. all-lowercase hex) won't be caught by this tier, though a matching specific pattern or keyword still would.

## Known limitations

- A URL with both a port and a mixed-case path (`https://host:8080/FooBar`) can have the `:port/path` tail redacted, because `host:port` parses as a key and value. Bare URLs without a port pass through fine.
- A high-entropy identifier that mixes case and digits (some tool or request IDs) may be caught by the heuristic. The 4-character hint makes these easy to spot.
- Every pattern scans the full output in sequence, so multi-megabyte tool output adds noticeable per-call latency.

## How it works

The hook reads a JSON payload from stdin and scrubs secrets from tool output. For Bash, it processes stdout and stderr separately. For other tools (Read, Grep, WebFetch), it scrubs the raw response. If no secrets are found, it exits silently (pass-through). If secrets are found, it outputs a JSON block response with redacted text. The last 4 characters of each secret are kept as a hint so you can tell which key was hit without exposing the value.

## Example

`cat .env` output that would normally expose:

```
DATABASE_URL=postgres://admin:secret@db.example.com:5432/prod
STRIPE_SECRET_KEY=<your-stripe-live-key>
APP_NAME=myapp
```

Your AI assistant instead sees:

```
DATABASE_URL=[REDACTED:database_url .../prod]
STRIPE_SECRET_KEY=[REDACTED:stripe_live ...8STU]
APP_NAME=myapp
```

Non-sensitive values pass through unchanged.

## Configuration

Two files, split by concern. Detection rules (what counts as a secret) live in
`engine.yml`; operational policy lives in `config.yaml`. Each loads a global
copy and a per-project copy. See `engine.example.yml`, `config.example.yaml`,
and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

### Engine config (detection)

Global `~/.config/redacted/engine.yml`, project `.redacted.engine.yml`.

```yaml
# Tune the heuristic scorer. Omit a field to keep its default.
heuristic:
  min_entropy: 4.0 # stricter than the 3.5 default, fewer false positives
  min_length: 16

# Add env-name keywords and vendor patterns.
keywords:
  - MONGO
patterns:
  - name: openai_key
    regex: 'sk-proj-[A-Za-z0-9_-]{20,}'
```

Raising heuristic thresholds takes effect at runtime. Lowering `min_length`
below the built-in 16 needs a rebuild, since the candidate regex floor is
compiled in.

### App config (operational)

Global `~/.config/redacted/config.yaml`, project `.redacted.yaml`.

```yaml
whitelist: # turn off built-in patterns by name
  - jwt
allow: # variable names that must never be redacted
  - APP_URL
```

Set `override: true` in a project file to ignore the global file entirely.
`patterns` and `keywords` go in `engine.yml`, not here.

### Internal tools

By default, all tool output is scrubbed (Bash, Read, Grep, WebFetch, etc.). To only scrub Bash output:

```yaml
ignore_internal_tools: true
```

### Allow list

Some variables match secret keywords but aren't actually sensitive (workflow SIDs, app URLs). Add them to the allow list:

```yaml
allow:
  - TWILIO_WORKFLOW_SID
  - APP_URL
```

## Verify

```bash
redacted verify
```

Runs health checks: binary in PATH, hook registered, config loaded, patterns compiled, test scrub passes.

## Stats

See which patterns actually fire:

```bash
redacted stats
```

It reports total redactions, a per-pattern breakdown, and a confidence tier for each: `vendor` (provider signatures, near-zero false positives), `keyword` (credential-named keys), and `heuristic` (entropy-only, where false positives concentrate). A high heuristic share flags patterns worth reviewing. Data lives at `~/.config/redacted/stats.jsonl` and holds pattern names and counts only, never secret values.

## Uninstall

```bash
redacted uninstall
```

Removes hooks from settings and deletes the binary. Use `--keep-binary` to only remove hooks.

## Development

```bash
git clone https://github.com/svn-arv/redacted.git
cd redacted
go build -o redacted .
go test ./...
```

### Project structure

```
main.go                         Entry point
cmd/
  root.go                       CLI root command + version
  init.go                       `redacted init` (installs the hook)
  scrub.go                      `redacted scrub` (the hook handler)
  stats.go                      `redacted stats` (redaction analytics)
  uninstall.go                  `redacted uninstall` (removes the hook)
  verify.go                     `redacted verify` (checks installation)
internal/
  config/config.go              Config file loading (global + project)
  hook/hook.go                  Hook protocol (JSON in/out, fail-closed)
  patterns/secrets.go           Secret detection patterns + Scrubber
  patterns/engine.yml        Pattern definitions (single source of truth)
  stats/stats.go                Redaction stats (record + aggregate)
  testutil/fake.go              Runtime secret generators for tests
```

### Releasing

Tag and push. GoReleaser builds binaries for all platforms, creates the GitHub release, and updates the Homebrew tap.

```bash
git tag vX.Y.Z
git push origin vX.Y.Z
```

## License

MIT
