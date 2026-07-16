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

Registers `redacted scrub` as a PostToolUse hook. Safe to run multiple times.

| Flag       | Settings file                 | Scope        |
| ---------- | ----------------------------- | ------------ |
| *(default)* | `~/.claude/settings.json`     | All projects |
| `--local`  | `.claude/settings.local.json` | This project |

### Other tools

`redacted scrub` reads a Claude-Code-style JSON payload on stdin and writes to stdout, so any hook-capable tool can wire it in:

```bash
echo '{"tool_name":"Bash","tool_response":{"stdout":"DB_PASSWORD=SUPER-SECRETPASSWORD"}}' | redacted scrub
```

Secrets found: a JSON response with `decision: "block"` and the redacted text. Nothing found: no output (pass-through). Bash stdout and stderr are scrubbed separately; other tools (Read, Grep, WebFetch) are scrubbed on the raw response.

## What it detects

Three tiers: vendor patterns, credential keywords, entropy heuristic.

### Vendor patterns

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

### Credential keywords

Any env var whose name contains one of these gets its value redacted:

`SECRET`, `TOKEN`, `PASSWORD`, `API_KEY`, `CREDENTIAL`, `PRIVATE_KEY`, `ACCESS_KEY`, `ENCRYPTION_KEY`, `SIGNING_KEY`, `LICENSE_KEY`, `CLIENT_ID`, `DB_PASS`, `DB_URL`, `DATABASE_URL`, `REDIS_URL`, `_DSN`, `_SID`, `ACCOUNT_ID`, `AUTH_KEY`, `MASTER_KEY`, `SERVICE_KEY`

Works in env files (`SECRET_KEY=value`), shell exports, and YAML.

### Entropy heuristic

Keywords can't name every secret-bearing variable. So any `KEY=value` / `key: value` assignment is also redacted when the value itself looks like a credential:

- 16–128 characters,
- lowercase + uppercase + digits, and
- high Shannon entropy (random, not structured).

Strict on purpose. UUIDs, git SHAs, versions, and timestamps use a single case or skip a character class, so they pass. The trade-off is precision over recall: a single-case secret under an unknown key slips this tier; a vendor pattern or keyword still catches it. Thresholds live under `heuristic:` in `engine.yml`.

## Configuration

Two files. Detection rules in `engine.yml`, operational policy in `config.yaml`. Each loads a global copy and a per-project copy. See `engine.example.yml`, `config.example.yaml`, and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

### engine.yml (detection)

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

Raising heuristic thresholds works at runtime. Lowering `min_length` below 16 needs a rebuild (the candidate regex floor is compiled in).

### config.yaml (operational)

Global `~/.config/redacted/config.yaml`, project `.redacted.yaml`.

```yaml
whitelist: # turn off built-in patterns by name
  - jwt
allow: # keyword-matching names that aren't secrets
  - TWILIO_WORKFLOW_SID
  - APP_URL
```

`override: true` in a project file ignores the global file. Patterns and keywords go in `engine.yml`, not here.

To scrub Bash output only:

```yaml
ignore_internal_tools: true
```

## Known limitations

- A URL with a port and a mixed-case path (`https://host:8080/FooBar`) can have the `:port/path` tail redacted; `host:port` parses as a key and value. Bare URLs without a port pass fine.
- A high-entropy identifier that mixes case and digits (some tool or request IDs) may trip the heuristic. The 4-character hint makes these easy to spot.
- Every pattern scans the full output in sequence; multi-megabyte output adds noticeable per-call latency.

## Verify

```bash
redacted verify
```

Health checks: binary in PATH, hook registered, config loaded, patterns compiled, test scrub passes.

## Stats

```bash
redacted stats
```

Total redactions, per-pattern counts, and each pattern's confidence tier: `vendor` (near-zero false positives), `keyword` (credential-named keys), `heuristic` (entropy-only, where false positives concentrate). A high heuristic share flags patterns worth reviewing. Data lives at `~/.config/redacted/stats.jsonl`: pattern names and counts only, never values.

## Uninstall

```bash
redacted uninstall
```

Removes hooks and deletes the binary. `--keep-binary` removes hooks only.

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
