# redacted

A hook that redacts secrets from tool output before your AI coding assistant sees them.

When an AI tool runs a command or reads a file, the full output goes into conversation context. If that output contains API keys, database URLs, or tokens, they end up on the wire. `redacted` prevents this by scanning the output and replacing secrets before they leave your machine.

Works with Claude Code, OpenCode, and any tool that supports output hooks or middleware. For tools without native hook support, `redacted scrub` works as a standalone stdin/stdout filter.

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
echo '{"tool_name":"Bash","tool_response":{"stdout":"DB_PASSWORD=super_secret_password"}}' | redacted scrub
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
| Private keys    | `-----BEGIN RSA PRIVATE KEY-----`             |
| JWTs            | `eyJ...` (three base64url segments)           |
| Database URLs   | `postgres://`, `mysql://`, `mongodb://`, `redis://`, `amqp://` |

### Generic catch-alls

Any environment variable whose name contains these keywords gets its value redacted:

`SECRET`, `TOKEN`, `PASSWORD`, `API_KEY`, `CREDENTIAL`, `PRIVATE_KEY`, `ACCESS_KEY`, `ENCRYPTION_KEY`, `SIGNING_KEY`, `LICENSE_KEY`, `CLIENT_ID`, `DB_PASS`, `DB_URL`, `DATABASE_URL`, `REDIS_URL`, `_DSN`, `_SID`, `ACCOUNT_ID`, `AUTH_KEY`, `MASTER_KEY`, `SERVICE_KEY`

Works in env files (`SECRET_KEY=value`), shell exports, and YAML configs.

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

Create a config file to customize detection.

**Global**: `~/.config/redacted/config.yaml`

```yaml
whitelist:
  - jwt
  - stripe_test

patterns:
  - name: slack_webhook
    regex: 'https://hooks\.slack\.com/services/\S+'

keywords:
  - MONGO
  - ELASTIC
```

**Project**: `.redacted.yaml` in your project root (merged with global)

```yaml
whitelist:
  - twilio_account_sid

keywords:
  - KAFKA
```

Set `override: true` in the project config to ignore the global config entirely.

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
  uninstall.go                  `redacted uninstall` (removes the hook)
  verify.go                     `redacted verify` (checks installation)
internal/
  config/config.go              Config file loading (global + project)
  hook/hook.go                  Hook protocol (JSON in/out)
  patterns/secrets.go           Secret detection patterns + Scrubber
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
