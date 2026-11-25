# redacted

Removes secrets from tool output before your AI coding assistant reads it.

> **Project direction:** Core development now continues in [`rmaw22/redacted-core`](https://github.com/rmaw22/redacted-core), the shared redaction engine for CLI and WebAssembly implementations. This repository (`svn-arv/redacted`) is the original CLI implementation and will focus on CLI behavior, integrations, and packaging. New detection rules, engine fixes, and shared redaction logic should be developed in `redacted-core`.

## What you see

![Claude Code after a cat of .env: the hook reports three scrubbed secrets](docs/images/claude-code.png)

Tool output:

```
DATABASE_URL=postgres://admin:secret@db.example.com:5432/prod
AWS_ACCESS_KEY_ID=AKIAEXAMPLEKEYID0001
SMTP_PASS="Qf7mZp2kLw9vTx4nRb2024"
APP_NAME=myapp
```

What the model reads (the third line needs `SMTP_PASS` learned by `redacted init`):

```
DATABASE_URL=[REDACTED:database_url ...prod]
AWS_ACCESS_KEY_ID=[REDACTED:aws_access_key ...0001]
SMTP_PASS="[REDACTED:smtp_pass ...2024]"
APP_NAME=myapp
```

## Why

Secrets reach the model through normal work, not only through `cat .env`:

- Ordinary output carries them: a committed key in `git diff`, a token in a log, a stack trace that prints the environment.
- Some commands exist to print them: `heroku config`, `kubectl get secret -o yaml`, `aws secretsmanager get-secret-value`.
- Deny lists check the command string. An npm script, a make target or a wrapper CLI changes the string, not the output.
- Once in context, a secret stays in the transcript on disk and in every later request.

`redacted` does not judge commands. It scrubs the output, whatever produced it.

## How it works

- Runs as a Claude Code PostToolUse hook: `redacted scrub` reads each tool result on stdin.
- Scanning happens on your machine. No network calls.
- A secret is replaced inline by a marker that keeps its last 4 characters.
- Clean output passes through unchanged.

## Install

```bash
curl -sSL https://raw.githubusercontent.com/svn-arv/redacted/main/install.sh | sh
redacted init
```

Homebrew, Cargo and pre-built binaries for Linux, macOS and Windows are in the [reference](docs/REFERENCE.md#install).

## `redacted init`

- Learns the secrets in your `.env` files, so the hook catches them even when no vendor pattern knows their format.
- Stores a SHA-256 hash, the length and an optional shape for each value. Never the value.
- You pick the values to learn and confirm the config before anything is written.
- Registers the hook in your Claude Code settings. Safe to run again.

Full walkthrough and flags: [Setup: `redacted init`](docs/REFERENCE.md#setup-redacted-init).

## What it catches

| Tier | What it catches | Default |
| --- | --- | --- |
| Vendor signatures | Keys with a known format: 46 built-in patterns covering AWS, GitHub, Stripe, OpenAI, Anthropic, database URLs, private keys and more. | on |
| Learned secrets | The values `redacted init` learned from your `.env`, matched by hash, plus rotated keys with the same prefix. | on once `init` writes entries |
| Entropy heuristic | Random-looking values in `KEY=value` lines that no other tier knows. | off |

Email addresses and phone numbers can be scrubbed too. Each is off until you turn it on in the config.

Every pattern and what it matches: [What it detects](docs/REFERENCE.md#what-it-detects).

## Works with

- Claude Code, through the PostToolUse hook.
- OpenCode, through the plugin that `redacted init --format opencode` writes.

Other assistants, and whether their hooks can replace tool output, are listed under [Other tools](docs/REFERENCE.md#other-tools).

## Known limitations

- Learned secrets match as whole tokens. One embedded mid-token, such as in a URL path, passes unless a vendor pattern catches it.
- A learned shape also matches a non-secret with the same prefix and similar length. Check the shape `init` shows before confirming.
- With the heuristic on, a high-entropy identifier that mixes case and digits (some tool or request ids) may be redacted. The 4-character hint makes these easy to spot.
- Every pattern scans the full output in turn, after a substring prefilter. Multi-megabyte output adds noticeable latency per call.
- Commands typed at the Claude Code prompt with `!` are not tool calls. Their output reaches the model unscrubbed.

## Docs

- [Reference](docs/REFERENCE.md): install methods, `init`, every pattern, configuration and commands.
- [Architecture](docs/ARCHITECTURE.md): how the code fits together.
- [Benchmark](docs/BENCHMARK.md): recall and precision on the test corpus.
- [Contributing](CONTRIBUTING.md): development, adding a detection rule and releasing.

## License

MIT
