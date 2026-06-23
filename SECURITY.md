# Security Policy

`redacted` scrubs secrets from tool output, so a missed secret (false negative)
or a crash that lets raw output through is a security issue, not just a bug.

## Reporting a vulnerability

Please report privately, not in a public issue: open a
[security advisory](https://github.com/svn-arv/redacted/security/advisories/new).

Include a synthetic example (never a real secret), the expected vs actual
redaction, and your version (`redacted --version`).

## Scope

In scope: missed secrets, fail-open on malformed input, panics, and pattern
bypasses. Out of scope: over-redaction (false positives), tracked as normal bugs.

## Supported versions

The latest released version receives fixes.
