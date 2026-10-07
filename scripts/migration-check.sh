#!/bin/sh
# Migration check for the Rust build: fresh install, upgrade from a v1
# config, and a v2 config, each in a throwaway HOME.
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
cargo build --quiet --manifest-path "$root/Cargo.toml"
bin="$root/target/debug/redacted"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
HOME="$tmp/home"
export HOME
unset REDACTED_STATS_FILE
mkdir -p "$HOME/.config/redacted" "$tmp/proj"
cd "$tmp/proj"

fail() {
	echo "FAIL: $1"
	exit 1
}

# Built at runtime so no secret-shaped literal sits in this file.
key="AKIA$(printf 'Q7%.0s' 1 2 3 4 5 6 7 8)"
payload() {
	printf '{"session_id":"%s","tool_name":"Bash","tool_response":{"stdout":"k %s","stderr":""}}' "$1" "$key"
}
notice='[redacted] config is v1: run `redacted init` to learn your secrets.'

echo "1. fresh install"
code=0
"$bin" init </dev/null >"$tmp/init.out" 2>&1 || code=$?
[ "$code" -eq 1 ] || fail "init without a terminal exited $code, want 1"
grep -qF "init needs an interactive terminal" "$tmp/init.out" || fail "init printed no TTY message"
echo "   ok: init refuses without a terminal and exits 1"

echo "2. upgrade from a v1 config"
printf 'whitelist: [jwt]\nallow: [FOO]\n' >"$HOME/.config/redacted/config.yaml"
payload s1 | "$bin" scrub >"$tmp/run1"
payload s1 | "$bin" scrub >"$tmp/run2"
for f in run1 run2; do
	grep -qF "REDACTED:aws_access_key" "$tmp/$f" || fail "$f did not scrub the vendor secret"
done
n=$(cat "$tmp/run1" "$tmp/run2" | grep -cF "$notice" || true)
[ "$n" -eq 1 ] || fail "v1 notice appeared $n times across two runs of one session, want 1"
grep -qF "$notice" "$tmp/run1" || fail "v1 notice missing from the first run"
echo "   ok: secret scrubbed both runs, notice once"

echo "3. v2 config"
printf 'version: 2\n' >"$HOME/.config/redacted/config.yaml"
payload s2 | "$bin" scrub >"$tmp/run3"
grep -qF "REDACTED:aws_access_key" "$tmp/run3" || fail "v2 run did not scrub the vendor secret"
if grep -qF "$notice" "$tmp/run3"; then fail "v2 config carried the v1 notice"; fi
echo "   ok: secret scrubbed, no notice"

echo "all migration checks passed"
