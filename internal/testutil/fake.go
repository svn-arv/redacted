// Package testutil generates fake secrets at runtime for testing.
// Values match the regex patterns in patterns.yaml but never appear in source
// code, avoiding GitHub push protection false positives.
package testutil

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
)

// Secret holds a generated fake value and its last-4-char hint.
type Secret struct {
	Value string
	Hint  string
}

func hint(s string) string {
	r := []rune(s)
	if len(r) <= 4 {
		return s
	}
	return string(r[len(r)-4:])
}

// RandHex returns n random hex characters.
func RandHex(n int) string {
	b := make([]byte, (n+1)/2)
	rand.Read(b)
	return hex.EncodeToString(b)[:n]
}

// RandAlphaNum returns n random mixed-case alphanumeric characters.
func RandAlphaNum(n int) string {
	const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	return randFromCharset(charset, n)
}

// RandDigits returns n random digit characters.
func RandDigits(n int) string {
	const charset = "0123456789"
	return randFromCharset(charset, n)
}

func randUpperAlphaNum(n int) string {
	const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	return randFromCharset(charset, n)
}

func randLowerAlphaNum(n int) string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	return randFromCharset(charset, n)
}

func randFromCharset(charset string, n int) string {
	b := make([]byte, n)
	for i := range b {
		idx, _ := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		b[i] = charset[idx.Int64()]
	}
	return string(b)
}

func secret(v string) Secret {
	return Secret{Value: v, Hint: hint(v)}
}

// --- Provider-specific generators ---

// AWSAccessKey returns AKIA + 16 uppercase alphanumeric chars.
func AWSAccessKey() Secret {
	return secret("AKIA" + randUpperAlphaNum(16))
}

// AWSSecretKey returns a 40-char base64-like string.
func AWSSecretKey() Secret {
	return secret(RandAlphaNum(37) + "/" + RandAlphaNum(2))
}

// GitHubToken returns ghp_ or ghs_ + 40 alphanumeric chars.
func GitHubToken(prefix string) Secret {
	return secret(prefix + RandAlphaNum(40))
}

// GitHubFineGrained returns github_pat_ + 26 alphanumeric chars.
func GitHubFineGrained() Secret {
	return secret("github_pat_" + RandAlphaNum(26))
}

// StripeKey returns prefix (sk_live_, pk_live_, etc.) + 24 alphanumeric chars.
func StripeKey(prefix string) Secret {
	return secret(prefix + RandAlphaNum(24))
}

// TwilioSID returns prefix (AC or SK) + 32 hex chars.
func TwilioSID(prefix string) Secret {
	return secret(prefix + RandHex(32))
}

// DigitalOceanToken returns dop_v1_ + 64 hex chars.
func DigitalOceanToken() Secret {
	return secret("dop_v1_" + RandHex(64))
}

// DigitalOceanSpaces returns SPACES_ACCESS_KEY= or SPACES_SECRET_KEY= + value.
func DigitalOceanSpaces(keyName string) Secret {
	v := keyName + "=" + randUpperAlphaNum(4) + RandAlphaNum(16)
	return Secret{Value: v, Hint: hint(v[len(keyName)+1:])}
}

// SentryDSN returns a fake Sentry DSN URL.
func SentryDSN() Secret {
	v := fmt.Sprintf("https://%s@o%s.ingest.sentry.io/%s", RandHex(32), RandDigits(6), RandDigits(7))
	return secret(v)
}

// SentryDSNSubdomain returns a Sentry DSN with a region subdomain.
func SentryDSNSubdomain() Secret {
	v := fmt.Sprintf("https://%s@o%s.ingest.us.sentry.io/%s", RandHex(32), RandDigits(6), RandDigits(7))
	return secret(v)
}

// SlackToken returns xoxb-/xoxp-/xoxa- + segments.
func SlackToken(prefix string) Secret {
	return secret(prefix + "-" + RandDigits(12) + "-" + RandDigits(12))
}

// SendGridKey returns SG. + segments.
func SendGridKey() Secret {
	return secret("SG." + RandAlphaNum(22) + "." + RandAlphaNum(43))
}

// HubSpotPAT returns pat-{region}-{uuid}.
func HubSpotPAT(region string) Secret {
	v := fmt.Sprintf("pat-%s-%s-%s-%s-%s-%s", region, RandHex(8), RandHex(4), RandHex(4), RandHex(4), RandHex(12))
	return secret(v)
}

func randBase64URL(n int) string {
	const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"
	b := make([]byte, n)
	for i := range b {
		idx, _ := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		b[i] = charset[idx.Int64()]
	}
	return string(b)
}

// JWT returns a fake JWT with random header, payload, and signature.
// All three segments start with "eyJ" (base64url for '{"') to match real JWT structure.
func JWT() Secret {
	header := "eyJ" + randBase64URL(33)
	payload := "eyJ" + randBase64URL(25)
	sig := randBase64URL(43)
	return secret(header + "." + payload + "." + sig)
}

// DatabaseURL returns scheme://user:pass@host:port/db.
func DatabaseURL(scheme, user, pass, host, port, db string) Secret {
	v := fmt.Sprintf("%s://%s:%s@%s:%s/%s", scheme, user, pass, host, port, db)
	return secret(v)
}

// DatabaseURLWithParams appends query params.
func DatabaseURLWithParams(scheme, user, pass, host, port, db, params string) Secret {
	v := fmt.Sprintf("%s://%s:%s@%s:%s/%s?%s", scheme, user, pass, host, port, db, params)
	return secret(v)
}

// DatabaseURLNoPort returns scheme://user:pass@host/db (no port, e.g. mongodb+srv).
func DatabaseURLNoPort(scheme, user, pass, host, db string) Secret {
	v := fmt.Sprintf("%s://%s:%s@%s/%s", scheme, user, pass, host, db)
	return secret(v)
}

// EnvSecret returns KEY=value for env-style catch-all testing.
func EnvSecret(key, value string) Secret {
	v := key + "=" + value
	return Secret{Value: v, Hint: hint(value)}
}

// EnvSecretColon returns KEY: value.
func EnvSecretColon(key, value string) Secret {
	v := key + ": " + value
	return Secret{Value: v, Hint: hint(value)}
}

// EnvSecretSpaced returns KEY = value.
func EnvSecretSpaced(key, value string) Secret {
	v := key + " = " + value
	return Secret{Value: v, Hint: hint(value)}
}

// AnthropicKey returns sk-ant- + 90 alphanumeric/dash chars.
func AnthropicKey() Secret {
	return secret("sk-ant-" + RandAlphaNum(90))
}

// CircleCIToken returns CCIPAT_ + 30 alphanumeric chars.
func CircleCIToken() Secret {
	return secret("CCIPAT_" + RandAlphaNum(30))
}

// SentryUserToken returns sntryu_ + 40 alphanumeric chars.
func SentryUserToken() Secret {
	return secret("sntryu_" + RandAlphaNum(40))
}

// RubyGemsKey returns rubygems_ + 30 alphanumeric chars.
func RubyGemsKey() Secret {
	return secret("rubygems_" + RandAlphaNum(30))
}

// NewRelicKey returns NRAK- + 27 alphanumeric chars.
func NewRelicKey() Secret {
	return secret("NRAK-" + RandAlphaNum(27))
}

// PrivateKey returns a fake PEM block.
func PrivateKey(kind string) Secret {
	body := RandAlphaNum(14)
	v := fmt.Sprintf("-----BEGIN %sPRIVATE KEY-----\n%s\n-----END %sPRIVATE KEY-----", kind, body, kind)
	return secret(v)
}

// HookPayload returns a JSON hook payload string with randomly generated secrets.
func HookPayload() string {
	stripe := StripeKey("sk_live_")
	stripePub := StripeKey("pk_live_")
	twilio := TwilioSID("AC")
	twilioAuth := randLowerAlphaNum(32)
	sendgrid := SendGridKey()
	sentry := SentryDSN()
	aws := AWSAccessKey()
	awsSecret := AWSSecretKey()

	return fmt.Sprintf(`{
  "session_id": "test-session-001",
  "transcript_path": "/home/user/.claude/projects/test/transcript.jsonl",
  "cwd": "/home/user/myapp",
  "permission_mode": "default",
  "hook_event_name": "PostToolUse",
  "tool_name": "Bash",
  "tool_input": {
    "command": "cat .env",
    "description": "Check environment variables"
  },
  "tool_response": {
    "exitCode": 0,
    "stdout": "name: myapp-prod\nregion: us-east-1\nservices:\n- name: web\n  envs:\n  - key: RAILS_ENV\n    value: production\n  - key: DATABASE_URL\n    value: postgres://dbuser:%s@db-host-12345.example.com:5432/myapp_prod?sslmode=require\n  - key: REDIS_URL\n    value: rediss://default:%s@redis-12345.example.com:6379\n  - key: SECRET_KEY_BASE\n    value: %s\n  - key: STRIPE_SECRET_KEY\n    value: %s\n  - key: STRIPE_PUBLISHABLE_KEY\n    value: %s\n  - key: TWILIO_ACCOUNT_SID\n    value: %s\n  - key: TWILIO_AUTH_TOKEN\n    value: %s\n  - key: SENDGRID_API_KEY\n    value: %s\n  - key: SENTRY_DSN\n    value: %s\n  - key: AWS_ACCESS_KEY_ID\n    value: %s\n  - key: AWS_SECRET_ACCESS_KEY\n    value: %s\n  - key: ENCRYPTION_KEY\n    value: enc_key_%s\n  - key: APP_NAME\n    value: myapp\n  - key: LOG_LEVEL\n    value: info",
    "stderr": ""
  },
  "tool_use_id": "toolu_01ABC123DEF456"
}`,
		RandAlphaNum(12),       // db password
		RandAlphaNum(10),       // redis password
		RandHex(64),            // SECRET_KEY_BASE
		stripe.Value,           // STRIPE_SECRET_KEY
		stripePub.Value,        // STRIPE_PUBLISHABLE_KEY
		twilio.Value,           // TWILIO_ACCOUNT_SID
		twilioAuth,             // TWILIO_AUTH_TOKEN
		sendgrid.Value,         // SENDGRID_API_KEY
		sentry.Value,           // SENTRY_DSN
		aws.Value,              // AWS_ACCESS_KEY_ID
		awsSecret.Value,        // AWS_SECRET_ACCESS_KEY
		RandAlphaNum(30),       // ENCRYPTION_KEY
	)
}
