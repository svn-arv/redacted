package patterns

import (
	"regexp"
	"strings"
)

// pattern pairs a name with a compiled regex.
type pattern struct {
	Name        string
	Regex       *regexp.Regexp
	includesKey bool // true if the regex matches KEY=value (not just the value)
}

// Option configures a Scrubber. This is the "functional options" pattern —
// each option is a function that modifies the Scrubber during construction.
type Option func(*Scrubber)

// Scrubber holds patterns and whitelist, and performs the actual redaction.
type Scrubber struct {
	patterns  []*pattern
	whitelist map[string]bool // pattern names to skip
	allow     map[string]bool // variable names to never redact (case-insensitive keys)
}

// New creates a Scrubber with built-in defaults plus any options.
//
//	s := patterns.New()                                        // defaults only
//	s := patterns.New(patterns.WithExtra("slack_webhook", `https://hooks\.slack\.com/\S+`))
//	s := patterns.New(patterns.WithWhitelist("jwt", "stripe_test"))
func New(opts ...Option) *Scrubber {
	s := &Scrubber{
		patterns:  builtins(),
		whitelist: make(map[string]bool),
		allow:     make(map[string]bool),
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// WithExtra adds a custom pattern. It runs BEFORE the generic catch-alls
// but AFTER the built-in specific patterns.
func WithExtra(name, expr string) Option {
	return func(s *Scrubber) {
		compiled := regexp.MustCompile(expr)
		// Insert before the last 2 patterns (env_secret + yaml_secret catch-alls)
		insertIdx := len(s.patterns) - 2
		if insertIdx < 0 {
			insertIdx = 0
		}
		s.patterns = append(s.patterns, nil)
		copy(s.patterns[insertIdx+1:], s.patterns[insertIdx:])
		s.patterns[insertIdx] = &pattern{Name: name, Regex: compiled}
	}
}

// WithWhitelist skips the named patterns during scrubbing.
// Use this when a built-in pattern causes false positives.
//
//	patterns.New(patterns.WithWhitelist("jwt", "stripe_test"))
func WithWhitelist(names ...string) Option {
	return func(s *Scrubber) {
		for _, n := range names {
			s.whitelist[n] = true
		}
	}
}

// WithAllow skips redaction when the matched text contains any of the
// given variable names (case-insensitive). Unlike WithWhitelist which
// disables entire pattern categories, WithAllow targets specific variables.
//
//	patterns.New(patterns.WithAllow("TWILIO_WORKFLOW_SID", "APP_URL"))
func WithAllow(names ...string) Option {
	return func(s *Scrubber) {
		for _, n := range names {
			s.allow[strings.ToUpper(n)] = true
		}
	}
}

// WithKeywords adds env-style detection for custom variable name keywords.
// Matches any KEY=value where KEY contains one of the given words.
//
//	patterns.New(patterns.WithKeywords("MONGO", "REDIS", "ELASTIC"))
func WithKeywords(keywords ...string) Option {
	return func(s *Scrubber) {
		if len(keywords) == 0 {
			return
		}
		joined := strings.Join(keywords, "|")
		expr := `(?i)\b[A-Z0-9_]*(` + joined + `)[A-Z0-9_]*\s*[=:]\s*[^\s\[][^\s]{7,}`
		compiled := regexp.MustCompile(expr)
		s.patterns = append(s.patterns, &pattern{
			Name:        "custom_keyword",
			Regex:       compiled,
			includesKey: true,
		})
	}
}

// Result holds what Scrub found.
type Result struct {
	Redacted bool   // true if any secret was replaced
	Text     string // the scrubbed text
	Count    int    // how many replacements
}

// redact builds the replacement string.
//
// For value-only matches (specific patterns like AKIA..., sk_live_...):
//
//	[REDACTED:stripe_live ...8STU]
//
// For key=value matches (catch-all patterns like env_secret, yaml_secret):
//
//	TWILIO_AUTH_TOKEN=[REDACTED ...0152]
//
// This preserves the variable name so devs know which key was hit.
func redact(name, match string, includesKey bool) string {
	if includesKey {
		// Find the assignment operator (= or :) and split there
		for i, ch := range match {
			if ch == '=' || ch == ':' {
				key := strings.TrimRight(match[:i], " \t")
				value := strings.TrimLeft(match[i+1:], " \t")
				hint := tail(value, 4)
				return key + "=[REDACTED ..." + hint + "]"
			}
		}
	}
	hint := tail(match, 4)
	return "[REDACTED:" + name + " ..." + hint + "]"
}

// tail returns the last n characters of s, or all of s if shorter than n.
func tail(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[len(r)-n:])
}

// Scrub replaces all detected secrets in text with [REDACTED:<type> ...hint].
func (s *Scrubber) Scrub(text string) Result {
	count := 0
	out := text

	for _, p := range s.patterns {
		if s.whitelist[p.Name] {
			continue
		}
		replaced := p.Regex.ReplaceAllStringFunc(out, func(match string) string {
			if s.isAllowed(match) {
				return match
			}
			count++
			return redact(p.Name, match, p.includesKey)
		})
		out = replaced
	}

	return Result{
		Redacted: count > 0,
		Text:     out,
		Count:    count,
	}
}

// isAllowed checks if the matched text contains any allowed variable name.
func (s *Scrubber) isAllowed(match string) bool {
	if len(s.allow) == 0 {
		return false
	}
	upper := strings.ToUpper(match)
	for name := range s.allow {
		if strings.Contains(upper, name) {
			return true
		}
	}
	return false
}

// sensitiveKeywords is the shared list of words that indicate a variable holds a secret.
// Matches variable names containing any of these words (case insensitive).
const sensitiveKeywords = `SECRET|TOKEN|PASSWORD|` +
	`API_KEY|APIKEY|CREDENTIAL|` +
	`PRIVATE_KEY|ACCESS_KEY|ENCRYPTION_KEY|SIGNING_KEY|LICENSE_KEY|` +
	`CLIENT_ID|` +
	`DB_PASS|DB_URL|DATABASE_URL|REDIS_URL|` +
	`_DSN|_SID|` +
	`ACCOUNT_ID|AUTH_KEY|MASTER_KEY|SERVICE_KEY`

// builtins returns the default pattern set.
// ORDER MATTERS: specific patterns first, generic catch-alls last.
func builtins() []*pattern {
	type def struct {
		name        string
		expr        string
		includesKey bool
	}

	raw := []def{
		// === Specific patterns (run first) — value only ===

		{"aws_access_key", `AKIA[0-9A-Z]{16}`, false},
		{"aws_secret_key", `(?i)aws[_\-]?secret[_\-]?access[_\-]?key\s*[=:]\s*[A-Za-z0-9/+=]{40}`, true},
		{"github_fine_grained", `github_pat_[A-Za-z0-9_]{22,}`, false},
		{"github_token", `gh[ps]_[A-Za-z0-9_]{36,}`, false},
		{"github_oauth", `gho_[A-Za-z0-9_]{36,}`, false},
		{"github_refresh", `ghr_[A-Za-z0-9_]{36,}`, false},
		{"stripe_live", `[srp]k_live_[A-Za-z0-9]{24,}`, false},
		{"stripe_test", `[srp]k_test_[A-Za-z0-9]{24,}`, false},
		{"twilio_api_key", `\bSK[0-9a-fA-F]{32}\b`, false},
		{"twilio_account_sid", `\bAC[0-9a-fA-F]{32}\b`, false},
		{"digitalocean_token", `dop_v1_[a-f0-9]{64}`, false},
		{"digitalocean_spaces", `(?i)SPACES_(ACCESS_KEY|SECRET_KEY)\s*[=:]\s*\S{8,}`, true},
		{"sentry_dsn", `https://[a-f0-9]{32}@[a-z0-9.\-]+\.ingest\.[a-z.]*sentry\.io/[0-9]+`, false},
		{"slack_token", `xox[bpars]-[A-Za-z0-9\-]{10,}`, false},
		{"sendgrid_key", `SG\.[A-Za-z0-9_\-]{22,}\.[A-Za-z0-9_\-]{22,}`, false},
		{"hubspot_key", `(?i)pat-[a-z0-9]{2,3}-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`, false},
		{"private_key", `-----BEGIN\s+(RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END\s+(RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`, false},
		{"jwt", `eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`, false},
		{"anthropic_key", `sk-ant-[A-Za-z0-9_-]{20,}`, false},
		{"circleci_token", `CCIPAT_[A-Za-z0-9]{20,}`, false},
		{"sentry_user_token", `sntryu_[A-Za-z0-9]{20,}`, false},
		{"rubygems_key", `rubygems_[A-Za-z0-9]{20,}`, false},
		{"newrelic_key", `NRAK-[A-Za-z0-9]{20,}`, false},
		{"database_url", `(?i)(postgres(?:ql)?|mysql|mongodb|mongodb\+srv|rediss?|amqps?)://[^\s"'` + "`" + `]+`, false},

		// === Generic catch-alls (run last) — include key name ===

		{"env_secret", `(?i)\b[A-Z0-9_]*(` + sensitiveKeywords + `)[A-Z0-9_]*\s*[=:]\s*[^\s\[][^\s]{7,}`, true},
		{"yaml_secret", `(?i)key:\s*[A-Z0-9_]*(` + sensitiveKeywords + `)[A-Z0-9_]*\s*\n\s*value:\s*[^\s\[][^\s]{7,}`, true},
	}

	patterns := make([]*pattern, 0, len(raw))
	for _, r := range raw {
		patterns = append(patterns, &pattern{
			Name:        r.name,
			Regex:       regexp.MustCompile(r.expr),
			includesKey: r.includesKey,
		})
	}
	return patterns
}

// defaultScrubber is the package-level scrubber for the convenience function.
var defaultScrubber = New()

// Scrub is a convenience function using default patterns.
// For custom patterns or whitelisting, use New() to create a Scrubber.
func Scrub(text string) Result {
	return defaultScrubber.Scrub(text)
}
