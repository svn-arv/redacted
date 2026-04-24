package patterns

import (
	_ "embed"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

//go:embed patterns.yaml
var patternsYAML []byte

// patternDef mirrors a patterns.yaml entry.
type patternDef struct {
	Name        string `yaml:"name"`
	Regex       string `yaml:"regex"`
	IncludesKey bool   `yaml:"includes_key"`
}

// patternFile is the parsed shape of patterns.yaml.
type patternFile struct {
	ValueSafeChar string       `yaml:"value_safe_char"`
	Keywords      []string     `yaml:"keywords"`
	Patterns      []patternDef `yaml:"patterns"`
}

// config is the parsed patterns.yaml, loaded once at package init.
var config = func() patternFile {
	var pf patternFile
	if err := yaml.Unmarshal(patternsYAML, &pf); err != nil {
		panic("patterns.yaml: " + err.Error())
	}
	if pf.ValueSafeChar == "" {
		panic("patterns.yaml: value_safe_char is required")
	}
	return pf
}()

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
		// Insert before the env_secret + yaml_secret catch-alls.
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
		expr := envSecretRegex(strings.Join(keywords, "|"))
		s.patterns = append(s.patterns, &pattern{
			Name:        "custom_keyword",
			Regex:       regexp.MustCompile(expr),
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
			if p.includesKey && looksLikeIdentifier(valueOf(match)) {
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

// valueOf returns the right-hand side of a KEY=value or KEY: value match,
// mirroring how redact splits the key and value.
func valueOf(match string) string {
	for i, ch := range match {
		if ch == '=' || ch == ':' {
			return strings.TrimLeft(match[i+1:], " \t")
		}
	}
	return ""
}

// looksLikeIdentifier reports whether v is a plain snake_case or CONSTANT_CASE
// identifier — at least one underscore, only letters and underscores, and
// consistent casing (all lower or all upper). Values like `not_token`,
// `OTHER_TOKEN_CONST`, or `secret_key_var` match this shape; they're typically
// variable references in Ruby/Python/JS source code, not actual secrets, so
// skip redaction to avoid false positives in code.
func looksLikeIdentifier(v string) bool {
	if !strings.Contains(v, "_") {
		return false
	}
	hasLower, hasUpper := false, false
	for _, r := range v {
		switch {
		case r >= 'a' && r <= 'z':
			hasLower = true
		case r >= 'A' && r <= 'Z':
			hasUpper = true
		case r == '_':
		default:
			return false
		}
	}
	return (hasLower && !hasUpper) || (hasUpper && !hasLower)
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

// envSecretRegex builds the env_secret catch-all for a custom keyword alternation.
// Hyphens are treated as equivalent to underscores so http-style keys like
// `api-key=...` or `x-api-key: ...` are caught alongside `API_KEY=...`.
func envSecretRegex(keywords string) string {
	flex := strings.ReplaceAll(keywords, "_", `[_\-]`)
	return `(?i)\b[A-Z0-9_\-]*(` + flex + `)[A-Z0-9_\-]*\s*[=:]\s*` + config.ValueSafeChar + `{8,}`
}

// yamlSecretRegex builds the yaml_secret catch-all for a keyword alternation.
func yamlSecretRegex(keywords string) string {
	flex := strings.ReplaceAll(keywords, "_", `[_\-]`)
	return `(?i)key:\s*[A-Z0-9_\-]*(` + flex + `)[A-Z0-9_\-]*\s*\n\s*value:\s*` + config.ValueSafeChar + `{8,}`
}

// builtins returns the default pattern set loaded from patterns.yaml plus
// the dynamic env_secret and yaml_secret catch-alls derived from
// config.Keywords. ORDER MATTERS: specific patterns first, catch-alls last —
// if a specific pattern redacts a value, the catch-all won't re-match it.
func builtins() []*pattern {
	patterns := make([]*pattern, 0, len(config.Patterns)+2)

	for _, p := range config.Patterns {
		patterns = append(patterns, &pattern{
			Name:        p.Name,
			Regex:       regexp.MustCompile(p.Regex),
			includesKey: p.IncludesKey,
		})
	}

	kw := strings.Join(config.Keywords, "|")
	patterns = append(patterns,
		&pattern{Name: "env_secret", Regex: regexp.MustCompile(envSecretRegex(kw)), includesKey: true},
		&pattern{Name: "yaml_secret", Regex: regexp.MustCompile(yamlSecretRegex(kw)), includesKey: true},
	)
	return patterns
}

// defaultScrubber is the package-level scrubber for the convenience function.
var defaultScrubber = New()

// Scrub is a convenience function using default patterns.
// For custom patterns or whitelisting, use New() to create a Scrubber.
func Scrub(text string) Result {
	return defaultScrubber.Scrub(text)
}
