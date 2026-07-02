package patterns

import (
	_ "embed"
	"math"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

//go:embed engine.yml
var patternsYAML []byte

// patternDef mirrors an engine.yml entry.
type patternDef struct {
	Name        string `yaml:"name"`
	Regex       string `yaml:"regex"`
	IncludesKey bool   `yaml:"includes_key"`
}

// HeuristicConfig holds the secret_value scorer thresholds (see secretLike).
type HeuristicConfig struct {
	MinLength      int     `yaml:"min_length"`
	MaxLength      int     `yaml:"max_length"`
	MinCharClasses int     `yaml:"min_char_classes"`
	MinEntropy     float64 `yaml:"min_entropy"`
}

// patternFile is the parsed shape of engine.yml.
type patternFile struct {
	ValueSafeChar string          `yaml:"value_safe_char"`
	Heuristic     HeuristicConfig `yaml:"heuristic"`
	Keywords      []string        `yaml:"keywords"`
	Patterns      []patternDef    `yaml:"patterns"`
}

// config is the parsed engine.yml, loaded once at package init.
var config = func() patternFile {
	var pf patternFile
	if err := yaml.Unmarshal(patternsYAML, &pf); err != nil {
		panic("engine.yml: " + err.Error())
	}
	if pf.ValueSafeChar == "" {
		panic("engine.yml: value_safe_char is required")
	}
	// Fall back to safe defaults if the heuristic block is absent or partial,
	// so the scorer always has sane thresholds to work with.
	if pf.Heuristic.MinLength == 0 {
		pf.Heuristic.MinLength = 16
	}
	if pf.Heuristic.MaxLength == 0 {
		pf.Heuristic.MaxLength = 128
	}
	if pf.Heuristic.MinCharClasses == 0 {
		pf.Heuristic.MinCharClasses = 3
	}
	if pf.Heuristic.MinEntropy == 0 {
		pf.Heuristic.MinEntropy = 3.5
	}
	return pf
}()

// pattern pairs a name with a compiled regex.
type pattern struct {
	Name        string
	Regex       *regexp.Regexp
	includesKey bool // true if the regex matches KEY=value (not just the value)
	scored      bool // true if redaction is gated by the secretLike value scorer
}

// Option configures a Scrubber. This is the "functional options" pattern —
// each option is a function that modifies the Scrubber during construction.
type Option func(*Scrubber)

// Scrubber holds patterns and whitelist, and performs the actual redaction.
type Scrubber struct {
	patterns       []*pattern
	whitelist      map[string]bool // pattern names to skip
	allow          map[string]bool // variable names to never redact (case-insensitive keys)
	heuristic      HeuristicConfig // secret_value scorer thresholds
	valueSafeChar  string          // catch-all value charset (engine.yml value_safe_char)
	customKeywords [][]string      // WithKeywords batches, compiled after options run
}

// New creates a Scrubber with built-in defaults plus any options.
//
//	s := patterns.New()                                        // defaults only
//	s := patterns.New(patterns.WithExtra("slack_webhook", `https://hooks\.slack\.com/\S+`))
//	s := patterns.New(patterns.WithWhitelist("jwt", "stripe_test"))
func New(opts ...Option) *Scrubber {
	s := &Scrubber{
		patterns:      specificBuiltins(),
		whitelist:     make(map[string]bool),
		allow:         make(map[string]bool),
		heuristic:     config.Heuristic,
		valueSafeChar: config.ValueSafeChar,
	}
	for _, opt := range opts {
		opt(s)
	}
	// The catch-alls compile last so options can shape their regexes
	// (heuristic floor, value charset, custom keyword batches).
	s.appendCatchAlls()
	return s
}

// WithExtra adds a custom pattern. It runs BEFORE the generic catch-alls
// (appended after options run) but AFTER the built-in specific patterns.
func WithExtra(name, expr string) Option {
	return func(s *Scrubber) {
		s.patterns = append(s.patterns, &pattern{Name: name, Regex: regexp.MustCompile(expr)})
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
// Matches any KEY=value where KEY contains one of the given words. The
// pattern compiles after options run, so it picks up the effective charset.
//
//	patterns.New(patterns.WithKeywords("MONGO", "REDIS", "ELASTIC"))
func WithKeywords(keywords ...string) Option {
	return func(s *Scrubber) {
		if len(keywords) == 0 {
			return
		}
		s.customKeywords = append(s.customKeywords, keywords)
	}
}

// WithValueSafeChar swaps the character class catch-all values are built
// from. The class must be a valid regexp character class; it shapes the
// env/yaml/heuristic catch-alls and any WithKeywords patterns.
//
//	patterns.New(patterns.WithValueSafeChar(`[A-Za-z0-9_\-]`))
func WithValueSafeChar(class string) Option {
	return func(s *Scrubber) {
		if class != "" {
			s.valueSafeChar = class
		}
	}
}

// WithHeuristic overrides secret_value scorer thresholds; only non-zero fields
// override, the rest keep the engine.yml defaults.
func WithHeuristic(h HeuristicConfig) Option {
	return func(s *Scrubber) {
		if h.MinLength != 0 {
			s.heuristic.MinLength = h.MinLength
		}
		if h.MaxLength != 0 {
			s.heuristic.MaxLength = h.MaxLength
		}
		if h.MinCharClasses != 0 {
			s.heuristic.MinCharClasses = h.MinCharClasses
		}
		if h.MinEntropy != 0 {
			s.heuristic.MinEntropy = h.MinEntropy
		}
	}
}

// Result holds what Scrub found.
type Result struct {
	Redacted  bool           // true if any secret was replaced
	Text      string         // the scrubbed text
	Count     int            // how many replacements
	ByPattern map[string]int // pattern name -> redaction count (nil if none)
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
// The original separator (`=` or `:`) is preserved so Ruby hash literals,
// YAML, and other key:value syntaxes don't get corrupted by the rewrite.
func redact(name, match string, includesKey bool) string {
	if includesKey {
		for i, ch := range match {
			if ch == '=' || ch == ':' {
				key := match[:i]
				sep := string(ch)
				value := strings.TrimLeft(match[i+1:], " \t")
				// Preserve any whitespace that sat between the key and sep
				// so `KEY = value` and `KEY: value` round-trip cleanly.
				trailingWS := ""
				trimmedKey := strings.TrimRight(key, " \t")
				if len(trimmedKey) < len(key) {
					trailingWS = key[len(trimmedKey):]
				}
				hint := tail(value, 4)
				return trimmedKey + trailingWS + sep + " [REDACTED ..." + hint + "]"
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
	var byPattern map[string]int
	out := text
	for _, p := range s.patterns {
		if s.whitelist[p.Name] {
			continue
		}
		var n int
		out, n = s.applyPattern(p, out)
		if n > 0 {
			if byPattern == nil {
				byPattern = make(map[string]int)
			}
			byPattern[p.Name] += n
		}
		count += n
	}

	return Result{
		Redacted:  count > 0,
		Text:      out,
		Count:     count,
		ByPattern: byPattern,
	}
}

// applyPattern redacts every match of p in text that isn't skipped, returning
// the rewritten text and the number of redactions made.
func (s *Scrubber) applyPattern(p *pattern, text string) (string, int) {
	locs := p.Regex.FindAllStringIndex(text, -1)
	if locs == nil {
		return text, 0
	}
	var b strings.Builder
	last, count := 0, 0
	for _, loc := range locs {
		start, end := loc[0], loc[1]
		b.WriteString(text[last:start])
		last = end
		match := text[start:end]
		if s.skipMatch(p, match, text, end) {
			b.WriteString(match)
			continue
		}
		b.WriteString(redact(p.Name, match, p.includesKey))
		count++
	}
	b.WriteString(text[last:])
	return b.String(), count
}

// skipMatch reports whether a candidate match should be left unredacted. end is
// the match's offset in text, used to inspect the character that follows it.
func (s *Scrubber) skipMatch(p *pattern, match, text string, end int) bool {
	if s.isAllowed(match) {
		return true
	}
	if !p.includesKey {
		return false
	}
	// A value immediately followed by `(` or `[` is a method call or index
	// access — source code, not a literal secret.
	if end < len(text) && (text[end] == '(' || text[end] == '[') {
		return true
	}
	// Skip source-code references; the heuristic catch-all additionally requires
	// the value to score as secret-like.
	value := valueOf(match)
	// A value that just re-states its own key (`password: password`) is a
	// keyword-arg echo passing a same-named variable, not a literal secret.
	// Quotes and the `=>` remnant are stripped before comparing.
	if key := keyOf(match); key != "" &&
		strings.EqualFold(key, strings.Trim(strings.TrimLeft(value, "> \t"), `"'`)) {
		return true
	}
	if looksLikeIdentifier(value) || looksLikeCodeReference(value) {
		return true
	}
	// Keys that name identifiers (tool_use_id, sessionId) hold IDs, not
	// credentials; only the scored catch-all skips them, so keyword keys
	// like CLIENT_ID keep their env_secret coverage.
	if p.scored && isIdentifierKey(keyOf(match)) {
		return true
	}
	// A scored match whose token already carries a scheme sits inside a URL:
	// host:port/Path parses as KEY:value but is address, not secret. Keyword
	// keys with URL values stay covered by env_secret.
	if p.scored && insideURL(text, end-len(match)) {
		return true
	}
	return p.scored && !s.secretLike(value)
}

// urlLookback caps how far insideURL walks; a scheme further back than this
// inside one unbroken token is out of scope, and the cap bounds scan cost.
const urlLookback = 2048

// insideURL reports whether the token containing offset start begins with a
// URL scheme: the characters from the previous token boundary up to start
// contain "://".
func insideURL(text string, start int) bool {
	i := start
	for i > 0 && start-i < urlLookback && !isTokenBoundary(text[i-1]) {
		i--
	}
	return strings.Contains(text[i:start], "://")
}

// isTokenBoundary reports whether c ends a token for insideURL's walk-back:
// whitespace, quotes, and the bracket/separator set value_safe_char excludes.
func isTokenBoundary(c byte) bool {
	switch c {
	case ' ', '\t', '\n', '\r', '"', '\'', '`', '(', ')', '[', ']', '{', '}', '<', '>', ',', ';':
		return true
	}
	return false
}

// isIdentifierKey reports whether key names an identifier rather than a
// credential: `id`/`uuid` alone, a `_id`/`-id` style suffix, or a camelCase
// `Id`/`Uuid` tail. A plain lowercase tail (`liquid`) is not a boundary.
func isIdentifierKey(key string) bool {
	k := strings.ToLower(key)
	if k == "id" || k == "uuid" {
		return true
	}
	for _, suf := range []string{"_id", "-id", "_uuid", "-uuid"} {
		if strings.HasSuffix(k, suf) {
			return true
		}
	}
	return strings.HasSuffix(key, "Id") || strings.HasSuffix(key, "Uuid")
}

// keyOf returns the left-hand side of a KEY=value or KEY: value match with
// quotes and padding trimmed, mirroring valueOf; "" when no separator exists.
func keyOf(match string) string {
	for i, ch := range match {
		if ch == '=' || ch == ':' {
			return strings.Trim(strings.TrimRight(match[:i], " \t"), `"'`)
		}
	}
	return ""
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

// looksLikeIdentifier reports whether v looks like a source-code identifier
// or method/attribute access path: only letters with `_` and/or `.` as
// separators, at least one separator present, and consistent casing (all
// lower or all upper). Values like `not_token`, `OTHER_TOKEN_CONST`,
// `credit_account.id`, or `obj.attr` match this shape; they're typically
// variable references or method calls in Ruby/Python/JS source code, not
// actual secrets, so skip redaction to avoid false positives in code.
func looksLikeIdentifier(v string) bool {
	hasLower, hasUpper, hasSeparator := false, false, false
	for _, r := range v {
		switch {
		case r >= 'a' && r <= 'z':
			hasLower = true
		case r >= 'A' && r <= 'Z':
			hasUpper = true
		case r == '_' || r == '.':
			hasSeparator = true
		default:
			return false
		}
	}
	if !hasSeparator {
		return false
	}
	return (hasLower && !hasUpper) || (hasUpper && !hasLower)
}

// looksLikeCodeReference reports whether v is a mixed-case code path joined by
// `.` or `::`, like `ENV.fetch` or `MyApp::Config` — a reference, not a literal.
// The mixed casing keeps single-case values (e.g. `abc.def.ghi123`) redactable.
func looksLikeCodeReference(v string) bool {
	hasSep, hasLower, hasUpper := false, false, false
	for _, r := range v {
		switch {
		case r >= 'a' && r <= 'z':
			hasLower = true
		case r >= 'A' && r <= 'Z':
			hasUpper = true
		case r >= '0' && r <= '9', r == '_':
			// Allowed inside an identifier segment.
		case r == '.', r == ':':
			hasSep = true
		default:
			// Quotes, brackets, slashes: not a plain identifier path.
			return false
		}
	}
	return hasSep && hasLower && hasUpper
}

// secretLike reports whether v looks like a random credential. Requiring lower,
// upper, and digit together is what lets UUIDs, hashes, and timestamps through.
func (s *Scrubber) secretLike(v string) bool {
	h := s.heuristic

	// A value containing "://" is a URL, not a credential (credentialed URLs are caught earlier).
	if strings.Contains(v, "://") {
		return false
	}

	length := utf8.RuneCountInString(v)
	if length < h.MinLength || length > h.MaxLength {
		return false
	}

	var hasLower, hasUpper, hasDigit bool
	for _, r := range v {
		switch {
		case r >= 'a' && r <= 'z':
			hasLower = true
		case r >= 'A' && r <= 'Z':
			hasUpper = true
		case r >= '0' && r <= '9':
			hasDigit = true
		}
	}
	classes := 0
	for _, present := range []bool{hasLower, hasUpper, hasDigit} {
		if present {
			classes++
		}
	}
	if classes < h.MinCharClasses {
		return false
	}

	return shannonEntropy(v) >= h.MinEntropy
}

// shannonEntropy returns the entropy of s in bits per character: high for random
// strings (many, evenly-spread characters), low for repetitive or structured ones.
func shannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}

	counts := make(map[rune]int)
	total := 0
	for _, r := range s {
		counts[r]++
		total++
	}

	var entropy float64
	for _, count := range counts {
		probability := float64(count) / float64(total)
		entropy -= probability * math.Log2(probability)
	}
	return entropy
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

// envSecretRegex builds the env_secret catch-all. Two arms enforce a real
// word boundary on the keyword:
//
//  1. snake/kebab: prefix/suffix must touch `_` or `-` (case-insensitive).
//  2. PascalCase: prefix ends in lowercase, keyword is matched case-sensitive
//     so the uppercase transition (e.g. `Account|Sid`) is what proves the
//     boundary — keeps `Tasid`/`Presidential` out.
//
// Separator is `=`, `:`, or Ruby/PHP/Perl `=>`. Optional `"`/`'` on either
// side accommodates quoted keys/values in Ruby/JSON/Python/PHP.
//
// Whitespace around the separator is space/tab only — otherwise an empty
// `KEY=\nNEXT_KEY=...` would match across the newline.
func envSecretRegex(keywords, safeChar string) string {
	flex := strings.ReplaceAll(keywords, "_", `[_\-]`)
	cap := capitalizeAll(keywords)
	snakeOrKebab := `(?:[A-Z0-9_\-]*[_\-])?(?:` + flex + `)(?:[_\-][A-Z0-9_\-]*)?`
	camelOrPascal := `(?-i:[a-zA-Z0-9]*[a-z])?(?-i:` + cap + `)(?-i:[A-Z][a-zA-Z0-9]*)?`
	return `(?i)\b(?:` + snakeOrKebab + `|` + camelOrPascal + `)` +
		`["']?[ \t]*(?:=>?|:)[ \t]*["']?` + safeChar + `{8,}`
}

// excludeSlash adds `/` to a negated class (`[^…]` -> `[^…/]`), or returns it
// unchanged if not negated.
func excludeSlash(class string) string {
	if strings.HasPrefix(class, "[^") && strings.HasSuffix(class, "]") {
		return class[:len(class)-1] + `/]`
	}
	return class
}

// heuristicAssignmentRegex matches KEY=value (value >= minLength chars), scored
// by secretLike. The value can't begin with "/" so a URL scheme isn't read as
// one. minLength comes from the Scrubber so runtime overrides can lower the
// floor below the embedded default.
func heuristicAssignmentRegex(minLength int, safeChar string) string {
	if minLength < 1 {
		minLength = 1
	}
	key := `[A-Za-z0-9_\-]*[A-Za-z][A-Za-z0-9_\-]*`
	rest := strconv.Itoa(minLength - 1)
	return `(?i)\b` + key + `["']?[ \t]*(?:=>?|:)[ \t]*["']?` +
		excludeSlash(safeChar) + safeChar + `{` + rest + `,}`
}

func capitalizeAll(keywords string) string {
	parts := strings.Split(keywords, "|")
	for i, p := range parts {
		parts[i] = capitalizeKeyword(p)
	}
	return strings.Join(parts, "|")
}

// capitalizeKeyword: `_SID` -> `Sid`, `API_KEY` -> `ApiKey`.
func capitalizeKeyword(kw string) string {
	kw = strings.TrimLeft(kw, "_-")
	var b strings.Builder
	upperNext := true
	for _, r := range kw {
		if r == '_' || r == '-' {
			upperNext = true
			continue
		}
		if upperNext {
			b.WriteRune(unicode.ToUpper(r))
			upperNext = false
		} else {
			b.WriteRune(unicode.ToLower(r))
		}
	}
	return b.String()
}

// yamlSecretRegex builds the yaml_secret catch-all for a keyword alternation.
// The middle `\s*\n\s*` is intentional — it spans the key line to the value
// line. The leading and trailing whitespace are space/tab only so the keyword
// stays on the `key:` line and the value stays on the `value:` line.
func yamlSecretRegex(keywords, safeChar string) string {
	flex := strings.ReplaceAll(keywords, "_", `[_\-]`)
	return `(?i)key:[ \t]*[A-Z0-9_\-]*(` + flex + `)[A-Z0-9_\-]*\s*\n\s*value:[ \t]*` + safeChar + `{8,}`
}

// specificBuiltins compiles the engine.yml pattern set. The catch-alls are
// appended by New after options run, so per-Scrubber charset and thresholds
// shape their regexes.
func specificBuiltins() []*pattern {
	patterns := make([]*pattern, 0, len(config.Patterns)+3)

	for _, p := range config.Patterns {
		patterns = append(patterns, &pattern{
			Name:        p.Name,
			Regex:       regexp.MustCompile(p.Regex),
			includesKey: p.IncludesKey,
		})
	}
	return patterns
}

// appendCatchAlls compiles and appends the env_secret, yaml_secret and
// secret_value catch-alls plus any custom keyword batches. Order matters:
// specific first, heuristic fallback last, custom keywords after (matching
// WithKeywords' historical position).
func (s *Scrubber) appendCatchAlls() {
	kw := strings.Join(config.Keywords, "|")
	s.patterns = append(s.patterns,
		&pattern{Name: "env_secret", Regex: regexp.MustCompile(envSecretRegex(kw, s.valueSafeChar)), includesKey: true},
		&pattern{Name: "yaml_secret", Regex: regexp.MustCompile(yamlSecretRegex(kw, s.valueSafeChar)), includesKey: true},
		&pattern{Name: "secret_value", Regex: regexp.MustCompile(heuristicAssignmentRegex(s.heuristic.MinLength, s.valueSafeChar)), includesKey: true, scored: true},
	)
	for _, batch := range s.customKeywords {
		expr := envSecretRegex(strings.Join(batch, "|"), s.valueSafeChar)
		s.patterns = append(s.patterns, &pattern{
			Name:        "custom_keyword",
			Regex:       regexp.MustCompile(expr),
			includesKey: true,
		})
	}
}

// defaultScrubber is the package-level scrubber for the convenience function.
var defaultScrubber = New()

// Scrub is a convenience function using default patterns.
// For custom patterns or whitelisting, use New() to create a Scrubber.
func Scrub(text string) Result {
	return defaultScrubber.Scrub(text)
}
