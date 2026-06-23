package patterns

import "testing"

// WithHeuristic tunes the scorer per Scrubber: raising a threshold excludes a
// value the default scrubber would redact.
func TestWithHeuristic_RaiseMinLength(t *testing.T) {
	val := "FOO_CONF=Xy7aB3kQ9mZ2pL5nR8tW" // non-keyword key, 20-char secret-like value
	if !New().Scrub(val).Redacted {
		t.Fatal("default scrubber should redact the secret-like value")
	}
	if New(WithHeuristic(HeuristicConfig{MinLength: 50})).Scrub(val).Redacted {
		t.Error("min_length=50 should exclude a 20-char value")
	}
}

// A partial override changes only the named field; the rest keep their defaults.
func TestWithHeuristic_PartialOverridePreservesDefaults(t *testing.T) {
	// Override only entropy; the default min_length (16) must still reject a short value.
	s := New(WithHeuristic(HeuristicConfig{MinEntropy: 0.1}))
	if s.secretLike("Ab1") {
		t.Error("partial override zeroed min_length; short value wrongly scored secret-like")
	}
}
