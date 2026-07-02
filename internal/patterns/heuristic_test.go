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

// Lowering min_length must also lower the candidate regex floor: the value
// regex is compiled per Scrubber from the effective threshold, not the
// embedded default, so a runtime override can widen detection too.
func TestWithHeuristic_LowerMinLength(t *testing.T) {
	val := "GADGET=aB3xK9pQ7mZ2" // 12-char, 3-class, high-entropy value
	if New().Scrub(val).Redacted {
		t.Fatal("default min_length=16 should leave a 12-char value alone")
	}
	if !New(WithHeuristic(HeuristicConfig{MinLength: 10})).Scrub(val).Redacted {
		t.Error("min_length=10 should redact a 12-char secret-like value")
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

// WithValueSafeChar swaps the catch-all value charset: narrowing it ends the
// value at the first excluded character, so a hyphenated token falls under
// the keyword tier's length floor.
func TestWithValueSafeChar(t *testing.T) {
	val := "TOKEN=abcd-efgh-1234"
	if !New().Scrub(val).Redacted {
		t.Fatal("default charset should redact the hyphenated keyword value")
	}
	if New(WithValueSafeChar(`[A-Za-z0-9]`)).Scrub(val).Redacted {
		t.Error("alnum-only charset should leave the hyphenated value under the floor")
	}
}
