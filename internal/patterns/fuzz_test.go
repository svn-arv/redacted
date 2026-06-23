package patterns

import "testing"

// FuzzScrub asserts Scrub never panics on arbitrary input and keeps its
// accounting consistent. The seeds also run under plain `go test`.
func FuzzScrub(f *testing.F) {
	seeds := []string{
		"",
		"nothing to see here",
		"TOKEN=abc",
		"https://github.com/org/repo/issues/1",
		"postgres://u:p@h:5432/db",
		"key: value\nother: thing",
		"AKIA================",
		"::::////@@@@",
		"a=" + "Xy7" + "0123456789012345",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, in string) {
		r := Scrub(in) // must not panic

		sum := 0
		for _, n := range r.ByPattern {
			sum += n
		}
		if sum != r.Count {
			t.Errorf("ByPattern sums to %d, want Count %d, input %q", sum, r.Count, in)
		}
		if r.Redacted != (r.Count > 0) {
			t.Errorf("Redacted=%v but Count=%d, input %q", r.Redacted, r.Count, in)
		}
		if !r.Redacted && r.Text != in {
			t.Errorf("clean input mutated: %q -> %q", in, r.Text)
		}
	})
}
