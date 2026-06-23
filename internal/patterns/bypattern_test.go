package patterns

import (
	"testing"

	"github.com/svn-arv/redacted/internal/testutil"
)

// TestScrub_ByPattern verifies Scrub reports a per-pattern redaction breakdown
// that sums to Count. This feeds the runtime stats (which patterns fire most).
func TestScrub_ByPattern(t *testing.T) {
	in := "log " + testutil.AWSAccessKey().Value +
		" and " + testutil.JWT().Value +
		" plus SECRET_KEY=" + testutil.RandAlphaNum(20)

	r := Scrub(in)

	want := map[string]int{"aws_access_key": 1, "jwt": 1, "env_secret": 1}
	for name, n := range want {
		if r.ByPattern[name] != n {
			t.Errorf("ByPattern[%q] = %d, want %d (full: %v)", name, r.ByPattern[name], n, r.ByPattern)
		}
	}

	sum := 0
	for _, n := range r.ByPattern {
		sum += n
	}
	if sum != r.Count {
		t.Errorf("sum(ByPattern) = %d, want Count = %d", sum, r.Count)
	}
}
