package patterns

import (
	"regexp"
	"strings"
	"testing"
)

// A pattern with prefilter literals only runs its regex when a literal is
// present: matching input without any literal passes through untouched.
// Soundness of the engine.yml literals themselves is guarded by
// TestCorpus_Recall, which plants a real match for every pattern.
func TestApplyPattern_PrefilterGate(t *testing.T) {
	s := New()
	p := &pattern{
		Name:       "gated",
		Regex:      regexp.MustCompile(`zz[0-9]{4}`),
		prefilters: []string{"needle"},
	}

	in := "zz1234 without the literal"
	if out, n := s.applyPattern(p, in, ""); n != 0 || out != in {
		t.Errorf("prefilter absent: regex should not fire, got n=%d out=%q", n, out)
	}
	if _, n := s.applyPattern(p, "needle near zz1234", ""); n != 1 {
		t.Errorf("prefilter present: regex should fire once, got n=%d", n)
	}
}

// Fold prefilters gate case-insensitive patterns: the literal is matched
// against a lowercased copy of the text, so any casing of it lets the regex
// run and none of it skips the scan.
func TestScrub_FoldPrefilterGate(t *testing.T) {
	s := New()
	p := &pattern{
		Name:           "fold-gated",
		Regex:          regexp.MustCompile(`(?i)zz[0-9]{4}`),
		foldPrefilters: []string{"needle"},
	}
	s.patterns = []*pattern{p}

	if r := s.Scrub("zz1234 without the literal"); r.Redacted {
		t.Errorf("fold literal absent: regex should not fire, got %q", r.Text)
	}
	if r := s.Scrub("NeEdLe near zz1234"); !r.Redacted {
		t.Error("fold literal present in mixed case: regex should fire")
	}
}

// env_secret scans line-scoped (its matches never span lines), so mixed
// multi-line output must behave exactly as full-text scanning: every keyword
// line redacts, every other line survives byte-identical.
func TestScrub_LineScopedEnvAcrossLines(t *testing.T) {
	in := "On branch main\n" +
		"AUTH_TOKEN=Xk7Pq9mW2vB8nZ4c\n" +
		"const id = user.account_id\n" +
		"DB_PASSWORD: Zx9Kq2Lm8Pn4Rt6V\n" +
		"added 150 packages in 3s"
	r := Scrub(in)
	if r.Count < 2 {
		t.Fatalf("expected both keyword lines redacted, got %d: %q", r.Count, r.Text)
	}
	for _, survivor := range []string{"On branch main", "const id = user.account_id", "added 150 packages in 3s"} {
		if !strings.Contains(r.Text, survivor) {
			t.Errorf("non-secret line lost: %q missing from %q", survivor, r.Text)
		}
	}
}

// The keyword catch-alls derive fold literals from every keyword's snake,
// kebab and Pascal spellings, so all three key styles keep redacting.
func TestScrub_KeywordFoldVariantsStillRedact(t *testing.T) {
	for _, in := range []string{
		"API_KEY=Xk7Pq9mW2vB8nZ4c",
		"api-key: Xk7Pq9mW2vB8nZ4c",
		"apiKey: Xk7Pq9mW2vB8nZ4c",
	} {
		if r := Scrub(in); !r.Redacted {
			t.Errorf("expected redaction for %q, got: %q", in, r.Text)
		}
	}
}
