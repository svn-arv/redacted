package stats

import (
	"math"
	"path/filepath"
	"testing"
)

func TestRecordAndAggregate(t *testing.T) {
	t.Setenv("REDACTED_STATS_FILE", filepath.Join(t.TempDir(), "stats.jsonl"))

	Record("Bash", map[string]int{"jwt": 1, "secret_value": 2})
	Record("Read", map[string]int{"jwt": 1, "aws_access_key": 1})
	Record("Bash", nil)              // no-op: nothing redacted
	Record("Bash", map[string]int{}) // no-op: empty

	s, err := Aggregate()
	if err != nil {
		t.Fatal(err)
	}
	if s.Events != 2 {
		t.Errorf("Events = %d, want 2", s.Events)
	}
	if s.Total != 5 {
		t.Errorf("Total = %d, want 5", s.Total)
	}
	for name, want := range map[string]int{"jwt": 2, "secret_value": 2, "aws_access_key": 1} {
		if s.ByPattern[name] != want {
			t.Errorf("ByPattern[%q] = %d, want %d", name, s.ByPattern[name], want)
		}
	}
	tier := s.ByTier()
	if tier["vendor"] != 3 { // jwt(2) + aws_access_key(1)
		t.Errorf("vendor tier = %d, want 3", tier["vendor"])
	}
	if tier["heuristic"] != 2 { // secret_value(2)
		t.Errorf("heuristic tier = %d, want 2", tier["heuristic"])
	}
	// secret_value (2) of 5 = 0.4 low-confidence share, where FPs concentrate.
	if got := s.HeuristicShare(); math.Abs(got-0.4) > 1e-9 {
		t.Errorf("HeuristicShare = %v, want 0.4", got)
	}
}

func TestTier(t *testing.T) {
	for name, want := range map[string]string{
		"aws_access_key": "vendor",
		"jwt":            "vendor",
		"env_secret":     "keyword",
		"yaml_secret":    "keyword",
		"secret_value":   "heuristic",
	} {
		if got := Tier(name); got != want {
			t.Errorf("Tier(%q) = %q, want %q", name, got, want)
		}
	}
}

func TestAggregate_MissingFileIsEmpty(t *testing.T) {
	t.Setenv("REDACTED_STATS_FILE", filepath.Join(t.TempDir(), "absent.jsonl"))
	s, err := Aggregate()
	if err != nil {
		t.Fatalf("missing file should not error: %v", err)
	}
	if s.Events != 0 || s.Total != 0 {
		t.Errorf("want empty summary, got %+v", s)
	}
}
