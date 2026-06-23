package cmd

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/svn-arv/redacted/internal/stats"
)

func TestRunStats_ReportsTotalsAndRisk(t *testing.T) {
	t.Setenv("REDACTED_STATS_FILE", filepath.Join(t.TempDir(), "stats.jsonl"))
	stats.Record("Bash", map[string]int{"secret_value": 3, "jwt": 1})

	var buf bytes.Buffer
	if err := runStats(&buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()

	// Behavior: the report surfaces the total, the false-positive-risk share, and
	// each pattern's confidence tier (secret_value 3 of 4 = 75%).
	for _, want := range []string{"4", "75%", "secret_value", "heuristic", "vendor"} {
		if !strings.Contains(out, want) {
			t.Errorf("report missing %q\n%s", want, out)
		}
	}
}

func TestRunStats_EmptyIsFriendly(t *testing.T) {
	t.Setenv("REDACTED_STATS_FILE", filepath.Join(t.TempDir(), "absent.jsonl"))

	var buf bytes.Buffer
	if err := runStats(&buf); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "No redactions") {
		t.Errorf("want friendly empty message, got %q", buf.String())
	}
}
