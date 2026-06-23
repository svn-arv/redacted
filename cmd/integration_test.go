package cmd

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/svn-arv/redacted/internal/hook"
	"github.com/svn-arv/redacted/internal/stats"
	"github.com/svn-arv/redacted/internal/testutil"
)

// End-to-end: the scrub path wires the hook Recorder to stats.Record, so a
// redaction must land in the stats log and aggregate back out.
func TestHookStatsWiring(t *testing.T) {
	t.Setenv("REDACTED_STATS_FILE", filepath.Join(t.TempDir(), "stats.jsonl"))
	hook.Recorder = stats.Record
	t.Cleanup(func() { hook.Recorder = nil })

	payload := `{"tool_name":"Bash","tool_response":{"stdout":"k ` + testutil.AWSAccessKey().Value + `","stderr":""}}`
	var out bytes.Buffer
	hook.ProcessSafely(strings.NewReader(payload), &out, nil)

	s, err := stats.Aggregate()
	if err != nil {
		t.Fatal(err)
	}
	if s.ByPattern["aws_access_key"] != 1 {
		t.Errorf("redaction did not reach stats: %v", s.ByPattern)
	}
	if s.Total != 1 || s.Events != 1 {
		t.Errorf("Total=%d Events=%d, want 1/1", s.Total, s.Events)
	}
}
