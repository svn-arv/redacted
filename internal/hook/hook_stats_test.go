package hook

import (
	"bytes"
	"testing"

	"github.com/svn-arv/redacted/internal/testutil"
)

// TestProcess_RecordsWhatItRedacted checks the hook reports the pattern that
// fired, so stats reflect real redactions.
func TestProcess_RecordsWhatItRedacted(t *testing.T) {
	var gotTool string
	var gotCounts map[string]int
	Recorder = func(tool string, byPattern map[string]int) {
		gotTool, gotCounts = tool, byPattern
	}
	t.Cleanup(func() { Recorder = nil })

	payload := `{"tool_name":"Bash","tool_response":{"stdout":"key ` + testutil.AWSAccessKey().Value + `","stderr":""}}`
	var out bytes.Buffer
	if err := Process(bytes.NewReader([]byte(payload)), &out, nil); err != nil {
		t.Fatal(err)
	}

	if gotTool != "Bash" {
		t.Errorf("tool = %q, want Bash", gotTool)
	}
	if gotCounts["aws_access_key"] != 1 {
		t.Errorf("aws_access_key = %d, want 1 (full: %v)", gotCounts["aws_access_key"], gotCounts)
	}
}

// TestProcess_NoRecordWhenClean checks nothing is recorded when no secret is
// found — clean runs must not inflate the stats.
func TestProcess_NoRecordWhenClean(t *testing.T) {
	called := false
	Recorder = func(string, map[string]int) { called = true }
	t.Cleanup(func() { Recorder = nil })

	payload := `{"tool_name":"Bash","tool_response":{"stdout":"nothing secret here","stderr":""}}`
	var out bytes.Buffer
	if err := Process(bytes.NewReader([]byte(payload)), &out, nil); err != nil {
		t.Fatal(err)
	}
	if called {
		t.Error("recorder called on clean output")
	}
}
