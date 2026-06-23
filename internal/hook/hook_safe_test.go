package hook

import (
	"bytes"
	"strings"
	"testing"

	"github.com/svn-arv/redacted/internal/testutil"
)

func TestRecoverToError(t *testing.T) {
	if err := recoverToError(func() error { return nil }); err != nil {
		t.Errorf("clean fn returned error: %v", err)
	}
	if err := recoverToError(func() error { panic("boom") }); err == nil {
		t.Error("a panic must become an error, not propagate")
	}
}

// A scrub error must withhold the output (fail closed), never pass the raw,
// unscrubbed bytes through.
func TestProcessSafely_FailsClosedOnError(t *testing.T) {
	var out bytes.Buffer
	ProcessSafely(strings.NewReader(`{"tool_name":"Bash","tool_response":"not-an-object"}`), &out, nil)
	if !strings.Contains(out.String(), "withheld") {
		t.Errorf("expected a withheld block on error, got %q", out.String())
	}
}

func TestProcessSafely_PassesCleanThrough(t *testing.T) {
	var out bytes.Buffer
	ProcessSafely(strings.NewReader(`{"tool_name":"Bash","tool_response":{"stdout":"nothing secret","stderr":""}}`), &out, nil)
	if out.Len() != 0 {
		t.Errorf("clean output must pass through untouched, got %q", out.String())
	}
}

func TestProcessSafely_BlocksSecret(t *testing.T) {
	var out bytes.Buffer
	payload := `{"tool_name":"Bash","tool_response":{"stdout":"k ` + testutil.AWSAccessKey().Value + `","stderr":""}}`
	ProcessSafely(strings.NewReader(payload), &out, nil)
	if !strings.Contains(out.String(), "[REDACTED") {
		t.Errorf("expected a redaction block, got %q", out.String())
	}
}
