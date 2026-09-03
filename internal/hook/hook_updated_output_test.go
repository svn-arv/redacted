package hook

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/svn-arv/redacted/internal/testutil"
)

// decode runs Process over payload and returns the parsed hook response.
func decode(t *testing.T, payload []byte) Output {
	t.Helper()

	var out bytes.Buffer
	if err := Process(bytes.NewReader(payload), &out, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.Len() == 0 {
		t.Fatal("expected a redaction response, got empty output")
	}

	var response Output
	if err := json.Unmarshal(out.Bytes(), &response); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	return response
}

func updatedOutput(t *testing.T, response Output) string {
	t.Helper()

	if response.HookSpecificOutput == nil {
		t.Fatal("expected hookSpecificOutput to be set")
	}
	if response.HookSpecificOutput.UpdatedToolOutput == "" {
		t.Fatal("expected updatedToolOutput to be set: reason alone only annotates, it does not replace the result")
	}
	return response.HookSpecificOutput.UpdatedToolOutput
}

// updatedToolOutput replaces the tool result, so it must carry the whole
// scrubbed output. reason may summarize; the replacement may not.
func TestProcess_BashUpdatedOutputCarriesFullResult(t *testing.T) {
	stripe := testutil.StripeKey("sk_live_")
	input := Input{
		HookEventName: "PostToolUse",
		ToolName:      "Bash",
		ToolInput:     ToolInput{Command: "cat .env"},
		ToolResponse: ToolResponse{
			Stdout: "HEADER=keep-me\nSTRIPE_KEY=" + stripe.Value + "\nFOOTER=keep-me-too",
		},
	}

	payload, _ := json.Marshal(input)
	updated := updatedOutput(t, decode(t, payload))

	if strings.Contains(updated, stripe.Value) {
		t.Error("raw secret survived into updatedToolOutput")
	}
	if !strings.Contains(updated, "[REDACTED:stripe_live ") {
		t.Errorf("expected a redaction marker, got: %s", updated)
	}
	for _, keep := range []string{"HEADER=keep-me", "FOOTER=keep-me-too"} {
		if !strings.Contains(updated, keep) {
			t.Errorf("updatedToolOutput dropped clean line %q, got: %s", keep, updated)
		}
	}
}

// Only redacted stderr was ever appended to reason. As a replacement that
// silently deletes a clean stderr the model still needs.
func TestProcess_BashUpdatedOutputKeepsCleanStderr(t *testing.T) {
	stripe := testutil.StripeKey("sk_live_")
	input := Input{
		HookEventName: "PostToolUse",
		ToolName:      "Bash",
		ToolInput:     ToolInput{Command: "deploy"},
		ToolResponse: ToolResponse{
			Stdout: "KEY=" + stripe.Value,
			Stderr: "warning: retrying once",
		},
	}

	payload, _ := json.Marshal(input)
	updated := updatedOutput(t, decode(t, payload))

	if !strings.Contains(updated, "warning: retrying once") {
		t.Errorf("clean stderr dropped from the replacement result, got: %s", updated)
	}
}

// The split that matters: reason stays a summary of the redacted lines so the
// model is not handed a JSON blob, while updatedToolOutput keeps the response
// shape intact because it stands in for the result itself.
func TestProcess_StructuredUpdatedOutputPreservesShape(t *testing.T) {
	stripe := testutil.StripeKey("sk_live_")
	resp, _ := json.Marshal(map[string]any{
		"filePath": "/tmp/config.env",
		"content":  "HEADER=value\nSTRIPE_KEY=" + stripe.Value + "\nFOOTER=value",
		"type":     "create",
	})
	payload, _ := json.Marshal(map[string]any{
		"hook_event_name": "PostToolUse",
		"tool_name":       "Write",
		"tool_response":   json.RawMessage(resp),
	})

	response := decode(t, payload)
	updated := updatedOutput(t, response)

	if strings.Contains(response.Reason, `"filePath"`) {
		t.Error("reason should stay summarized, not carry raw JSON keys")
	}

	var shape map[string]any
	if err := json.Unmarshal([]byte(updated), &shape); err != nil {
		t.Fatalf("updatedToolOutput must stay valid JSON for a structured response: %v", err)
	}
	for _, key := range []string{"filePath", "content", "type"} {
		if _, ok := shape[key]; !ok {
			t.Errorf("updatedToolOutput dropped key %q, got: %s", key, updated)
		}
	}
	if shape["filePath"] != "/tmp/config.env" {
		t.Errorf("clean field mangled: %v", shape["filePath"])
	}

	content, _ := shape["content"].(string)
	if strings.Contains(content, stripe.Value) {
		t.Error("raw secret survived into updatedToolOutput")
	}
	if !strings.Contains(content, "[REDACTED:stripe_live ") {
		t.Errorf("expected a redaction marker in content, got: %s", content)
	}
	for _, keep := range []string{"HEADER=value", "FOOTER=value"} {
		if !strings.Contains(content, keep) {
			t.Errorf("updatedToolOutput dropped clean line %q, got: %s", keep, content)
		}
	}
}

// Nested arrays and objects must survive the walk, not just top-level strings.
func TestProcess_StructuredUpdatedOutputScrubsNestedLeaves(t *testing.T) {
	stripe := testutil.StripeKey("sk_live_")
	resp, _ := json.Marshal(map[string]any{
		"results": []map[string]any{
			{"title": "Unrelated", "snippet": "nothing sensitive here"},
			{"title": "Stripe docs", "snippet": "use STRIPE_KEY=" + stripe.Value},
		},
		"totalTokens": 100,
	})
	payload, _ := json.Marshal(map[string]any{
		"hook_event_name": "PostToolUse",
		"tool_name":       "WebSearch",
		"tool_response":   json.RawMessage(resp),
	})

	updated := updatedOutput(t, decode(t, payload))

	if strings.Contains(updated, stripe.Value) {
		t.Error("raw secret survived in a nested array element")
	}
	if !strings.Contains(updated, "nothing sensitive here") {
		t.Errorf("unrelated array element dropped, got: %s", updated)
	}
	if !strings.Contains(updated, `"totalTokens":100`) {
		t.Errorf("non-string leaf dropped, got: %s", updated)
	}
}

// HTML-bearing content is a live false-positive class, so the replacement must
// arrive as literal markup, not as Go's default < escapes.
func TestProcess_UpdatedOutputDoesNotEscapeHTML(t *testing.T) {
	stripe := testutil.StripeKey("sk_live_")
	resp, _ := json.Marshal(map[string]any{
		"content": "<span>KEY=" + stripe.Value + "</span>",
	})
	payload, _ := json.Marshal(map[string]any{
		"hook_event_name": "PostToolUse",
		"tool_name":       "Read",
		"tool_response":   json.RawMessage(resp),
	})

	updated := updatedOutput(t, decode(t, payload))

	for _, escape := range []string{`\u003c`, `\u003e`, `\u0026`} {
		if strings.Contains(updated, escape) {
			t.Errorf("markup arrived HTML-escaped as %s, got: %s", escape, updated)
		}
	}
	if !strings.Contains(updated, "<span>") {
		t.Errorf("expected literal markup, got: %s", updated)
	}
}

// A plain-string tool_response is already faithful text, so it replaces
// verbatim rather than as a quoted JSON string.
func TestProcess_StringResponseUpdatedOutputIsBareText(t *testing.T) {
	stripe := testutil.StripeKey("sk_live_")
	resp, _ := json.Marshal("HEADER\nSECRET_KEY=" + stripe.Value + "\nFOOTER")
	payload, _ := json.Marshal(map[string]any{
		"hook_event_name": "PostToolUse",
		"tool_name":       "Grep",
		"tool_response":   json.RawMessage(resp),
	})

	updated := updatedOutput(t, decode(t, payload))

	if strings.HasPrefix(updated, `"`) {
		t.Errorf("string response should replace as bare text, not a quoted JSON string: %s", updated)
	}
	if strings.Contains(updated, stripe.Value) {
		t.Error("raw secret survived into updatedToolOutput")
	}
	if !strings.Contains(updated, "HEADER") || !strings.Contains(updated, "FOOTER") {
		t.Errorf("clean lines dropped, got: %s", updated)
	}
}

// The fail-closed path is where raw output is most dangerous, so it must
// replace the result too, not just annotate it.
func TestWriteWithheld_SetsUpdatedToolOutput(t *testing.T) {
	var out bytes.Buffer
	writeWithheld(&out)

	var response Output
	if err := json.Unmarshal(out.Bytes(), &response); err != nil {
		t.Fatalf("failed to parse withheld response: %v", err)
	}

	updated := updatedOutput(t, response)
	if !strings.Contains(updated, "withheld") {
		t.Errorf("expected the withheld notice as the replacement result, got: %s", updated)
	}
}

// block plus reason is the existing annotation and stays: it is the only thing
// that shows up if a host ignores updatedToolOutput.
func TestProcess_KeepsBlockAndReasonAlongsideUpdatedOutput(t *testing.T) {
	input := Input{
		HookEventName: "PostToolUse",
		ToolName:      "Bash",
		ToolResponse:  ToolResponse{Stdout: "KEY=" + testutil.StripeKey("sk_live_").Value},
	}

	payload, _ := json.Marshal(input)
	response := decode(t, payload)

	if response.Decision != "block" {
		t.Errorf("expected decision=block, got %q", response.Decision)
	}
	if !strings.Contains(response.Reason, "[REDACTED:") {
		t.Errorf("expected redaction markers in reason, got: %s", response.Reason)
	}
	if response.HookSpecificOutput.HookEventName != "PostToolUse" {
		t.Errorf("expected hookEventName=PostToolUse, got %q", response.HookSpecificOutput.HookEventName)
	}
	_ = updatedOutput(t, response)
}
