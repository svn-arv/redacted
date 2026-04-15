package hook

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/svn-arv/redacted/internal/testutil"
)

func TestProcess_CleanOutput(t *testing.T) {
	input := Input{
		HookEventName: "PostToolUse",
		ToolName:      "Bash",
		ToolInput:     ToolInput{Command: "ls -la"},
		ToolResponse: ToolResponse{
			ExitCode: 0,
			Stdout:   "total 8\ndrwxr-xr-x 2 user user 4096 Jan 1 00:00 .\n",
			Stderr:   "",
		},
	}

	payload, _ := json.Marshal(input)
	var out bytes.Buffer

	err := Process(bytes.NewReader(payload), &out, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if out.Len() != 0 {
		t.Errorf("expected empty output for clean text, got: %s", out.String())
	}
}

func TestProcess_RedactsStdout(t *testing.T) {
	stripe := testutil.StripeKey("sk_live_")
	dbURL := testutil.DatabaseURL("postgres", "admin", testutil.RandAlphaNum(8), "db.example.com", "5432", "prod")

	input := Input{
		HookEventName: "PostToolUse",
		ToolName:      "Bash",
		ToolInput:     ToolInput{Command: "cat .env"},
		ToolResponse: ToolResponse{
			ExitCode: 0,
			Stdout:   "SECRET_KEY=" + stripe.Value + "\nDATABASE_URL=" + dbURL.Value,
			Stderr:   "",
		},
	}

	payload, _ := json.Marshal(input)
	var out bytes.Buffer

	err := Process(bytes.NewReader(payload), &out, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if out.Len() == 0 {
		t.Fatal("expected redacted response, got empty output")
	}

	var response Output
	if err := json.Unmarshal(out.Bytes(), &response); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if response.Decision != "block" {
		t.Errorf("expected decision=block, got %q", response.Decision)
	}
	if !strings.Contains(response.Reason, "[REDACTED:") {
		t.Errorf("expected redaction markers in reason, got: %s", response.Reason)
	}
	if strings.Contains(response.Reason, stripe.Value) {
		t.Error("secret key leaked through redaction")
	}
}

func TestProcess_RedactsStderr(t *testing.T) {
	dbURL := testutil.DatabaseURL("postgres", "admin", testutil.RandAlphaNum(8), "db.example.com", "5432", "prod")

	input := Input{
		HookEventName: "PostToolUse",
		ToolName:      "Bash",
		ToolInput:     ToolInput{Command: "some-command"},
		ToolResponse: ToolResponse{
			ExitCode: 1,
			Stdout:   "normal output",
			Stderr:   "error: connection to " + dbURL.Value + " failed",
		},
	}

	payload, _ := json.Marshal(input)
	var out bytes.Buffer

	err := Process(bytes.NewReader(payload), &out, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if out.Len() == 0 {
		t.Fatal("expected redacted response for secret in stderr")
	}

	var response Output
	if err := json.Unmarshal(out.Bytes(), &response); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if response.Decision != "block" {
		t.Errorf("expected decision=block, got %q", response.Decision)
	}
	if !strings.Contains(response.Reason, "[stderr]") {
		t.Error("expected [stderr] section in reason")
	}
}

func TestProcess_BothStdoutAndStderrSecrets(t *testing.T) {
	stripe := testutil.StripeKey("sk_live_")
	dbURL := testutil.DatabaseURL("postgres", "u", "p", "h", "5432", "d")

	input := Input{
		HookEventName: "PostToolUse",
		ToolName:      "Bash",
		ToolInput:     ToolInput{Command: "deploy"},
		ToolResponse: ToolResponse{
			ExitCode: 1,
			Stdout:   "STRIPE_KEY=" + stripe.Value,
			Stderr:   "DB=" + dbURL.Value,
		},
	}

	payload, _ := json.Marshal(input)
	var out bytes.Buffer

	err := Process(bytes.NewReader(payload), &out, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var response Output
	json.Unmarshal(out.Bytes(), &response)

	if !strings.Contains(response.Reason, "[REDACTED:stripe_live ") {
		t.Error("stdout secret not redacted")
	}
	if !strings.Contains(response.Reason, "[REDACTED:database_url ") {
		t.Error("stderr secret not redacted")
	}
	if !strings.Contains(response.Reason, "[stderr]") {
		t.Error("expected [stderr] section")
	}
}

func TestProcess_ScrubsNonBashTools(t *testing.T) {
	tools := []string{"Read", "Grep", "WebFetch"}

	for _, tool := range tools {
		t.Run(tool, func(t *testing.T) {
			stripe := testutil.StripeKey("sk_live_")
			// Non-Bash tools have a generic tool_response (JSON string)
			resp, _ := json.Marshal("SECRET_KEY=" + stripe.Value)
			payload, _ := json.Marshal(map[string]any{
				"hook_event_name": "PostToolUse",
				"tool_name":      tool,
				"tool_response":  json.RawMessage(resp),
			})

			var out bytes.Buffer
			err := Process(bytes.NewReader(payload), &out, nil)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if out.Len() == 0 {
				t.Fatalf("expected redacted response for %s tool, got empty output", tool)
			}

			var response Output
			json.Unmarshal(out.Bytes(), &response)

			if response.Decision != "block" {
				t.Errorf("expected decision=block, got %q", response.Decision)
			}
			if !strings.Contains(response.Reason, "[REDACTED:") {
				t.Errorf("expected redaction markers in reason, got: %s", response.Reason)
			}
			if strings.Contains(response.Reason, stripe.Value) {
				t.Error("secret leaked through redaction")
			}
		})
	}
}

func TestProcess_NonBashCleanOutput(t *testing.T) {
	resp, _ := json.Marshal("just normal file content, nothing secret here")
	payload, _ := json.Marshal(map[string]any{
		"hook_event_name": "PostToolUse",
		"tool_name":      "Read",
		"tool_response":  json.RawMessage(resp),
	})

	var out bytes.Buffer
	err := Process(bytes.NewReader(payload), &out, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if out.Len() != 0 {
		t.Errorf("expected pass-through for clean Read output, got: %s", out.String())
	}
}

func TestProcess_NonBashObjectResponse(t *testing.T) {
	// Some tools return JSON objects, not strings
	stripe := testutil.StripeKey("sk_live_")
	resp, _ := json.Marshal(map[string]string{
		"content": "KEY=" + stripe.Value,
	})
	payload, _ := json.Marshal(map[string]any{
		"hook_event_name": "PostToolUse",
		"tool_name":      "WebFetch",
		"tool_response":  json.RawMessage(resp),
	})

	var out bytes.Buffer
	err := Process(bytes.NewReader(payload), &out, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if out.Len() == 0 {
		t.Fatal("expected redacted response for object with secret")
	}

	var response Output
	json.Unmarshal(out.Bytes(), &response)

	if strings.Contains(response.Reason, stripe.Value) {
		t.Error("secret leaked through redaction")
	}
}

func TestProcess_InvalidJSON(t *testing.T) {
	var out bytes.Buffer
	err := Process(strings.NewReader("not json at all"), &out, nil)

	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
	if !strings.Contains(err.Error(), "parse hook payload") {
		t.Errorf("expected parse error, got: %v", err)
	}
}

func TestProcess_EmptyStdout(t *testing.T) {
	input := Input{
		HookEventName: "PostToolUse",
		ToolName:      "Bash",
		ToolInput:     ToolInput{Command: "true"},
		ToolResponse: ToolResponse{
			ExitCode: 0,
			Stdout:   "",
			Stderr:   "",
		},
	}

	payload, _ := json.Marshal(input)
	var out bytes.Buffer

	err := Process(bytes.NewReader(payload), &out, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if out.Len() != 0 {
		t.Errorf("expected pass-through for empty output, got: %s", out.String())
	}
}

func TestProcess_ResponseHasCorrectHookEventName(t *testing.T) {
	aws := testutil.AWSAccessKey()

	input := Input{
		HookEventName: "PostToolUse",
		ToolName:      "Bash",
		ToolResponse: ToolResponse{
			Stdout: aws.Value,
		},
	}

	payload, _ := json.Marshal(input)
	var out bytes.Buffer

	Process(bytes.NewReader(payload), &out, nil)

	var response Output
	json.Unmarshal(out.Bytes(), &response)

	if response.HookSpecificOutput == nil {
		t.Fatal("expected hookSpecificOutput to be set")
	}
	if response.HookSpecificOutput.HookEventName != "PostToolUse" {
		t.Errorf("expected hookEventName=PostToolUse, got %q", response.HookSpecificOutput.HookEventName)
	}
}

func TestProcess_EditToolFormatsCleanly(t *testing.T) {
	stripe := testutil.StripeKey("sk_live_")

	// Edit tool_response is an object with oldString/newString/originalFile
	resp, _ := json.Marshal(map[string]string{
		"filePath":     "/tmp/test.rb",
		"oldString":    "line1\nSTRIPE_KEY=" + stripe.Value + "\nline3",
		"newString":    "line1\nSTRIPE_KEY=new_value\nline3",
		"originalFile": "header\nline1\nSTRIPE_KEY=" + stripe.Value + "\nline3\nfooter",
	})
	payload, _ := json.Marshal(map[string]any{
		"hook_event_name": "PostToolUse",
		"tool_name":       "Edit",
		"tool_response":   json.RawMessage(resp),
	})

	var out bytes.Buffer
	err := Process(bytes.NewReader(payload), &out, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if out.Len() == 0 {
		t.Fatal("expected redacted response for Edit with secret")
	}

	var response Output
	json.Unmarshal(out.Bytes(), &response)

	if response.Decision != "block" {
		t.Errorf("expected decision=block, got %q", response.Decision)
	}
	if strings.Contains(response.Reason, stripe.Value) {
		t.Error("secret leaked through Edit redaction")
	}
	// The output should NOT contain the raw JSON blob with filePath/oldString keys
	if strings.Contains(response.Reason, `"filePath"`) {
		t.Error("output contains raw JSON keys - should show summarized lines, not JSON blob")
	}
	// Should only show lines that have [REDACTED markers
	if strings.Contains(response.Reason, "header") || strings.Contains(response.Reason, "footer") {
		t.Error("output contains non-redacted lines from originalFile")
	}
}

// structuredLeakCase describes a tool_response shape that historically
// leaked unrelated fields through the hook block reason. Each case wires
// up a real secret and a few surrounding keys/values we expect to stay
// out of the reason body.
type structuredLeakCase struct {
	name          string
	toolName      string
	response      any
	forbiddenKeys []string // raw JSON keys that must not appear in the reason
	forbiddenText []string // surrounding values that must not appear in the reason
}

func TestProcess_StructuredResponsesDoNotLeak(t *testing.T) {
	stripe := testutil.StripeKey("sk_live_")
	secret := stripe.Value

	cases := []structuredLeakCase{
		{
			name:     "MultiEdit",
			toolName: "MultiEdit",
			response: map[string]any{
				"filePath": "/tmp/app.rb",
				"edits": []map[string]string{
					{
						"old_string": "STRIPE_KEY=" + secret,
						"new_string": "STRIPE_KEY=placeholder",
					},
				},
				"originalFile": "top\nSTRIPE_KEY=" + secret + "\nbottom",
			},
			forbiddenKeys: []string{`"filePath"`, `"edits"`, `"originalFile"`, `"old_string"`, `"new_string"`},
			forbiddenText: []string{"/tmp/app.rb", "top", "bottom"},
		},
		{
			name:     "Write",
			toolName: "Write",
			response: map[string]any{
				"filePath": "/tmp/config.env",
				"content":  "HEADER=value\nSTRIPE_KEY=" + secret + "\nFOOTER=value",
				"type":     "create",
			},
			forbiddenKeys: []string{`"filePath"`, `"content"`, `"type"`},
			forbiddenText: []string{"/tmp/config.env", "HEADER", "FOOTER"},
		},
		{
			name:     "TodoWrite",
			toolName: "TodoWrite",
			response: map[string]any{
				"todos": []map[string]string{
					{
						"content":    "deploy with STRIPE_KEY=" + secret,
						"status":     "pending",
						"activeForm": "deploying service",
					},
					{
						"content":    "write docs",
						"status":     "completed",
						"activeForm": "writing docs",
					},
				},
			},
			forbiddenKeys: []string{`"todos"`, `"activeForm"`, `"status"`},
			forbiddenText: []string{"write docs", "writing docs", "completed"},
		},
		{
			name:     "Task",
			toolName: "Task",
			response: map[string]any{
				"content": []map[string]string{
					{"type": "text", "text": "Subagent result: STRIPE_KEY=" + secret},
				},
				"totalTokens":           100,
				"totalToolUseCount":     3,
				"structuredPatchSha256": "deadbeef",
			},
			forbiddenKeys: []string{`"content"`, `"totalTokens"`, `"structuredPatchSha256"`},
			forbiddenText: []string{"deadbeef"},
		},
		{
			name:     "WebSearch",
			toolName: "WebSearch",
			response: map[string]any{
				"results": []map[string]string{
					{
						"title":   "Stripe docs",
						"url":     "https://example.com/docs",
						"snippet": "Use STRIPE_KEY=" + secret + " in production",
					},
					{
						"title":   "Unrelated",
						"url":     "https://example.com/other",
						"snippet": "nothing sensitive here",
					},
				},
			},
			forbiddenKeys: []string{`"results"`, `"title"`, `"url"`, `"snippet"`},
			forbiddenText: []string{"https://example.com", "nothing sensitive", "Unrelated"},
		},
		{
			name:     "NotebookEdit",
			toolName: "NotebookEdit",
			response: map[string]any{
				"filePath": "/tmp/notebook.ipynb",
				"cellId":   "cell-0",
				"oldString": "STRIPE_KEY=" + secret,
				"newString": "STRIPE_KEY=placeholder",
			},
			forbiddenKeys: []string{`"filePath"`, `"cellId"`, `"oldString"`, `"newString"`},
			forbiddenText: []string{"/tmp/notebook.ipynb", "cell-0"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := json.Marshal(tc.response)
			if err != nil {
				t.Fatalf("marshal response: %v", err)
			}
			payload, err := json.Marshal(map[string]any{
				"hook_event_name": "PostToolUse",
				"tool_name":       tc.toolName,
				"tool_response":   json.RawMessage(resp),
			})
			if err != nil {
				t.Fatalf("marshal payload: %v", err)
			}

			var out bytes.Buffer
			if err := Process(bytes.NewReader(payload), &out, nil); err != nil {
				t.Fatalf("Process: %v", err)
			}
			if out.Len() == 0 {
				t.Fatalf("expected block response, got empty output")
			}

			var response Output
			if err := json.Unmarshal(out.Bytes(), &response); err != nil {
				t.Fatalf("unmarshal response: %v", err)
			}

			if response.Decision != "block" {
				t.Errorf("expected decision=block, got %q", response.Decision)
			}
			if strings.Contains(response.Reason, secret) {
				t.Errorf("secret leaked in %s reason: %s", tc.toolName, response.Reason)
			}
			if !strings.Contains(response.Reason, "[REDACTED") {
				t.Errorf("expected [REDACTED marker in reason, got: %s", response.Reason)
			}
			for _, key := range tc.forbiddenKeys {
				if strings.Contains(response.Reason, key) {
					t.Errorf("raw JSON key %s leaked into reason: %s", key, response.Reason)
				}
			}
			for _, text := range tc.forbiddenText {
				if strings.Contains(response.Reason, text) {
					t.Errorf("unrelated content %q leaked into reason: %s", text, response.Reason)
				}
			}
		})
	}
}

// TestProcess_ReadPreservesFullContent ensures that plain text-like
// responses (Read's typed envelope, Grep's plain string) return the full
// scrubbed body so Claude can still see surrounding context, rather than
// being collapsed to only the lines containing secrets.
func TestProcess_ReadPreservesFullContent(t *testing.T) {
	stripe := testutil.StripeKey("sk_live_")

	fileBody := "line1\nline2\nSTRIPE_KEY=" + stripe.Value + "\nline4\nline5"
	resp, _ := json.Marshal(map[string]any{
		"type": "text",
		"file": map[string]any{
			"filePath":  "/tmp/env",
			"content":   fileBody,
			"numLines":  5,
			"startLine": 1,
		},
	})
	payload, _ := json.Marshal(map[string]any{
		"hook_event_name": "PostToolUse",
		"tool_name":       "Read",
		"tool_response":   json.RawMessage(resp),
	})

	var out bytes.Buffer
	if err := Process(bytes.NewReader(payload), &out, nil); err != nil {
		t.Fatalf("Process: %v", err)
	}
	if out.Len() == 0 {
		t.Fatal("expected block response for Read with secret")
	}

	var response Output
	json.Unmarshal(out.Bytes(), &response)

	if strings.Contains(response.Reason, stripe.Value) {
		t.Error("secret leaked")
	}
	for _, line := range []string{"line1", "line2", "line4", "line5"} {
		if !strings.Contains(response.Reason, line) {
			t.Errorf("expected Read reason to preserve %q, got: %s", line, response.Reason)
		}
	}
}

func TestProcess_ReasonContainsSecretCount(t *testing.T) {
	aws := testutil.AWSAccessKey()
	stripe := testutil.StripeKey("sk_live_")

	input := Input{
		HookEventName: "PostToolUse",
		ToolName:      "Bash",
		ToolResponse: ToolResponse{
			Stdout: "A=" + aws.Value + "\nB=" + stripe.Value,
		},
	}

	payload, _ := json.Marshal(input)
	var out bytes.Buffer

	Process(bytes.NewReader(payload), &out, nil)

	var response Output
	json.Unmarshal(out.Bytes(), &response)

	if !strings.Contains(response.Reason, "secret(s) scrubbed") {
		t.Errorf("expected secret count in reason, got: %s", response.Reason)
	}
}

func TestProcess_LargeOutput(t *testing.T) {
	dbURL := testutil.DatabaseURL("postgres", "admin", testutil.RandAlphaNum(8), "db.example.com", "5432", "prod")

	var sb strings.Builder
	for i := 0; i < 1000; i++ {
		sb.WriteString("2024-01-01T00:00:00Z INFO normal log line number ")
		sb.WriteString(strings.Repeat("x", 80))
		sb.WriteString("\n")
	}
	sb.WriteString("DATABASE_URL=" + dbURL.Value + "\n")
	for i := 0; i < 1000; i++ {
		sb.WriteString("2024-01-01T00:00:01Z INFO more log output\n")
	}

	input := Input{
		HookEventName: "PostToolUse",
		ToolName:      "Bash",
		ToolResponse:  ToolResponse{Stdout: sb.String()},
	}

	payload, _ := json.Marshal(input)
	var out bytes.Buffer

	err := Process(bytes.NewReader(payload), &out, nil)
	if err != nil {
		t.Fatalf("unexpected error on large output: %v", err)
	}

	if out.Len() == 0 {
		t.Fatal("expected redaction in large output")
	}

	var response Output
	json.Unmarshal(out.Bytes(), &response)

	if strings.Contains(response.Reason, dbURL.Value) {
		t.Error("secret leaked in large output")
	}
}
