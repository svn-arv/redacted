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

func TestProcess_IgnoresNonBash(t *testing.T) {
	tools := []string{"Read", "Write", "Edit", "Glob", "Grep", "Agent"}

	for _, tool := range tools {
		t.Run(tool, func(t *testing.T) {
			stripe := testutil.StripeKey("sk_live_")
			input := Input{
				HookEventName: "PostToolUse",
				ToolName:      tool,
				ToolResponse: ToolResponse{
					Stdout: "SECRET_KEY=" + stripe.Value,
				},
			}

			payload, _ := json.Marshal(input)
			var out bytes.Buffer

			err := Process(bytes.NewReader(payload), &out, nil)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if out.Len() != 0 {
				t.Errorf("expected pass-through for %s tool, got: %s", tool, out.String())
			}
		})
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
