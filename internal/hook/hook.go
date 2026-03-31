package hook

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/svn-arv/redacted/internal/patterns"
)

// Input is the JSON payload Claude Code sends to PostToolUse hooks on stdin.
type Input struct {
	SessionID     string       `json:"session_id"`
	HookEventName string       `json:"hook_event_name"`
	ToolName      string       `json:"tool_name"`
	ToolInput     ToolInput    `json:"tool_input"`
	ToolResponse  ToolResponse `json:"tool_response"`
}

type ToolInput struct {
	Command     string `json:"command"`
	Description string `json:"description,omitempty"`
}

type ToolResponse struct {
	ExitCode int    `json:"exitCode"`
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
}

// Output is the JSON payload we write to stdout for Claude Code to consume.
type Output struct {
	Decision           string              `json:"decision,omitempty"`
	Reason             string              `json:"reason,omitempty"`
	HookSpecificOutput *HookSpecificOutput `json:"hookSpecificOutput,omitempty"`
}

type HookSpecificOutput struct {
	HookEventName     string `json:"hookEventName"`
	AdditionalContext string `json:"additionalContext,omitempty"`
}

// Process reads the hook payload from stdin, scrubs secrets from both stdout
// and stderr, and writes the appropriate response to stdout.
//
// If scrubber is nil, uses the default package-level scrubber.
// If no secrets found: writes nothing, exits cleanly (pass-through).
// If secrets found: blocks the output and provides redacted version as reason.
func Process(stdin io.Reader, stdout io.Writer, scrubber *patterns.Scrubber) error {
	data, err := io.ReadAll(stdin)
	if err != nil {
		return fmt.Errorf("read stdin: %w", err)
	}

	var input Input
	if err := json.Unmarshal(data, &input); err != nil {
		return fmt.Errorf("parse hook payload: %w", err)
	}

	if input.ToolName != "Bash" {
		return nil
	}

	scrub := patterns.Scrub
	if scrubber != nil {
		scrub = scrubber.Scrub
	}

	stdoutResult := scrub(input.ToolResponse.Stdout)
	stderrResult := scrub(input.ToolResponse.Stderr)

	if !stdoutResult.Redacted && !stderrResult.Redacted {
		return nil
	}

	total := stdoutResult.Count + stderrResult.Count

	redactedOutput := stdoutResult.Text
	if stderrResult.Redacted {
		redactedOutput += "\n[stderr]\n" + stderrResult.Text
	}

	output := Output{
		Decision: "block",
		Reason: fmt.Sprintf(
			"[redacted] %d secret(s) scrubbed from command output.\n\n%s",
			total, redactedOutput,
		),
		HookSpecificOutput: &HookSpecificOutput{
			HookEventName: "PostToolUse",
		},
	}

	enc := json.NewEncoder(stdout)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(output); err != nil {
		return fmt.Errorf("write response: %w", err)
	}

	return nil
}
