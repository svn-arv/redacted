package hook

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

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

// Process reads the hook payload from stdin, scrubs secrets from the tool
// output, and writes the appropriate response to stdout.
//
// Supports all Claude Code tools: Bash (structured stdout/stderr handling),
// and generic tools like Read, Grep, WebFetch (raw response scrubbing).
//
// If scrubber is nil, uses the default package-level scrubber.
// If no secrets found: writes nothing, exits cleanly (pass-through).
// If secrets found: blocks the output and provides redacted version as reason.
func Process(stdin io.Reader, stdout io.Writer, scrubber *patterns.Scrubber) error {
	data, err := io.ReadAll(stdin)
	if err != nil {
		return fmt.Errorf("read stdin: %w", err)
	}

	var header struct {
		ToolName string `json:"tool_name"`
	}
	if err := json.Unmarshal(data, &header); err != nil {
		return fmt.Errorf("parse hook payload: %w", err)
	}

	scrub := patterns.Scrub
	if scrubber != nil {
		scrub = scrubber.Scrub
	}

	if header.ToolName == "Bash" {
		return processBash(data, scrub, stdout)
	}
	return processGeneric(data, header.ToolName, scrub, stdout)
}

// processBash handles Bash tool output with structured stdout/stderr scrubbing.
func processBash(data []byte, scrub func(string) patterns.Result, w io.Writer) error {
	var input Input
	if err := json.Unmarshal(data, &input); err != nil {
		return fmt.Errorf("parse hook payload: %w", err)
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

	return writeBlock(w, total, "command", redactedOutput)
}

// processGeneric handles non-Bash tools by scrubbing the raw tool_response.
func processGeneric(data []byte, toolName string, scrub func(string) patterns.Result, w io.Writer) error {
	var raw struct {
		ToolResponse json.RawMessage `json:"tool_response"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("parse tool_response: %w", err)
	}

	// Extract text content from the tool response.
	// Strategy 1: plain JSON string (e.g. some simple tools)
	// Strategy 2: object with a nested content/output string (e.g. Read, Grep)
	// Strategy 3: fall back to raw JSON
	text := extractText(raw.ToolResponse)

	result := scrub(text)
	if !result.Redacted {
		return nil
	}

	// For file-modifying tools, the operation already completed on disk.
	// Show a clean summary with what was scrubbed instead of the full raw JSON.
	content := result.Text
	switch toolName {
	case "Edit", "Write", "NotebookEdit":
		content = summarizeScrubbed(text, result.Text)
	}

	return writeBlock(w, result.Count, toolName, content)
}

// toolResponse is the typed envelope for Claude Code tool responses.
type toolResponse struct {
	Type string          `json:"type"`
	File *fileResponse   `json:"file,omitempty"`
	Raw  json.RawMessage `json:"-"` // preserved for fallback
}

type fileResponse struct {
	FilePath  string `json:"filePath"`
	Content   string `json:"content"`
	NumLines  int    `json:"numLines"`
	StartLine int    `json:"startLine"`
}

// extractText pulls readable text from a tool_response JSON value.
func extractText(raw json.RawMessage) string {
	// Try plain JSON string first
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}

	// Try typed response envelope
	var resp toolResponse
	if err := json.Unmarshal(raw, &resp); err == nil {
		switch resp.Type {
		case "text":
			if resp.File != nil {
				return resp.File.Content
			}
		}
	}

	// Fallback: raw JSON as string
	return string(raw)
}

// summarizeScrubbed compares original and scrubbed text to extract only
// the lines that contain [REDACTED markers. This avoids dumping entire
// file contents (e.g. Edit's originalFile field) into the output.
func summarizeScrubbed(original, scrubbed string) string {
	scrubbedLines := strings.Split(scrubbed, "\n")
	originalLines := strings.Split(original, "\n")

	var hits []string
	for i, line := range scrubbedLines {
		if strings.Contains(line, "[REDACTED") {
			// Include the original line for context if available
			if i < len(originalLines) && originalLines[i] != line {
				hits = append(hits, "- "+line)
			} else {
				hits = append(hits, "- "+line)
			}
		}
	}

	if len(hits) == 0 {
		return "Secret(s) removed from tool response."
	}
	return strings.Join(hits, "\n")
}

func writeBlock(w io.Writer, count int, source, redactedOutput string) error {
	output := Output{
		Decision: "block",
		Reason: fmt.Sprintf(
			"[redacted] %d secret(s) scrubbed from %s output.\n\n%s",
			count, source, redactedOutput,
		),
		HookSpecificOutput: &HookSpecificOutput{
			HookEventName: "PostToolUse",
		},
	}

	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(output); err != nil {
		return fmt.Errorf("write response: %w", err)
	}
	return nil
}
