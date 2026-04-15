package hook

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
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

// processGeneric scrubs non-Bash tool responses. Structured responses are
// summarized to only the redacted lines so JSON keys and unrelated fields
// do not leak into the block reason Claude reads as the replacement result.
func processGeneric(data []byte, toolName string, scrub func(string) patterns.Result, w io.Writer) error {
	var raw struct {
		ToolResponse json.RawMessage `json:"tool_response"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("parse tool_response: %w", err)
	}

	ex := extractText(raw.ToolResponse)
	result := scrub(ex.Text)
	if !result.Redacted {
		return nil
	}

	content := result.Text
	if ex.Structured {
		content = summarizeScrubbed(result.Text)
	}

	return writeBlock(w, result.Count, toolName, content)
}

type fileResponse struct {
	FilePath  string `json:"filePath"`
	Content   string `json:"content"`
	NumLines  int    `json:"numLines"`
	StartLine int    `json:"startLine"`
}

type readEnvelope struct {
	Type string        `json:"type"`
	File *fileResponse `json:"file,omitempty"`
}

// extractedText carries scrubber input plus whether the source was a
// structured JSON value, which decides summarize vs. full-content output.
type extractedText struct {
	Text       string
	Structured bool
}

func extractText(raw json.RawMessage) extractedText {
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return extractedText{Text: s, Structured: false}
	}

	var env readEnvelope
	if err := json.Unmarshal(raw, &env); err == nil && env.Type == "text" && env.File != nil {
		return extractedText{Text: env.File.Content, Structured: false}
	}

	var parts []string
	walkStrings(raw, &parts)
	if len(parts) > 0 {
		return extractedText{Text: strings.Join(parts, "\n"), Structured: true}
	}

	return extractedText{Text: string(raw), Structured: true}
}

// walkStrings recursively collects every string leaf from a JSON value.
// Object keys are visited in sorted order so leaf order is deterministic.
func walkStrings(raw json.RawMessage, dst *[]string) {
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		if s != "" {
			*dst = append(*dst, s)
		}
		return
	}

	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err == nil && obj != nil {
		keys := make([]string, 0, len(obj))
		for k := range obj {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			walkStrings(obj[k], dst)
		}
		return
	}

	var arr []json.RawMessage
	if err := json.Unmarshal(raw, &arr); err == nil {
		for _, v := range arr {
			walkStrings(v, dst)
		}
	}
}

// summarizeScrubbed returns only the scrubbed lines that contain a
// [REDACTED marker, each prefixed with "- ".
func summarizeScrubbed(scrubbed string) string {
	var hits []string
	for _, line := range strings.Split(scrubbed, "\n") {
		if strings.Contains(line, "[REDACTED") {
			hits = append(hits, "- "+line)
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
