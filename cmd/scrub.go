package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
	"github.com/svn-arv/redacted/internal/config"
	"github.com/svn-arv/redacted/internal/hook"
	"github.com/svn-arv/redacted/internal/patterns"
	"github.com/svn-arv/redacted/internal/stats"
)

var scrubCmd = &cobra.Command{
	Use:   "scrub",
	Short: "Scrub secrets from a hook payload (stdin -> stdout)",
	Long: `Reads a Claude Code PostToolUse hook JSON payload from stdin, scans the
tool output for secrets, and writes a response to stdout.

Supports all Claude Code tools: Bash (structured stdout/stderr handling),
and internal tools like Read, Grep, WebFetch (raw response scrubbing).

If secrets are found:
  Outputs a JSON response with decision "block" and the redacted output
  as the reason. Claude sees the scrubbed version instead of the raw output.

If no secrets are found:
  Outputs nothing and exits cleanly. The original output passes through
  to Claude unmodified.

Configuration is loaded from:
  ~/.config/redacted/config.yaml   (global)
  <project>/.redacted.yaml         (project, merged with global)

Set ignore_internal_tools: true in config to only scrub Bash output.`,
	Example: `  # Pipe a hook payload manually
  cat testdata/hook_payload.json | redacted scrub

  # Test with inline JSON (Bash)
  echo '{"tool_name":"Bash","tool_response":{"stdout":"DB_PASSWORD=Xk7Pq9mW2vB8nZ4cA1fH"}}' | redacted scrub

  # Test with inline JSON (Read)
  echo '{"tool_name":"Read","tool_response":"SECRET_KEY=Xk7Pq9mW2vB8nZ4cA1fH"}' | redacted scrub

  # Test mode: any non-JSON stdin is scrubbed as raw text and printed
  echo 'TOKEN=mysecretvalue123' | redacted scrub`,
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			return fmt.Errorf("scrub: read stdin: %w", err)
		}

		cwd := extractCwd(data)
		cfg, _ := config.Load(cwd)
		eng, _ := config.LoadEngine(cwd)
		scrubber := buildScrubberFromConfig(cfg, eng)

		// Test mode: if stdin isn't a JSON object, scrub as raw text and
		// print to stdout. Hook payloads always start with `{`, so a
		// first-non-space character of anything else means manual testing.
		if !looksLikeHookPayload(data) {
			scrub := patterns.Scrub
			if scrubber != nil {
				scrub = scrubber.Scrub
			}
			result := scrub(string(data))
			fmt.Fprint(os.Stdout, result.Text)
			if result.Redacted {
				fmt.Fprintf(os.Stderr, "[redacted] %d secret(s) scrubbed\n", result.Count)
			}
			return nil
		}

		// If config says ignore internal tools, only scrub Bash
		if cfg != nil && cfg.IgnoreInternalTools {
			if extractToolName(data) != "Bash" {
				return nil
			}
		}

		hook.Recorder = stats.Record
		hook.ProcessSafely(bytes.NewReader(data), os.Stdout, scrubber)
		return nil
	},
}

// looksLikeHookPayload reports whether data is a JSON object — the shape of
// every Claude Code hook payload. A leading `{` is necessary but not
// sufficient: Ruby/PHP hash literals like `{"SID"=>"..."}` also start with
// `{` but aren't valid JSON, so they should fall through to test mode where
// the env_secret regex can do its job.
func looksLikeHookPayload(data []byte) bool {
	trimmed := bytes.TrimLeft(data, " \t\r\n")
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return false
	}
	return json.Valid(trimmed)
}

func init() {
	rootCmd.AddCommand(scrubCmd)
}

// buildScrubberFromConfig builds a Scrubber from app config (whitelist, allow)
// and engine config (heuristic, keywords, patterns). Returns nil when neither
// customizes anything, so hook.Process falls back to the default scrubber.
func buildScrubberFromConfig(cfg *config.Config, eng *config.EngineConfig) *patterns.Scrubber {
	appEmpty := cfg == nil || cfg.IsEmpty()
	engEmpty := eng == nil || eng.IsEmpty()
	if appEmpty && engEmpty {
		return nil
	}

	var opts []patterns.Option

	if cfg != nil {
		if len(cfg.Whitelist) > 0 {
			opts = append(opts, patterns.WithWhitelist(cfg.Whitelist...))
		}
		if len(cfg.Allow) > 0 {
			opts = append(opts, patterns.WithAllow(cfg.Allow...))
		}
	}

	if eng != nil {
		if eng.Heuristic != (config.HeuristicConfig{}) {
			opts = append(opts, patterns.WithHeuristic(patterns.HeuristicConfig{
				MinLength:      eng.Heuristic.MinLength,
				MaxLength:      eng.Heuristic.MaxLength,
				MinCharClasses: eng.Heuristic.MinCharClasses,
				MinEntropy:     eng.Heuristic.MinEntropy,
			}))
		}
		for _, p := range eng.Patterns {
			opts = append(opts, patterns.WithExtra(p.Name, p.Regex))
		}
		if len(eng.Keywords) > 0 {
			opts = append(opts, patterns.WithKeywords(eng.Keywords...))
		}
	}

	return patterns.New(opts...)
}

func extractCwd(data []byte) string {
	var partial struct {
		Cwd string `json:"cwd"`
	}
	json.Unmarshal(data, &partial)
	return partial.Cwd
}

func extractToolName(data []byte) string {
	var partial struct {
		ToolName string `json:"tool_name"`
	}
	json.Unmarshal(data, &partial)
	return partial.ToolName
}
