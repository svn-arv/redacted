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
)

var scrubCmd = &cobra.Command{
	Use:   "scrub",
	Short: "Scrub secrets from a hook payload (stdin -> stdout)",
	Long: `Reads a Claude Code PostToolUse hook JSON payload from stdin, scans the
Bash tool output for secrets, and writes a response to stdout.

If secrets are found:
  Outputs a JSON response with decision "block" and the redacted output
  as the reason. Claude sees the scrubbed version instead of the raw output.

If no secrets are found:
  Outputs nothing and exits cleanly. The original output passes through
  to Claude unmodified.

Configuration is loaded from:
  ~/.config/redacted/config.yaml   (global)
  <project>/.redacted.yaml         (project, merged with global)

This command is called automatically by the Claude Code hook. You don't
normally need to run it by hand.`,
	Example: `  # Pipe a hook payload manually
  cat testdata/hook_payload.json | redacted scrub

  # Test with inline JSON
  echo '{"tool_name":"Bash","tool_response":{"stdout":"DB_PASSWORD=hunter2"}}' | redacted scrub`,
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			return fmt.Errorf("scrub: read stdin: %w", err)
		}

		scrubber := buildScrubber(extractCwd(data))

		if err := hook.Process(bytes.NewReader(data), os.Stdout, scrubber); err != nil {
			return fmt.Errorf("scrub: %w", err)
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(scrubCmd)
}

// buildScrubber loads config and creates a configured Scrubber.
// Returns nil if no config found (hook.Process falls back to default).
func buildScrubber(cwd string) *patterns.Scrubber {
	cfg, err := config.Load(cwd)
	if err != nil || cfg.IsEmpty() {
		return nil
	}

	var opts []patterns.Option

	if len(cfg.Whitelist) > 0 {
		opts = append(opts, patterns.WithWhitelist(cfg.Whitelist...))
	}

	for _, p := range cfg.Patterns {
		opts = append(opts, patterns.WithExtra(p.Name, p.Regex))
	}

	if len(cfg.Keywords) > 0 {
		opts = append(opts, patterns.WithKeywords(cfg.Keywords...))
	}

	if len(cfg.Allow) > 0 {
		opts = append(opts, patterns.WithAllow(cfg.Allow...))
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
