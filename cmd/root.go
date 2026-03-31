package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// Version is set at build time by GoReleaser via ldflags.
var Version = "dev"

var rootCmd = &cobra.Command{
	Use:     "redacted",
	Short:   "A hook that redacts secrets from Bash tool output",
	Version: Version,
	Long: `redacted intercepts Bash tool output and replaces secrets with [REDACTED]
before your AI coding assistant sees them.

When an AI tool runs a Bash command, the full output goes into conversation
context. If that output contains API keys, database URLs, or tokens, they
end up on the wire. redacted prevents this by scanning the output and
replacing secrets before they leave your machine.

Quick start:
  curl -sSL https://raw.githubusercontent.com/svn-arv/redacted/main/install.sh | sh
  redacted init

Works with Claude Code, OpenCode, and any tool that supports output hooks.

Built-in detection for:
  AWS, GitHub, Stripe, Twilio, DigitalOcean, Sentry, Slack,
  SendGrid, HubSpot, JWTs, private keys, database URLs,
  and any env variable containing SECRET, TOKEN, PASSWORD, etc.`,
	Example: `  redacted init               Install the hook (this project)
  redacted init --global      Install the hook (all projects)
  redacted verify             Check installation health
  redacted scrub              Run manually (reads stdin, used by the hook)`,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
