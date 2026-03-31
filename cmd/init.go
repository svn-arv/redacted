package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

var flagGlobal bool

// HookCommand is a single hook action in Claude Code settings.
type HookCommand struct {
	Type    string `json:"type"`
	Command string `json:"command"`
}

// HookEntry is a PostToolUse hook entry in Claude Code settings.
type HookEntry struct {
	Matcher string        `json:"matcher"`
	Hooks   []HookCommand `json:"hooks"`
}

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Install redacted as a hook",
	Long: `Registers redacted as a PostToolUse hook in your settings.

By default, installs to .claude/settings.local.json (this project only).
Use --global to install to ~/.claude/settings.json (all projects).

After running this command, every Bash tool invocation will have its output
piped through "redacted scrub" before your AI assistant sees it.

Safe to run multiple times. Existing redacted entries are replaced, and
other hooks are left untouched.`,
	Example: `  # Install for this project (default)
  redacted init

  # Install globally (all projects)
  redacted init --global

  # Verify
  cat ~/.claude/settings.json | jq '.hooks.PostToolUse'`,
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		return installHook(flagGlobal)
	},
}

func init() {
	initCmd.Flags().BoolVar(&flagGlobal, "global", false, "install to ~/.claude/settings.json (all projects)")
	rootCmd.AddCommand(initCmd)
}

func installHook(global bool) error {
	binPath, err := exec.LookPath("redacted")
	if err != nil {
		binPath, err = os.Executable()
		if err != nil {
			return fmt.Errorf("cannot determine redacted binary path: %w", err)
		}
	}
	binPath, _ = filepath.Abs(binPath)

	settingsPath, err := resolveSettingPath(global)
	if err != nil {
		return err
	}

	if err := installHookToPath(settingsPath, binPath); err != nil {
		return err
	}

	scope := "local"
	if global {
		scope = "global"
	}
	fmt.Printf("Installed redacted hook (%s) in %s\n", scope, settingsPath)
	fmt.Printf("Binary: %s scrub\n", binPath)
	return nil
}

func installHookToPath(settingsPath, binPath string) error {
	settings := make(map[string]any)
	data, err := os.ReadFile(settingsPath)
	if err == nil {
		if err := json.Unmarshal(data, &settings); err != nil {
			return fmt.Errorf("parsing %s: %w", settingsPath, err)
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("reading %s: %w", settingsPath, err)
	}

	hooks, _ := settings["hooks"].(map[string]any)
	if hooks == nil {
		hooks = make(map[string]any)
	}

	// Convert existing PostToolUse entries to typed structs
	var existing []HookEntry
	if raw, ok := hooks["PostToolUse"]; ok {
		b, _ := json.Marshal(raw)
		json.Unmarshal(b, &existing)
	}

	// Filter out old redacted entries, keep everything else
	var filtered []HookEntry
	for _, entry := range existing {
		if !isRedactedEntry(entry) {
			filtered = append(filtered, entry)
		}
	}

	// Add new redacted entry
	filtered = append(filtered, HookEntry{
		Matcher: "Bash",
		Hooks: []HookCommand{
			{Type: "command", Command: binPath + " scrub"},
		},
	})

	hooks["PostToolUse"] = filtered
	settings["hooks"] = hooks

	out, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal settings: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(settingsPath), 0o755); err != nil {
		return fmt.Errorf("create config directory: %w", err)
	}

	return os.WriteFile(settingsPath, out, 0o644)
}

func resolveSettingPath(global bool) (string, error) {
	if global {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("cannot determine home directory: %w", err)
		}
		return filepath.Join(homeDir, ".claude", "settings.json"), nil
	}

	cwd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("cannot determine working directory: %w", err)
	}
	return filepath.Join(cwd, ".claude", "settings.local.json"), nil
}

func isRedactedEntry(entry HookEntry) bool {
	for _, h := range entry.Hooks {
		if strings.HasSuffix(h.Command, "redacted scrub") {
			return true
		}
	}
	return false
}
