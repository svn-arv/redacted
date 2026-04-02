package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/spf13/cobra"
)

var uninstallCmd = &cobra.Command{
	Use:   "uninstall",
	Short: "Remove redacted hooks and binary",
	Long: `Removes redacted hook entries from Claude Code settings files and
deletes the redacted binary.

By default removes from both global and local settings. Use --global
or --local to target a specific scope.

Use --keep-binary to only remove hooks without deleting the binary.`,
	Example: `  redacted uninstall                Remove hooks and binary
  redacted uninstall --global       Remove global hooks and binary
  redacted uninstall --keep-binary  Remove hooks only`,
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		global, _ := cmd.Flags().GetBool("global")
		local, _ := cmd.Flags().GetBool("local")
		keepBinary, _ := cmd.Flags().GetBool("keep-binary")

		if global && local {
			return fmt.Errorf("cannot use --global and --local together")
		}

		both := !global && !local
		removed := 0

		if both || global {
			path, err := resolveSettingPath(true)
			if err == nil {
				if removeHookFromPath(path) {
					fmt.Printf("Removed redacted hook from %s\n", path)
					removed++
				}
			}
		}

		if both || local {
			path, err := resolveSettingPath(false)
			if err == nil {
				if removeHookFromPath(path) {
					fmt.Printf("Removed redacted hook from %s\n", path)
					removed++
				}
			}
		}

		if removed == 0 {
			fmt.Println("No redacted hooks found.")
		}

		if !keepBinary {
			removeBinary()
		}

		return nil
	},
}

func init() {
	uninstallCmd.Flags().Bool("global", false, "remove from ~/.claude/settings.json only")
	uninstallCmd.Flags().Bool("local", false, "remove from .claude/settings.local.json only")
	uninstallCmd.Flags().Bool("keep-binary", false, "only remove hooks, keep the binary installed")
	rootCmd.AddCommand(uninstallCmd)
}

// removeBinary finds and deletes the redacted binary.
// If the PATH entry is a symlink to a different location (e.g. Homebrew),
// both the symlink and the resolved binary are removed.
func removeBinary() {
	exePath, err := os.Executable()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Could not determine binary path, remove manually")
		return
	}
	exePath, _ = filepath.Abs(exePath)

	// Also find the PATH entry — may be a symlink pointing elsewhere
	var linkPath string
	if looked, err := exec.LookPath("redacted"); err == nil {
		looked, _ = filepath.Abs(looked)
		if looked != exePath {
			linkPath = looked
		}
	}

	if linkPath != "" {
		if err := os.Remove(linkPath); err == nil {
			fmt.Printf("Removed %s\n", linkPath)
		}
	}

	if err := os.Remove(exePath); err != nil {
		fmt.Fprintf(os.Stderr, "Could not remove %s: %v\n", exePath, err)
		fmt.Fprintf(os.Stderr, "Remove manually: rm %s\n", exePath)
		return
	}
	fmt.Printf("Removed %s\n", exePath)
}

// removeHookFromPath removes redacted entries from a settings file.
// Returns true if an entry was found and removed.
func removeHookFromPath(path string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}

	var settings map[string]any
	if err := json.Unmarshal(data, &settings); err != nil {
		return false
	}

	hooks, _ := settings["hooks"].(map[string]any)
	if hooks == nil {
		return false
	}

	var existing []HookEntry
	if raw, ok := hooks["PostToolUse"]; ok {
		b, _ := json.Marshal(raw)
		json.Unmarshal(b, &existing)
	}

	var filtered []HookEntry
	found := false
	for _, entry := range existing {
		if isRedactedEntry(entry) {
			found = true
			continue
		}
		filtered = append(filtered, entry)
	}

	if !found {
		return false
	}

	if len(filtered) == 0 {
		delete(hooks, "PostToolUse")
	} else {
		hooks["PostToolUse"] = filtered
	}

	if len(hooks) == 0 {
		delete(settings, "hooks")
	}

	out, _ := json.MarshalIndent(settings, "", "  ")
	os.WriteFile(path, out, 0o644)
	return true
}
