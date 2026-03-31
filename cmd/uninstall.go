package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var uninstallCmd = &cobra.Command{
	Use:   "uninstall",
	Short: "Remove redacted hooks from settings",
	Long: `Removes redacted hook entries from Claude Code settings files.

By default removes from both global and local settings. Use --global
or --local to target a specific one.

This only removes the hook registration. To also remove the binary:
  rm $(which redacted)`,
	Example: `  redacted uninstall            Remove from all settings
  redacted uninstall --global   Remove from global only
  redacted uninstall --local    Remove from local only`,
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		global, _ := cmd.Flags().GetBool("global")
		local, _ := cmd.Flags().GetBool("local")

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
		return nil
	},
}

func init() {
	uninstallCmd.Flags().Bool("global", false, "remove from ~/.claude/settings.json only")
	uninstallCmd.Flags().Bool("local", false, "remove from .claude/settings.local.json only")
	rootCmd.AddCommand(uninstallCmd)
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
