package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// readPostToolUse reads settings JSON and returns typed PostToolUse entries.
func readPostToolUse(t *testing.T, path string) []HookEntry {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read settings: %v", err)
	}
	var settings map[string]any
	if err := json.Unmarshal(data, &settings); err != nil {
		t.Fatalf("parse settings: %v", err)
	}
	hooks, _ := settings["hooks"].(map[string]any)
	raw := hooks["PostToolUse"]
	b, _ := json.Marshal(raw)
	var entries []HookEntry
	json.Unmarshal(b, &entries)
	return entries
}

func TestInstallHook_CreatesNewFile(t *testing.T) {
	tmpDir := t.TempDir()
	settingsPath := filepath.Join(tmpDir, ".claude", "settings.json")

	err := installHookToPath(settingsPath, "/usr/local/bin/redacted")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	entries := readPostToolUse(t, settingsPath)
	if len(entries) != 1 {
		t.Fatalf("expected 1 PostToolUse entry, got %d", len(entries))
	}
	if entries[0].Matcher != "Bash" {
		t.Errorf("expected matcher=Bash, got %q", entries[0].Matcher)
	}
	if len(entries[0].Hooks) != 1 {
		t.Fatalf("expected 1 hook, got %d", len(entries[0].Hooks))
	}
	if entries[0].Hooks[0].Type != "command" {
		t.Errorf("expected type=command, got %q", entries[0].Hooks[0].Type)
	}
	if !strings.HasSuffix(entries[0].Hooks[0].Command, "redacted scrub") {
		t.Errorf("expected command to end with 'redacted scrub', got %q", entries[0].Hooks[0].Command)
	}
}

func TestInstallHook_PreservesExistingSettings(t *testing.T) {
	tmpDir := t.TempDir()
	settingsPath := filepath.Join(tmpDir, ".claude", "settings.json")

	os.MkdirAll(filepath.Dir(settingsPath), 0o755)
	existing := map[string]any{
		"theme": "dark",
		"hooks": map[string]any{
			"PreToolUse": []HookEntry{
				{
					Matcher: "Bash",
					Hooks:   []HookCommand{{Type: "command", Command: "/usr/local/bin/rtk-rewrite.sh"}},
				},
			},
		},
	}
	data, _ := json.MarshalIndent(existing, "", "  ")
	os.WriteFile(settingsPath, data, 0o644)

	err := installHookToPath(settingsPath, "/usr/local/bin/redacted")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Check theme preserved
	raw, _ := os.ReadFile(settingsPath)
	var settings map[string]any
	json.Unmarshal(raw, &settings)
	if settings["theme"] != "dark" {
		t.Error("existing theme setting was lost")
	}

	// Check PreToolUse preserved
	hooks, _ := settings["hooks"].(map[string]any)
	pre, _ := hooks["PreToolUse"].([]any)
	if len(pre) != 1 {
		t.Errorf("existing PreToolUse hooks were modified, got %d entries", len(pre))
	}

	// Check PostToolUse added
	entries := readPostToolUse(t, settingsPath)
	if len(entries) != 1 {
		t.Fatalf("expected 1 PostToolUse entry, got %d", len(entries))
	}
}

func TestInstallHook_PreservesOtherPostToolUseHooks(t *testing.T) {
	tmpDir := t.TempDir()
	settingsPath := filepath.Join(tmpDir, ".claude", "settings.json")

	os.MkdirAll(filepath.Dir(settingsPath), 0o755)
	existing := map[string]any{
		"hooks": map[string]any{
			"PostToolUse": []HookEntry{
				{
					Matcher: "Bash",
					Hooks:   []HookCommand{{Type: "command", Command: "/usr/local/bin/other-hook"}},
				},
			},
		},
	}
	data, _ := json.MarshalIndent(existing, "", "  ")
	os.WriteFile(settingsPath, data, 0o644)

	err := installHookToPath(settingsPath, "/usr/local/bin/redacted")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	entries := readPostToolUse(t, settingsPath)
	if len(entries) != 2 {
		t.Fatalf("expected 2 PostToolUse entries (other + redacted), got %d", len(entries))
	}
}

func TestInstallHook_ReplacesExistingRedacted(t *testing.T) {
	tmpDir := t.TempDir()
	settingsPath := filepath.Join(tmpDir, ".claude", "settings.json")

	os.MkdirAll(filepath.Dir(settingsPath), 0o755)
	existing := map[string]any{
		"hooks": map[string]any{
			"PostToolUse": []HookEntry{
				{
					Matcher: "Bash",
					Hooks:   []HookCommand{{Type: "command", Command: "/old/path/to/redacted scrub"}},
				},
				{
					Matcher: "Bash",
					Hooks:   []HookCommand{{Type: "command", Command: "/usr/local/bin/other-hook"}},
				},
			},
		},
	}
	data, _ := json.MarshalIndent(existing, "", "  ")
	os.WriteFile(settingsPath, data, 0o644)

	err := installHookToPath(settingsPath, "/new/path/redacted")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	entries := readPostToolUse(t, settingsPath)
	if len(entries) != 2 {
		t.Fatalf("expected 2 PostToolUse entries, got %d", len(entries))
	}

	foundOld, foundNew := false, false
	for _, entry := range entries {
		for _, h := range entry.Hooks {
			if strings.Contains(h.Command, "/old/path") {
				foundOld = true
			}
			if strings.Contains(h.Command, "/new/path") {
				foundNew = true
			}
		}
	}
	if foundOld {
		t.Error("old redacted entry should have been removed")
	}
	if !foundNew {
		t.Error("new redacted entry should have been added")
	}
}

func TestInstallHook_Idempotent(t *testing.T) {
	tmpDir := t.TempDir()
	settingsPath := filepath.Join(tmpDir, ".claude", "settings.json")

	installHookToPath(settingsPath, "/usr/local/bin/redacted")
	installHookToPath(settingsPath, "/usr/local/bin/redacted")

	entries := readPostToolUse(t, settingsPath)
	if len(entries) != 1 {
		t.Errorf("expected exactly 1 entry after running twice, got %d", len(entries))
	}
}

func TestInstallHook_InvalidExistingJSON(t *testing.T) {
	tmpDir := t.TempDir()
	settingsPath := filepath.Join(tmpDir, ".claude", "settings.json")

	os.MkdirAll(filepath.Dir(settingsPath), 0o755)
	os.WriteFile(settingsPath, []byte("not json"), 0o644)

	err := installHookToPath(settingsPath, "/usr/local/bin/redacted")
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
	if !strings.Contains(err.Error(), "parsing") {
		t.Errorf("expected parsing error, got: %v", err)
	}
}

func TestIsRedactedEntry(t *testing.T) {
	tests := []struct {
		name string
		cmd  string
		want bool
	}{
		{"exact match", "/usr/local/bin/redacted scrub", true},
		{"different path", "/home/user/go/bin/redacted scrub", true},
		{"not redacted", "/usr/local/bin/other-hook", false},
		{"partial match", "/usr/local/bin/not-redacted scrub-extra", false},
		{"empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entry := HookEntry{
				Hooks: []HookCommand{{Type: "command", Command: tt.cmd}},
			}
			got := isRedactedEntry(entry)
			if got != tt.want {
				t.Errorf("isRedactedEntry(%q) = %v, want %v", tt.cmd, got, tt.want)
			}
		})
	}
}
