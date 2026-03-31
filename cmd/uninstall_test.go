package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestRemoveHookFromPath_RemovesRedacted(t *testing.T) {
	path := writeSettings(t, map[string]any{
		"hooks": map[string]any{
			"PostToolUse": []HookEntry{
				{Matcher: "Bash", Hooks: []HookCommand{{Type: "command", Command: "/usr/local/bin/redacted scrub"}}},
			},
		},
	})

	if !removeHookFromPath(path) {
		t.Fatal("expected removal, got false")
	}

	settings := readSettings(t, path)
	hooks, _ := settings["hooks"].(map[string]any)
	if hooks != nil {
		if _, ok := hooks["PostToolUse"]; ok {
			t.Error("PostToolUse should be removed when empty")
		}
	}
}

func TestRemoveHookFromPath_PreservesOtherHooks(t *testing.T) {
	path := writeSettings(t, map[string]any{
		"hooks": map[string]any{
			"PostToolUse": []HookEntry{
				{Matcher: "Bash", Hooks: []HookCommand{{Type: "command", Command: "/usr/local/bin/other-hook"}}},
				{Matcher: "Bash", Hooks: []HookCommand{{Type: "command", Command: "/usr/local/bin/redacted scrub"}}},
			},
		},
	})

	if !removeHookFromPath(path) {
		t.Fatal("expected removal, got false")
	}

	entries := readPostToolUse(t, path)
	if len(entries) != 1 {
		t.Fatalf("expected 1 remaining entry, got %d", len(entries))
	}
	if entries[0].Hooks[0].Command != "/usr/local/bin/other-hook" {
		t.Errorf("wrong hook preserved: %q", entries[0].Hooks[0].Command)
	}
}

func TestRemoveHookFromPath_PreservesOtherSettings(t *testing.T) {
	path := writeSettings(t, map[string]any{
		"theme": "dark",
		"hooks": map[string]any{
			"PreToolUse": []HookEntry{
				{Matcher: "Bash", Hooks: []HookCommand{{Type: "command", Command: "/usr/local/bin/rtk"}}},
			},
			"PostToolUse": []HookEntry{
				{Matcher: "Bash", Hooks: []HookCommand{{Type: "command", Command: "/usr/local/bin/redacted scrub"}}},
			},
		},
	})

	removeHookFromPath(path)

	settings := readSettings(t, path)
	if settings["theme"] != "dark" {
		t.Error("theme setting was lost")
	}

	hooks, _ := settings["hooks"].(map[string]any)
	pre, _ := hooks["PreToolUse"].([]any)
	if len(pre) != 1 {
		t.Error("PreToolUse hooks were modified")
	}
}

func TestRemoveHookFromPath_NoRedactedEntry(t *testing.T) {
	path := writeSettings(t, map[string]any{
		"hooks": map[string]any{
			"PostToolUse": []HookEntry{
				{Matcher: "Bash", Hooks: []HookCommand{{Type: "command", Command: "/usr/local/bin/other-hook"}}},
			},
		},
	})

	if removeHookFromPath(path) {
		t.Error("expected false when no redacted entry exists")
	}
}

func TestRemoveHookFromPath_FileNotFound(t *testing.T) {
	if removeHookFromPath("/nonexistent/path/settings.json") {
		t.Error("expected false for missing file")
	}
}

func TestRemoveHookFromPath_EmptyFile(t *testing.T) {
	path := writeSettings(t, map[string]any{})

	if removeHookFromPath(path) {
		t.Error("expected false for empty settings")
	}
}

func TestRemoveHookFromPath_NoHooksKey(t *testing.T) {
	path := writeSettings(t, map[string]any{"theme": "dark"})

	if removeHookFromPath(path) {
		t.Error("expected false when no hooks key exists")
	}
}

func TestRemoveHookFromPath_CleansEmptyHooksKey(t *testing.T) {
	path := writeSettings(t, map[string]any{
		"theme": "dark",
		"hooks": map[string]any{
			"PostToolUse": []HookEntry{
				{Matcher: "Bash", Hooks: []HookCommand{{Type: "command", Command: "/usr/local/bin/redacted scrub"}}},
			},
		},
	})

	removeHookFromPath(path)

	settings := readSettings(t, path)
	if _, ok := settings["hooks"]; ok {
		t.Error("empty hooks key should be removed")
	}
	if settings["theme"] != "dark" {
		t.Error("other settings should be preserved")
	}
}

func TestRemoveHookFromPath_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	os.WriteFile(path, []byte("not json"), 0o644)

	if removeHookFromPath(path) {
		t.Error("expected false for invalid JSON")
	}
}

// --- helpers ---

func writeSettings(t *testing.T, settings map[string]any) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	data, _ := json.MarshalIndent(settings, "", "  ")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func readSettings(t *testing.T, path string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var settings map[string]any
	if err := json.Unmarshal(data, &settings); err != nil {
		t.Fatal(err)
	}
	return settings
}
