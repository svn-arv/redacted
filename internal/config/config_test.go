package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoad_NoFiles(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	cfg, err := Load("/nonexistent/path")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cfg.IsEmpty() {
		t.Error("expected empty config when no files exist")
	}
}

func TestLoad_GlobalConfig(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	configDir := filepath.Join(tmpHome, ".config", "redacted")
	os.MkdirAll(configDir, 0o755)
	os.WriteFile(filepath.Join(configDir, "config.yaml"), []byte(`
whitelist:
  - jwt
  - stripe_test
allow:
  - APP_URL
`), 0o644)

	cfg, err := Load("/some/project")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.Whitelist) != 2 || cfg.Whitelist[0] != "jwt" {
		t.Errorf("unexpected whitelist: %v", cfg.Whitelist)
	}
	if len(cfg.Allow) != 1 || cfg.Allow[0] != "APP_URL" {
		t.Errorf("unexpected allow: %v", cfg.Allow)
	}
}

func TestLoad_MergesGlobalAndProject(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	configDir := filepath.Join(tmpHome, ".config", "redacted")
	os.MkdirAll(configDir, 0o755)
	os.WriteFile(filepath.Join(configDir, "config.yaml"), []byte("whitelist:\n  - jwt\n"), 0o644)

	tmpProject := t.TempDir()
	os.WriteFile(filepath.Join(tmpProject, ".redacted.yaml"), []byte("whitelist:\n  - stripe_test\nallow:\n  - APP_URL\n"), 0o644)

	cfg, err := Load(tmpProject)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.Whitelist) != 2 {
		t.Errorf("expected 2 whitelist entries (merged), got %v", cfg.Whitelist)
	}
	if len(cfg.Allow) != 1 {
		t.Errorf("expected merged allow, got %v", cfg.Allow)
	}
}

func TestLoad_InvalidYAMLIgnored(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	tmpProject := t.TempDir()
	os.WriteFile(filepath.Join(tmpProject, ".redacted.yaml"), []byte("whitelist: [\n  invalid unclosed\n"), 0o644)

	cfg, err := Load(tmpProject)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cfg.IsEmpty() {
		t.Error("expected empty config when YAML is invalid")
	}
}

func TestLoad_OverrideIgnoresGlobal(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	configDir := filepath.Join(tmpHome, ".config", "redacted")
	os.MkdirAll(configDir, 0o755)
	os.WriteFile(filepath.Join(configDir, "config.yaml"), []byte("whitelist:\n  - jwt\n  - stripe_test\n"), 0o644)

	tmpProject := t.TempDir()
	os.WriteFile(filepath.Join(tmpProject, ".redacted.yaml"), []byte("override: true\nwhitelist:\n  - stripe_test\n"), 0o644)

	cfg, err := Load(tmpProject)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.Whitelist) != 1 || cfg.Whitelist[0] != "stripe_test" {
		t.Errorf("expected only project whitelist on override, got %v", cfg.Whitelist)
	}
}

func TestLoad_IgnoreInternalToolsMerges(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	tmpProject := t.TempDir()
	os.WriteFile(filepath.Join(tmpProject, ".redacted.yaml"), []byte("ignore_internal_tools: true\n"), 0o644)

	cfg, err := Load(tmpProject)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cfg.IgnoreInternalTools {
		t.Error("expected ignore_internal_tools true")
	}
}

func TestIsEmpty(t *testing.T) {
	if !(&Config{}).IsEmpty() {
		t.Error("zero Config should be empty")
	}
	if (&Config{Whitelist: []string{"jwt"}}).IsEmpty() {
		t.Error("Config with whitelist should not be empty")
	}
	if (&Config{Allow: []string{"APP_URL"}}).IsEmpty() {
		t.Error("Config with allow should not be empty")
	}
}
