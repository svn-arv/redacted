package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoad_NoFiles(t *testing.T) {
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

patterns:
  - name: slack_webhook
    regex: 'https://hooks\.slack\.com/services/\S+'

keywords:
  - MONGO
  - ELASTIC
`), 0o644)

	cfg, err := Load("/some/project")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(cfg.Whitelist) != 2 {
		t.Errorf("expected 2 whitelist entries, got %d", len(cfg.Whitelist))
	}
	if cfg.Whitelist[0] != "jwt" || cfg.Whitelist[1] != "stripe_test" {
		t.Errorf("unexpected whitelist: %v", cfg.Whitelist)
	}

	if len(cfg.Patterns) != 1 {
		t.Errorf("expected 1 custom pattern, got %d", len(cfg.Patterns))
	}
	if cfg.Patterns[0].Name != "slack_webhook" {
		t.Errorf("expected pattern name slack_webhook, got %s", cfg.Patterns[0].Name)
	}

	if len(cfg.Keywords) != 2 {
		t.Errorf("expected 2 keywords, got %d", len(cfg.Keywords))
	}
}

func TestLoad_ProjectConfig(t *testing.T) {
	tmpProject := t.TempDir()
	os.WriteFile(filepath.Join(tmpProject, ".redacted.yaml"), []byte(`
whitelist:
  - jwt

keywords:
  - KAFKA
`), 0o644)

	// Set HOME to empty dir so global config doesn't exist
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	cfg, err := Load(tmpProject)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(cfg.Whitelist) != 1 || cfg.Whitelist[0] != "jwt" {
		t.Errorf("expected whitelist [jwt], got %v", cfg.Whitelist)
	}
	if len(cfg.Keywords) != 1 || cfg.Keywords[0] != "KAFKA" {
		t.Errorf("expected keywords [KAFKA], got %v", cfg.Keywords)
	}
}

func TestLoad_MergesGlobalAndProject(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	// Global config
	configDir := filepath.Join(tmpHome, ".config", "redacted")
	os.MkdirAll(configDir, 0o755)
	os.WriteFile(filepath.Join(configDir, "config.yaml"), []byte(`
whitelist:
  - jwt

keywords:
  - MONGO
`), 0o644)

	// Project config
	tmpProject := t.TempDir()
	os.WriteFile(filepath.Join(tmpProject, ".redacted.yaml"), []byte(`
whitelist:
  - stripe_test

keywords:
  - KAFKA

patterns:
  - name: custom
    regex: 'CUSTOM_\d+'
`), 0o644)

	cfg, err := Load(tmpProject)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should merge both
	if len(cfg.Whitelist) != 2 {
		t.Errorf("expected 2 whitelist entries (merged), got %d: %v", len(cfg.Whitelist), cfg.Whitelist)
	}
	if len(cfg.Keywords) != 2 {
		t.Errorf("expected 2 keywords (merged), got %d: %v", len(cfg.Keywords), cfg.Keywords)
	}
	if len(cfg.Patterns) != 1 {
		t.Errorf("expected 1 pattern (from project), got %d", len(cfg.Patterns))
	}
}

func TestLoad_EmptyCwd(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cfg.IsEmpty() {
		t.Error("expected empty config with no files and empty cwd")
	}
}

func TestLoad_InvalidYAML(t *testing.T) {
	tmpProject := t.TempDir()
	os.WriteFile(filepath.Join(tmpProject, ".redacted.yaml"), []byte(`
whitelist: [
  invalid yaml unclosed
`), 0o644)

	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	// Should not error — invalid config is silently ignored
	cfg, err := Load(tmpProject)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cfg.IsEmpty() {
		t.Error("expected empty config when YAML is invalid")
	}
}

func TestLoad_WhitelistOnly(t *testing.T) {
	tmpProject := t.TempDir()
	os.WriteFile(filepath.Join(tmpProject, ".redacted.yaml"), []byte(`
whitelist:
  - jwt
`), 0o644)

	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	cfg, err := Load(tmpProject)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.IsEmpty() {
		t.Error("config with whitelist should not be empty")
	}
	if len(cfg.Patterns) != 0 {
		t.Error("expected no patterns")
	}
	if len(cfg.Keywords) != 0 {
		t.Error("expected no keywords")
	}
}

func TestLoad_OverrideIgnoresGlobal(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	// Global config with whitelist and keywords
	configDir := filepath.Join(tmpHome, ".config", "redacted")
	os.MkdirAll(configDir, 0o755)
	os.WriteFile(filepath.Join(configDir, "config.yaml"), []byte(`
whitelist:
  - jwt
  - stripe_test

keywords:
  - MONGO
  - ELASTIC
`), 0o644)

	// Project config with override: true
	tmpProject := t.TempDir()
	os.WriteFile(filepath.Join(tmpProject, ".redacted.yaml"), []byte(`
override: true

whitelist:
  - stripe_test
`), 0o644)

	cfg, err := Load(tmpProject)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should only have project's whitelist, not global's
	if len(cfg.Whitelist) != 1 {
		t.Errorf("expected 1 whitelist entry (override), got %d: %v", len(cfg.Whitelist), cfg.Whitelist)
	}
	if cfg.Whitelist[0] != "stripe_test" {
		t.Errorf("expected stripe_test, got %s", cfg.Whitelist[0])
	}

	// Global keywords should be gone
	if len(cfg.Keywords) != 0 {
		t.Errorf("expected 0 keywords (override), got %d: %v", len(cfg.Keywords), cfg.Keywords)
	}
}

func TestLoad_OverrideFalseStillMerges(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	configDir := filepath.Join(tmpHome, ".config", "redacted")
	os.MkdirAll(configDir, 0o755)
	os.WriteFile(filepath.Join(configDir, "config.yaml"), []byte(`
whitelist:
  - jwt
`), 0o644)

	tmpProject := t.TempDir()
	os.WriteFile(filepath.Join(tmpProject, ".redacted.yaml"), []byte(`
override: false

whitelist:
  - stripe_test
`), 0o644)

	cfg, err := Load(tmpProject)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should merge both
	if len(cfg.Whitelist) != 2 {
		t.Errorf("expected 2 whitelist entries (merge), got %d: %v", len(cfg.Whitelist), cfg.Whitelist)
	}
}

func TestLoad_OnlyGlobalNoProject(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	configDir := filepath.Join(tmpHome, ".config", "redacted")
	os.MkdirAll(configDir, 0o755)
	os.WriteFile(filepath.Join(configDir, "config.yaml"), []byte(`
whitelist:
  - jwt
keywords:
  - MONGO
`), 0o644)

	cfg, err := Load("/nonexistent/project")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(cfg.Whitelist) != 1 || cfg.Whitelist[0] != "jwt" {
		t.Errorf("expected global whitelist [jwt], got %v", cfg.Whitelist)
	}
	if len(cfg.Keywords) != 1 || cfg.Keywords[0] != "MONGO" {
		t.Errorf("expected global keywords [MONGO], got %v", cfg.Keywords)
	}
}

func TestIsEmpty(t *testing.T) {
	empty := &Config{}
	if !empty.IsEmpty() {
		t.Error("zero Config should be empty")
	}

	withWhitelist := &Config{Whitelist: []string{"jwt"}}
	if withWhitelist.IsEmpty() {
		t.Error("Config with whitelist should not be empty")
	}

	withPatterns := &Config{Patterns: []CustomPattern{{Name: "x", Regex: "y"}}}
	if withPatterns.IsEmpty() {
		t.Error("Config with patterns should not be empty")
	}

	withKeywords := &Config{Keywords: []string{"MONGO"}}
	if withKeywords.IsEmpty() {
		t.Error("Config with keywords should not be empty")
	}
}
