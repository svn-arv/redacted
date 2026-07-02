package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadEngine_HeuristicOverride(t *testing.T) {
	t.Setenv("HOME", t.TempDir()) // isolate from any real global engine.yml
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".redacted.engine.yml"),
		[]byte("heuristic:\n  min_entropy: 4.2\n  min_length: 24\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	eng, err := LoadEngine(dir)
	if err != nil {
		t.Fatal(err)
	}
	if eng.Heuristic.MinEntropy != 4.2 || eng.Heuristic.MinLength != 24 {
		t.Errorf("got %+v, want min_entropy 4.2 / min_length 24", eng.Heuristic)
	}
	// Unset fields stay zero so WithHeuristic keeps their engine defaults.
	if eng.Heuristic.MaxLength != 0 || eng.Heuristic.MinCharClasses != 0 {
		t.Errorf("unset fields should be zero, got %+v", eng.Heuristic)
	}
}

func TestLoadEngine_MissingIsEmpty(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	eng, err := LoadEngine(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if !eng.IsEmpty() {
		t.Errorf("no files should yield an empty engine config, got %+v", eng)
	}
}

func TestLoadEngine_KeywordsAndPatterns(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)
	dir := filepath.Join(tmpHome, ".config", "redacted")
	os.MkdirAll(dir, 0o755)
	os.WriteFile(filepath.Join(dir, "engine.yml"), []byte(`
keywords:
  - MONGO
  - ELASTIC
patterns:
  - name: slack_webhook
    regex: 'https://hooks\.slack\.com/services/\S+'
`), 0o644)

	eng, err := LoadEngine("/some/project")
	if err != nil {
		t.Fatal(err)
	}
	if len(eng.Keywords) != 2 {
		t.Errorf("expected 2 keywords, got %v", eng.Keywords)
	}
	if len(eng.Patterns) != 1 || eng.Patterns[0].Name != "slack_webhook" {
		t.Errorf("expected slack_webhook pattern, got %v", eng.Patterns)
	}
}

func TestLoadEngine_Merge(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)
	dir := filepath.Join(tmpHome, ".config", "redacted")
	os.MkdirAll(dir, 0o755)
	os.WriteFile(filepath.Join(dir, "engine.yml"), []byte("keywords:\n  - MONGO\nheuristic:\n  min_length: 20\n"), 0o644)

	proj := t.TempDir()
	os.WriteFile(filepath.Join(proj, ".redacted.engine.yml"), []byte("keywords:\n  - KAFKA\nheuristic:\n  min_entropy: 4.5\n"), 0o644)

	eng, err := LoadEngine(proj)
	if err != nil {
		t.Fatal(err)
	}
	if len(eng.Keywords) != 2 {
		t.Errorf("expected merged keywords, got %v", eng.Keywords)
	}
	// Project entropy overlays; the global min_length is kept.
	if eng.Heuristic.MinEntropy != 4.5 || eng.Heuristic.MinLength != 20 {
		t.Errorf("expected merged heuristic (len 20, entropy 4.5), got %+v", eng.Heuristic)
	}
}

func TestLoadEngine_ValueSafeChar(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)
	dir := filepath.Join(tmpHome, ".config", "redacted")
	os.MkdirAll(dir, 0o755)
	os.WriteFile(filepath.Join(dir, "engine.yml"), []byte("value_safe_char: '[A-Za-z0-9_]'\n"), 0o644)

	eng, err := LoadEngine("/some/project")
	if err != nil {
		t.Fatal(err)
	}
	if eng.ValueSafeChar != "[A-Za-z0-9_]" {
		t.Errorf("expected value_safe_char to load, got %q", eng.ValueSafeChar)
	}
	if eng.IsEmpty() {
		t.Error("a value_safe_char override should not read as empty")
	}
}

func TestLoadEngine_ValueSafeCharProjectWins(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)
	dir := filepath.Join(tmpHome, ".config", "redacted")
	os.MkdirAll(dir, 0o755)
	os.WriteFile(filepath.Join(dir, "engine.yml"), []byte("value_safe_char: '[A-Za-z0-9_]'\n"), 0o644)

	proj := t.TempDir()
	os.WriteFile(filepath.Join(proj, ".redacted.engine.yml"), []byte("value_safe_char: '[A-Za-z0-9]'\n"), 0o644)

	eng, err := LoadEngine(proj)
	if err != nil {
		t.Fatal(err)
	}
	if eng.ValueSafeChar != "[A-Za-z0-9]" {
		t.Errorf("project value_safe_char should overlay global, got %q", eng.ValueSafeChar)
	}
}

func TestLoadEngine_Override(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)
	dir := filepath.Join(tmpHome, ".config", "redacted")
	os.MkdirAll(dir, 0o755)
	os.WriteFile(filepath.Join(dir, "engine.yml"), []byte("keywords:\n  - MONGO\n"), 0o644)

	proj := t.TempDir()
	os.WriteFile(filepath.Join(proj, ".redacted.engine.yml"), []byte("override: true\nkeywords:\n  - KAFKA\n"), 0o644)

	eng, err := LoadEngine(proj)
	if err != nil {
		t.Fatal(err)
	}
	if len(eng.Keywords) != 1 || eng.Keywords[0] != "KAFKA" {
		t.Errorf("expected only project keywords on override, got %v", eng.Keywords)
	}
}
