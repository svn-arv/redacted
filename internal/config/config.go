package config

import (
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Config holds user configuration loaded from YAML files.
type Config struct {
	// Override, when true in a project config, ignores global config entirely.
	Override bool `yaml:"override"`

	// Whitelist skips built-in patterns by name.
	Whitelist []string `yaml:"whitelist"`

	// Allow lists variable names that should never be redacted (case-insensitive,
	// substring match on the matched text).
	Allow []string `yaml:"allow"`

	// IgnoreInternalTools, when true, only scrubs Bash output and skips Claude
	// Code's internal tools (Read, Grep, WebFetch, etc.).
	IgnoreInternalTools bool `yaml:"ignore_internal_tools"`
}

// CustomPattern is a user-defined regex pattern.
type CustomPattern struct {
	Name  string `yaml:"name"`
	Regex string `yaml:"regex"`
}

// Load reads config from two locations:
//   - ~/.config/redacted/config.yaml  (global)
//   - <cwd>/.redacted.yaml            (project)
//
// By default, project config merges with global (whitelist and allow combine).
// If the project config sets override: true, global config is ignored entirely.
//
// Missing files are silently ignored.
func Load(cwd string) (*Config, error) {
	// Load global config
	var global *Config
	homeDir, err := os.UserHomeDir()
	if err == nil {
		globalPath := filepath.Join(homeDir, ".config", "redacted", "config.yaml")
		global, _ = loadFile(globalPath)
	}

	// Load project config
	var project *Config
	if cwd != "" {
		projectPath := filepath.Join(cwd, ".redacted.yaml")
		project, _ = loadFile(projectPath)
	}

	// No config at all
	if global == nil && project == nil {
		return &Config{}, nil
	}

	// Only global
	if project == nil {
		return global, nil
	}

	// Project overrides global
	if project.Override || global == nil {
		return project, nil
	}

	// Merge: global first, then project on top
	merged := &Config{}
	merge(merged, global)
	merge(merged, project)
	return merged, nil
}

// IsEmpty returns true if no config was loaded.
func (c *Config) IsEmpty() bool {
	return len(c.Whitelist) == 0 && len(c.Allow) == 0
}

func loadFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func merge(dst, src *Config) {
	dst.Whitelist = append(dst.Whitelist, src.Whitelist...)
	dst.Allow = append(dst.Allow, src.Allow...)
	dst.IgnoreInternalTools = dst.IgnoreInternalTools || src.IgnoreInternalTools
}

// EngineConfig overrides detection rules, loaded from engine.yml (global) and
// .redacted.engine.yml (project). config.yaml stays app/operational policy.
type EngineConfig struct {
	Override      bool            `yaml:"override"`
	ValueSafeChar string          `yaml:"value_safe_char"`
	Heuristic     HeuristicConfig `yaml:"heuristic"`
	Keywords      []string        `yaml:"keywords"`
	Patterns      []CustomPattern `yaml:"patterns"`
}

// HeuristicConfig overrides secret_value scorer thresholds; a zero field keeps the default.
type HeuristicConfig struct {
	MinLength      int     `yaml:"min_length"`
	MaxLength      int     `yaml:"max_length"`
	MinCharClasses int     `yaml:"min_char_classes"`
	MinEntropy     float64 `yaml:"min_entropy"`
}

// LoadEngine reads engine.yml (global) and .redacted.engine.yml (project),
// merging project over global (or replacing it when project sets override).
func LoadEngine(cwd string) (*EngineConfig, error) {
	var global *EngineConfig
	if home, err := os.UserHomeDir(); err == nil {
		global = loadEngineFile(filepath.Join(home, ".config", "redacted", "engine.yml"))
	}
	var project *EngineConfig
	if cwd != "" {
		project = loadEngineFile(filepath.Join(cwd, ".redacted.engine.yml"))
	}

	switch {
	case global == nil && project == nil:
		return &EngineConfig{}, nil
	case project == nil:
		return global, nil
	case project.Override || global == nil:
		return project, nil
	}

	merged := *global
	merged.Keywords = append(append([]string{}, global.Keywords...), project.Keywords...)
	merged.Patterns = append(append([]CustomPattern{}, global.Patterns...), project.Patterns...)
	overlayHeuristic(&merged.Heuristic, project.Heuristic)
	if project.ValueSafeChar != "" {
		merged.ValueSafeChar = project.ValueSafeChar
	}
	return &merged, nil
}

// IsEmpty reports whether the engine config overrides nothing.
func (e *EngineConfig) IsEmpty() bool {
	return e.Heuristic == (HeuristicConfig{}) && len(e.Keywords) == 0 &&
		len(e.Patterns) == 0 && e.ValueSafeChar == ""
}

func loadEngineFile(path string) *EngineConfig {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var ec EngineConfig
	if yaml.Unmarshal(data, &ec) != nil {
		return nil
	}
	return &ec
}

// overlayHeuristic copies the non-zero fields of src over dst.
func overlayHeuristic(dst *HeuristicConfig, src HeuristicConfig) {
	if src.MinLength != 0 {
		dst.MinLength = src.MinLength
	}
	if src.MaxLength != 0 {
		dst.MaxLength = src.MaxLength
	}
	if src.MinCharClasses != 0 {
		dst.MinCharClasses = src.MinCharClasses
	}
	if src.MinEntropy != 0 {
		dst.MinEntropy = src.MinEntropy
	}
}
