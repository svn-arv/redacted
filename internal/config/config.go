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

	// Patterns adds custom regex patterns.
	Patterns []CustomPattern `yaml:"patterns"`

	// Keywords adds custom env variable name keywords to the catch-all.
	Keywords []string `yaml:"keywords"`

	// Allow lists variable names that should never be redacted.
	// Matches are case-insensitive and check if the variable name
	// appears in the matched text.
	Allow []string `yaml:"allow"`

	// IgnoreInternalTools, when true, skips scrubbing for Claude Code's
	// internal tools (Read, Grep, WebFetch, etc.) and only scrubs Bash output.
	// Default is false, meaning all tools are scrubbed.
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
// By default, project config merges with global (whitelists, patterns,
// keywords combine). If the project config sets override: true, global
// config is ignored entirely.
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
	return len(c.Whitelist) == 0 && len(c.Patterns) == 0 && len(c.Keywords) == 0 && len(c.Allow) == 0
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
	dst.Patterns = append(dst.Patterns, src.Patterns...)
	dst.Keywords = append(dst.Keywords, src.Keywords...)
	dst.Allow = append(dst.Allow, src.Allow...)
	dst.IgnoreInternalTools = dst.IgnoreInternalTools || src.IgnoreInternalTools
}
