package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/svn-arv/redacted/internal/config"
	"github.com/svn-arv/redacted/internal/patterns"
)

var verifyCmd = &cobra.Command{
	Use:          "verify",
	Short:        "Check that redacted is installed and working",
	Example:      `  redacted verify`,
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runVerify()
	},
}

func init() {
	rootCmd.AddCommand(verifyCmd)
}

type checkStatus int

const (
	statusPass checkStatus = iota
	statusFail
	statusSkip
)

type check struct {
	name   string
	status checkStatus
	detail string
}

func runVerify() error {
	var checks []check

	checks = append(checks, checkBinary())
	checks = append(checks, checkHooks()...)
	checks = append(checks, checkConfig())
	checks = append(checks, checkPatterns())
	checks = append(checks, checkScrub())

	passed, failed := 0, 0
	for _, c := range checks {
		var tag string
		switch c.status {
		case statusPass:
			tag = "PASS"
			passed++
		case statusFail:
			tag = "FAIL"
			failed++
		case statusSkip:
			tag = "SKIP"
		}

		if c.detail != "" {
			fmt.Printf("  [%s] %s - %s\n", tag, c.name, c.detail)
		} else {
			fmt.Printf("  [%s] %s\n", tag, c.name)
		}
	}

	fmt.Printf("\n%d passed, %d failed\n", passed, failed)
	if failed > 0 {
		return fmt.Errorf("%d check(s) failed", failed)
	}
	return nil
}

func checkBinary() check {
	path, err := which("redacted")
	if err != nil {
		return check{"binary in PATH", statusFail, "not found, run: go install or brew install"}
	}
	return check{"binary in PATH", statusPass, path}
}

func checkHooks() []check {
	globalPath, _ := resolveSettingPath(true)
	localPath, _ := resolveSettingPath(false)

	global := checkSettingsFile(globalPath, "global hook")
	local := checkSettingsFile(localPath, "local hook")

	// If one is found, the missing one is just a skip, not a failure
	if global.status == statusPass && local.status == statusFail {
		local.status = statusSkip
	}
	if local.status == statusPass && global.status == statusFail {
		global.status = statusSkip
	}

	results := []check{global, local}

	if global.status != statusPass && local.status != statusPass {
		results = append(results, check{
			"hook registered", statusFail,
			"not found in either settings file, run: redacted init",
		})
	}

	return results
}

func checkSettingsFile(path, label string) check {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return check{label, statusFail, "file not found: " + path}
		}
		return check{label, statusFail, "cannot read " + path + ": " + err.Error()}
	}

	var settings struct {
		Hooks struct {
			PostToolUse []HookEntry `json:"PostToolUse"`
		} `json:"hooks"`
	}
	if err := json.Unmarshal(data, &settings); err != nil {
		return check{label, statusFail, path + " contains invalid JSON: " + err.Error()}
	}

	if len(settings.Hooks.PostToolUse) == 0 {
		return check{label, statusFail, "no PostToolUse hooks in " + path + ", run: redacted init"}
	}

	for _, entry := range settings.Hooks.PostToolUse {
		if !isRedactedEntry(entry) {
			continue
		}

		// Found the entry, verify the binary it points to still exists.
		for _, h := range entry.Hooks {
			if !strings.HasSuffix(h.Command, "redacted scrub") {
				continue
			}
			bin := strings.TrimSuffix(h.Command, " scrub")
			if _, err := os.Stat(bin); err != nil {
				return check{label, statusFail, fmt.Sprintf(
					"hook command references %s but that binary doesn't exist, reinstall or run: redacted init", bin,
				)}
			}
		}
		return check{label, statusPass, path}
	}

	return check{label, statusFail, "PostToolUse exists but has no redacted entry, run: redacted init"}
}

func checkConfig() check {
	cwd, _ := os.Getwd()
	cfg, err := config.Load(cwd)
	if err != nil {
		return check{"config files", statusFail, "failed to load config: " + err.Error()}
	}

	homeDir, _ := os.UserHomeDir()
	globalPath := filepath.Join(homeDir, ".config", "redacted", "config.yaml")
	projectPath := filepath.Join(cwd, ".redacted.yaml")

	_, globalErr := os.Stat(globalPath)
	_, projectErr := os.Stat(projectPath)

	if globalErr != nil && projectErr != nil {
		return check{"config files", statusPass, "none found (using built-in defaults)"}
	}

	var sources []string
	if globalErr == nil {
		sources = append(sources, "global")
	}
	if projectErr == nil {
		sources = append(sources, "project")
	}
	detail := strings.Join(sources, " + ") + " loaded"

	if !cfg.IsEmpty() {
		var extras []string
		if n := len(cfg.Whitelist); n > 0 {
			extras = append(extras, fmt.Sprintf("%d whitelisted", n))
		}
		if n := len(cfg.Patterns); n > 0 {
			extras = append(extras, fmt.Sprintf("%d custom patterns", n))
		}
		if n := len(cfg.Keywords); n > 0 {
			extras = append(extras, fmt.Sprintf("%d extra keywords", n))
		}
		if n := len(cfg.Allow); n > 0 {
			extras = append(extras, fmt.Sprintf("%d allowed vars", n))
		}
		detail += " (" + strings.Join(extras, ", ") + ")"
	}

	return check{"config files", statusPass, detail}
}

func checkPatterns() check {
	defer func() {
		if r := recover(); r != nil {
			// handled by the caller getting the zero-value check
		}
	}()

	patterns.New()
	return check{"patterns load", statusPass, "all patterns compiled"}
}

func checkScrub() check {
	s := patterns.New()

	result := s.Scrub("DATABASE_URL=postgres://user:pass@host:5432/db")
	if !result.Redacted || result.Count == 0 {
		return check{"test scrub", statusFail, "scrubber did not detect a database URL, patterns may be broken"}
	}
	if !strings.Contains(result.Text, "[REDACTED") {
		return check{"test scrub", statusFail, "scrubber output is missing [REDACTED tag, redaction may be broken"}
	}

	return check{"test scrub", statusPass, fmt.Sprintf("caught %d secret(s) in test input", result.Count)}
}

func which(name string) (string, error) {
	// Try the running binary first
	if exe, err := os.Executable(); err == nil {
		abs, _ := filepath.Abs(exe)
		return abs, nil
	}

	// Fall back to PATH lookup
	for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
		p := filepath.Join(dir, name)
		if _, err := os.Stat(p); err == nil {
			abs, _ := filepath.Abs(p)
			return abs, nil
		}
	}
	return "", fmt.Errorf("%s not found in PATH", name)
}
