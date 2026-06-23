// Package stats records and aggregates per-pattern redaction counts, so you can
// see which patterns fire in real use.
package stats

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// event is one redaction run, appended as a JSONL line.
type event struct {
	Time      string         `json:"t"`
	Tool      string         `json:"tool"`
	ByPattern map[string]int `json:"by"`
}

// filePath returns the stats log location. REDACTED_STATS_FILE overrides it (for
// tests); otherwise it sits beside the config at ~/.config/redacted/stats.jsonl.
func filePath() (string, error) {
	if p := os.Getenv("REDACTED_STATS_FILE"); p != "" {
		return p, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "redacted", "stats.jsonl"), nil
}

// Record appends one redaction event. Best-effort: every error is swallowed so
// stats can never break the hook. A no-op when nothing was redacted.
func Record(tool string, byPattern map[string]int) {
	if len(byPattern) == 0 {
		return
	}
	p, err := filePath()
	if err != nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return
	}
	f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()

	line, err := json.Marshal(event{
		Time:      time.Now().UTC().Format(time.RFC3339),
		Tool:      tool,
		ByPattern: byPattern,
	})
	if err != nil {
		return
	}
	f.Write(append(line, '\n'))
}

// Summary is the aggregated view across all recorded events.
type Summary struct {
	Events    int
	Total     int
	ByPattern map[string]int
}

// Aggregate reads the stats log and sums per-pattern counts. A missing file
// yields an empty summary; malformed lines are skipped.
func Aggregate() (Summary, error) {
	s := Summary{ByPattern: map[string]int{}}
	p, err := filePath()
	if err != nil {
		return s, err
	}
	f, err := os.Open(p)
	if err != nil {
		if os.IsNotExist(err) {
			return s, nil
		}
		return s, err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		if len(sc.Bytes()) == 0 {
			continue
		}
		var e event
		if json.Unmarshal(sc.Bytes(), &e) != nil {
			continue
		}
		s.Events++
		for name, n := range e.ByPattern {
			s.ByPattern[name] += n
			s.Total += n
		}
	}
	return s, sc.Err()
}

// Tier classifies a pattern by detection confidence (a false-positive proxy):
// vendor near-zero FP, keyword medium, heuristic where FPs concentrate.
func Tier(pattern string) string {
	switch pattern {
	case "secret_value":
		return "heuristic"
	case "env_secret", "yaml_secret", "custom_keyword":
		return "keyword"
	default:
		return "vendor"
	}
}

// ByTier sums redactions into vendor/keyword/heuristic buckets.
func (s Summary) ByTier() map[string]int {
	t := map[string]int{"vendor": 0, "keyword": 0, "heuristic": 0}
	for name, n := range s.ByPattern {
		t[Tier(name)] += n
	}
	return t
}

// HeuristicShare is the fraction of redactions caught by entropy alone, the
// cheapest proxy for false-positive risk.
func (s Summary) HeuristicShare() float64 {
	if s.Total == 0 {
		return 0
	}
	return float64(s.ByTier()["heuristic"]) / float64(s.Total)
}
