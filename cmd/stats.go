package cmd

import (
	"fmt"
	"io"
	"os"
	"sort"

	"github.com/spf13/cobra"
	"github.com/svn-arv/redacted/internal/stats"
)

var statsCmd = &cobra.Command{
	Use:   "stats",
	Short: "Show how often each pattern has redacted secrets",
	Long: `Reports cumulative redaction counts per pattern, gathered from real hook
runs. The catch-all share is a proxy for false-positive risk: the heuristic
patterns (secret_value, env_secret, yaml_secret) are where false positives
concentrate, so a high share is a signal to review or tighten them.`,
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runStats(os.Stdout)
	},
}

func runStats(w io.Writer) error {
	s, err := stats.Aggregate()
	if err != nil {
		return err
	}
	if s.Total == 0 {
		fmt.Fprintln(w, "No redactions recorded yet.")
		return nil
	}

	fmt.Fprintf(w, "Redactions: %d across %d hook runs\n", s.Total, s.Events)
	fmt.Fprintf(w, "False-positive risk: %.0f%% caught by heuristic alone (review these)\n\n", s.HeuristicShare()*100)

	tier := s.ByTier()
	fmt.Fprintln(w, "By confidence:")
	fmt.Fprintf(w, "  vendor     %d  (high: known provider signatures)\n", tier["vendor"])
	fmt.Fprintf(w, "  keyword    %d  (medium: credential-named keys)\n", tier["keyword"])
	fmt.Fprintf(w, "  heuristic  %d  (low: entropy-only; most false positives)\n\n", tier["heuristic"])

	type row struct {
		name string
		n    int
	}
	rows := make([]row, 0, len(s.ByPattern))
	for name, n := range s.ByPattern {
		rows = append(rows, row{name, n})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].n != rows[j].n {
			return rows[i].n > rows[j].n
		}
		return rows[i].name < rows[j].name
	})
	fmt.Fprintln(w, "By pattern:")
	for _, r := range rows {
		fmt.Fprintf(w, "  %-22s %d  (%s)\n", r.name, r.n, stats.Tier(r.name))
	}
	return nil
}

func init() {
	rootCmd.AddCommand(statsCmd)
}
