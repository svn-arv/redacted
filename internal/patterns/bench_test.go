package patterns

import (
	"fmt"
	"strings"
	"testing"

	"github.com/svn-arv/redacted/internal/testutil"
)

// BenchmarkScrub measures the per-call cost the hook adds to tool output, at a
// typical size and a large worst case, over realistic mixed dev output.
func BenchmarkScrub(b *testing.B) {
	block := strings.Join([]string{
		"On branch main",
		"https://github.com/org/repo/issues/123 referenced in the changelog",
		"added 150 packages in 3s",
		"export AWS_ACCESS_KEY_ID=" + testutil.AWSAccessKey().Value,
		"DATABASE_URL=postgres://u:p@db.example.com:5432/app",
		"const id = user.account_id // not a secret",
		"2026-06-22T14:30:00Z level=info request_id=7f3e9a1b2c4d5e6f7a8b9c0d1e2f3a",
	}, "\n") + "\n"

	// Clean = the common case (most tool output has no secrets), isolating scan
	// cost. Dense = a secret on every line, isolating rebuild cost.
	clean := strings.Join([]string{
		"On branch main, your branch is up to date with origin/main.",
		"https://github.com/org/repo/issues/123 referenced in the changelog",
		"added 150 packages in 3s; compiled successfully in 1200ms",
		"const id = user.account_id // a plain identifier, not a secret",
		"2026-06-22T14:30:00Z level=info msg=request handled status=200",
	}, "\n") + "\n"

	for _, c := range []struct {
		name string
		text string
	}{{"clean", clean}, {"dense", block}} {
		for _, kb := range []int{16, 1024} {
			input := strings.Repeat(c.text, (kb*1024)/len(c.text)+1)
			b.Run(fmt.Sprintf("%s/%dKB", c.name, kb), func(b *testing.B) {
				b.SetBytes(int64(len(input)))
				b.ReportAllocs()
				for i := 0; i < b.N; i++ {
					Scrub(input)
				}
			})
		}
	}
}
