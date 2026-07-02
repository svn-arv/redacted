package patterns

import (
	"strings"
	"testing"

	"github.com/svn-arv/redacted/internal/testutil"
)

// TestScrub_GCPServiceAccountKey covers escaped-PEM service-account JSON: a
// truncated key dump has no END marker for the private_key pattern to anchor
// on, and env_secret stops at the first backslash, so the assertion targets
// the key material itself, not just Redacted.
func TestScrub_GCPServiceAccountKey(t *testing.T) {
	material := testutil.RandAlphaNum(96)
	sa := testutil.GCPServiceAccountKey(material)

	r := Scrub(sa.Value)
	if !r.Redacted {
		t.Fatalf("expected redaction: %q", sa.Value)
	}
	if strings.Contains(r.Text, material) {
		t.Errorf("key material survived the scrub: %q", r.Text)
	}
	if !strings.Contains(r.Text, "[REDACTED") {
		t.Errorf("expected redaction marker, got: %q", r.Text)
	}
}
