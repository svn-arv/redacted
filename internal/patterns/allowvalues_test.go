package patterns

import (
	"strings"
	"testing"

	"github.com/svn-arv/redacted/internal/testutil"
)

// TestScrub_AllowValues covers issue #28: a value-shape allow-list clears
// candidate matches whose value (key=value) or whole match (value-only) matches
// a shipped allow_values row, while unrelated real secrets keep redacting.
func TestScrub_AllowValues(t *testing.T) {
	// Cleared by an allow row. Each fires pre-fix; the row must clear it.
	// Note: bare/JSON transcript ids never fire today (lenient `:` + `_` reads
	// as an identifier), so the transcript row is exercised via the `=` form.
	clean := []string{
		"parent_tool_use=toolu_01AbCdEf234567GhIjKl",                         // transcript id
		"DATABASE_URL=postgres://USER:PASSWORD@localhost:5432/myapp",         // all-caps placeholder
		"connection: mysql://user:pass@db.example.com:3306/app",              // lowercase placeholder
		"mongodb://admin:<password>@cluster.example.com/db",                  // angle-bracket placeholder
		"Ticket: Luce-MG/luce-product-design#5688.",                          // github ticket ref
		`[{"title": "Release/v1.2.3.4", "headRefName": "release/v1.2.3.4"}]`, // version tail
		`{:url=>"redis://localhost:6379/0"}`,                                 // credential-free localhost URL
	}
	for _, in := range clean {
		if r := Scrub(in); r.Redacted {
			t.Errorf("expected no redaction for allow_values row %q, got: %q", in, r.Text)
		}
	}

	// Recall: real credentials and unrelated values must still redact. The
	// placeholder rows must not clear a real password, and localhost WITH
	// userinfo is a real credentialed URL.
	redactGuards := []string{
		"postgis://test:testpassword@localhost:5432/gis",             // testpassword != placeholder `password`
		"redis://default:xK9q2Lp8Wn@localhost:6379/0",                // localhost WITH userinfo
		"postgres://admin:S3cretRand9x@db.internal.example.com/prod", // real password
		"TICKET_TOKEN: aB3xK9pLq2mNz7rT4wZ",                          // ticket row must not loosen a token value
		"WIDGET=aB3xK9pLq2mNz7rT4vWy",                                // version row must not loosen a token value
	}
	for _, in := range redactGuards {
		if r := Scrub(in); !r.Redacted {
			t.Errorf("expected redaction for %q, got: %q", in, r.Text)
		}
	}
}

// TestScrubber_WithAllowValues covers the option: a custom value-shape row
// clears a value the defaults would redact, without disabling other detection.
func TestScrubber_WithAllowValues(t *testing.T) {
	control := Scrub("WORKER=svc_aB3xK9pLq2mNz7rT4vWy")
	if !control.Redacted {
		t.Fatalf("precondition: default scrubber should redact svc_ value, got: %q", control.Text)
	}

	s := New(WithAllowValues(`^svc_[A-Za-z0-9]+$`))
	if r := s.Scrub("WORKER=svc_aB3xK9pLq2mNz7rT4vWy"); r.Redacted {
		t.Errorf("custom allow_values row should clear svc_ value, got: %q", r.Text)
	}

	// A value that doesn't match the custom row still redacts, and built-ins
	// keep working.
	if r := s.Scrub("WORKER=Xy7" + testutil.RandAlphaNum(16)); !r.Redacted {
		t.Error("non-matching value should still redact under a custom allow_values scrubber")
	}
	aws := testutil.AWSAccessKey()
	if r := s.Scrub(aws.Value); !r.Redacted || !strings.Contains(r.Text, "[REDACTED:aws_access_key") {
		t.Errorf("built-in aws pattern should still redact, got: %q", r.Text)
	}
}
