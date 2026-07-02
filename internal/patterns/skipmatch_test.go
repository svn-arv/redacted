package patterns

import "testing"

// TestScrub_KeywordEchoValues covers keyword-arg echoes: in Ruby/JS source,
// `password: password` passes a same-named variable, not a literal secret.
// A value that just re-states its own key never redacts.
func TestScrub_KeywordEchoValues(t *testing.T) {
	clean := []string{
		"password: password",
		"token: token", // sub-floor today; kept as a regression row
		"credential: credential",
		"update(password: password)",
		`opts = { "password" => "password" }`,
		"PASSWORD: password", // echo compare is case-insensitive
	}
	for _, in := range clean {
		if result := Scrub(in); result.Redacted {
			t.Errorf("expected no redaction for keyword echo %q, got: %q", in, result.Text)
		}
	}

	// Guardrails: near-echoes and real values under keyword keys still redact.
	redactGuards := []string{
		"password: password2",
		"DB_PASSWORD=password",
		"password: hunter2secret",
	}
	for _, in := range redactGuards {
		if result := Scrub(in); !result.Redacted {
			t.Errorf("expected redaction for %q, got: %q", in, result.Text)
		}
	}
}
