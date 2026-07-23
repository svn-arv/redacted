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
		// #29 supersedes these: the value is the keyword itself plus digits or a
		// separator (a placeholder), so it no longer redacts.
		"password: password2",
		"DB_PASSWORD=password",
	}
	for _, in := range clean {
		if result := Scrub(in); result.Redacted {
			t.Errorf("expected no redaction for keyword echo %q, got: %q", in, result.Text)
		}
	}

	// Guardrails: a real value under a keyword key still redacts.
	redactGuards := []string{
		"password: hunter2secret",
	}
	for _, in := range redactGuards {
		if result := Scrub(in); !result.Redacted {
			t.Errorf("expected redaction for %q, got: %q", in, result.Text)
		}
	}
}

// TestScrub_PlaceholderValues covers #29: keyword echoes with decoration and
// short dictionary words are placeholders; real values under the same keys redact.
func TestScrub_PlaceholderValues(t *testing.T) {
	clean := []string{
		"PASSWORD=christmas",
		"DB_PASSWORD=changeme",
		"SECRET_KEY=placeholder",
		"ADMIN_PASSWORD=password123",
		"API_KEY=apikey123",
		"password: 'password123'",
	}
	for _, in := range clean {
		if result := Scrub(in); result.Redacted {
			t.Errorf("expected no redaction for placeholder %q, got: %q", in, result.Text)
		}
	}

	// Guardrails: a long all-lowercase value (over the dictionary cap) and a
	// keyword-plus-noise value that isn't a clean echo still redact.
	redactGuards := []string{
		"DB_PASSWORD=supersecretpassword",
		"PASSWORD=hunter2secret9",
	}
	for _, in := range redactGuards {
		if result := Scrub(in); !result.Redacted {
			t.Errorf("expected redaction for %q, got: %q", in, result.Text)
		}
	}
}

// TestScrub_LenientCodeContextValues covers #26: identifier-shaped values under
// `:`/`=>`/spaced-`=` are code references; env dumps and random tokens still redact.
func TestScrub_LenientCodeContextValues(t *testing.T) {
	clean := []string{
		"{ password: 'random_variable_password' }",
		"{ password: oauth2_password }",
		"{ password: userPassword }",
		"{ password: my_password_123 }",
		"update(password: new_password2)",
		"conversation_sid: CH_test_1234",
		"sid: 'CHclosed'",
		"FUNCTION_TEMPLATE_SID: 'HXnotice'",
		"SentryHelper.report_to_sentry(error, { conversation_sid: conversation&.conversation_sid })",
		"target_worker_sid: transfer_to_lead? ? lead_agent.sid : nil",
		"#  fk_rails_...  (client_id => clients.id)",
		"state.newClientId = clientId",
		"VISIT_RESCHEDULE_WITH_TOKEN = 'RescheduleVisitWithToken'",
		`get "invite/:token" => "invitation_acceptances#show"`,
		"ACTION_RESET_PASSWORD_EMAIL = 'reset_password_email'",
	}
	for _, in := range clean {
		if result := Scrub(in); result.Redacted {
			t.Errorf("expected no redaction for lenient code context %q, got: %q", in, result.Text)
		}
	}

	// Guardrails: bare `KEY=value` stays strict (env-dump shape), and a random
	// token under a lenient separator (digits, no separator char) still redacts.
	redactGuards := []string{
		"TOKEN=my_token_123",
		"TOKEN=MyRealSecretToken",
		"AUTH_TOKEN: aB3xK9pLq2mNz7rT4wZ",
		"secret_key = Xk7Pq9mW2vB8nZ4cA1fH",
		"API_TOKEN: https://example.com:8080/FooBar/Baz123",
	}
	for _, in := range redactGuards {
		if result := Scrub(in); !result.Redacted {
			t.Errorf("expected redaction for %q, got: %q", in, result.Text)
		}
	}
}

// TestScrub_IdentifierKeyValues covers identifier-named keys: a high-entropy
// value under an id/uuid key (tool_use_id, sessionId) is an ID, not a
// credential. Only the scored catch-all skips; keyword keys keep their
// env_secret coverage.
func TestScrub_IdentifierKeyValues(t *testing.T) {
	clean := []string{
		`"tool_use_id": "toolu_01ABC123DEF456"`,
		`"session_id": "Ab3xK9mQ2rT8wZ4yP6vN"`,
		"requestId: Zx9Kq2Lm8Pn4Rt6Vw1Yb",
		"BUILD-ID: aB3xK9pLq2mNz7rT4vWy",
		`"trace_uuid": "Xk7Pq9mW2vB8nZ4cA1fH"`,
	}
	for _, in := range clean {
		if result := Scrub(in); result.Redacted {
			t.Errorf("expected no redaction for identifier key %q, got: %q", in, result.Text)
		}
	}

	// Guardrails: keyword keys ending in _ID stay covered (env_secret is not
	// scored), and an id-ish tail without a boundary is not exempted.
	redactGuards := []string{
		"CLIENT_ID=Zx9Kq2Lm8Pn4Rt6Vw1Yb",
		"liquid: Zx9Kq2Lm8Pn4Rt6Vw1Yb",
	}
	for _, in := range redactGuards {
		if result := Scrub(in); !result.Redacted {
			t.Errorf("expected redaction for %q, got: %q", in, result.Text)
		}
	}
}

// TestScrub_URLContextValues covers port URLs: host:port parses as KEY:value
// and an uppercase path clears the scorer, but a scored match whose token
// already carries a scheme is an address, not a secret.
func TestScrub_URLContextValues(t *testing.T) {
	clean := []string{
		"https://example.com:8080/FooBar/Baz123",
		"curl https://api.example.com:9200/Index7/_search?q=FooBar9",
	}
	for _, in := range clean {
		if result := Scrub(in); result.Redacted {
			t.Errorf("expected no redaction for URL %q, got: %q", in, result.Text)
		}
	}

	// Guardrails: a keyword key with a URL value stays covered (env_secret is
	// not scored), and a scored secret merely adjacent to a URL still redacts.
	redactGuards := []string{
		"API_TOKEN: https://example.com:8080/FooBar/Baz123",
		"see https://example.com:8080/docs then WIDGET=aB3xK9pLq2mNz7rT4vWy",
	}
	for _, in := range redactGuards {
		if result := Scrub(in); !result.Redacted {
			t.Errorf("expected redaction for %q, got: %q", in, result.Text)
		}
	}
}
