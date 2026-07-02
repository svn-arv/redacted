package patterns

import (
	"embed"
	"strings"
	"testing"

	"github.com/svn-arv/redacted/internal/testutil"
)

// cleanCorpus holds adversarial non-secrets: real dev output that must never
// redact. Every redaction on it is, by definition, a false positive.
//
//go:embed corpus/clean
var cleanCorpus embed.FS

// knownResidualFPs still redact today but aren't secrets. The precision test
// asserts each still redacts, flagging when one gets fixed (promote to clean).
// Currently empty; future residuals land here.
var knownResidualFPs []string

// TestCorpus_Precision fails on any redaction of the clean corpus, and reports
// the precision so accuracy stays visible even when green.
func TestCorpus_Precision(t *testing.T) {
	const dir = "corpus/clean"
	entries, err := cleanCorpus.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	clean := 0
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		data, err := cleanCorpus.ReadFile(dir + "/" + e.Name())
		if err != nil {
			t.Fatal(err)
		}
		if !Scrub(string(data)).Redacted {
			clean++
			continue
		}
		// Pinpoint the offending line(s); fall back to the whole file for a
		// cross-line match (e.g. a yaml_secret spanning two lines).
		hit := false
		for i, line := range strings.Split(string(data), "\n") {
			if line == "" {
				continue
			}
			if r := Scrub(line); r.Redacted {
				hit = true
				t.Errorf("false positive %s:%d\n  in:  %q\n  out: %q", e.Name(), i+1, line, r.Text)
			}
		}
		if !hit {
			t.Errorf("false positive %s (cross-line)\n  out: %q", e.Name(), Scrub(string(data)).Text)
		}
	}
	t.Logf("precision: %d/%d clean corpus files fully clean", clean, len(entries))

	// Tripwire: these are known FPs. If one stops redacting, move it into
	// corpus/clean and drop it here.
	for _, s := range knownResidualFPs {
		if !Scrub(s).Redacted {
			t.Errorf("residual FP no longer redacts; promote it to corpus/clean and remove from knownResidualFPs: %q", s)
		}
	}
}

// TestCorpus_Recall plants every synthetic secret factory (value-only bare,
// key-gated with its required key) and fails on any miss.
func TestCorpus_Recall(t *testing.T) {
	// Guarantees lower+upper+digit so the heuristic value clears secretLike
	// regardless of the random tail.
	heuristicVal := "Xy7" + testutil.RandAlphaNum(18)

	cases := []struct{ name, text string }{
		{"aws_access_key", testutil.AWSAccessKey().Value},
		{"aws_secret_key", "AWS_SECRET_ACCESS_KEY=" + testutil.AWSSecretKey().Value},
		{"github_token_ghp", testutil.GitHubToken("ghp_").Value},
		{"github_token_ghs", testutil.GitHubToken("ghs_").Value},
		{"github_oauth", testutil.GitHubToken("gho_").Value},
		{"github_refresh", testutil.GitHubToken("ghr_").Value},
		{"github_fine_grained", testutil.GitHubFineGrained().Value},
		{"stripe_live_sk", testutil.StripeKey("sk_live_").Value},
		{"stripe_live_pk", testutil.StripeKey("pk_live_").Value},
		{"stripe_test_sk", testutil.StripeKey("sk_test_").Value},
		{"twilio_account_sid", testutil.TwilioSID("AC").Value},
		{"twilio_api_key", testutil.TwilioSID("SK").Value},
		{"digitalocean_token", testutil.DigitalOceanToken().Value},
		{"digitalocean_spaces", testutil.DigitalOceanSpaces("SPACES_ACCESS_KEY").Value},
		{"sentry_dsn", testutil.SentryDSN().Value},
		{"sentry_dsn_subdomain", testutil.SentryDSNSubdomain().Value},
		{"slack_bot", testutil.SlackToken("xoxb").Value},
		{"slack_user", testutil.SlackToken("xoxp").Value},
		{"slack_app", testutil.SlackToken("xoxa").Value},
		{"sendgrid_key", testutil.SendGridKey().Value},
		{"hubspot_key", testutil.HubSpotPAT("na1").Value},
		{"jwt", testutil.JWT().Value},
		{"openai_key", testutil.OpenAIKey().Value},
		{"openai_classic", testutil.OpenAIClassicKey().Value},
		{"google_api_key", testutil.GoogleAPIKey().Value},
		{"gitlab_pat", testutil.GitLabPAT().Value},
		{"npm_token", testutil.NPMToken().Value},
		{"slack_webhook", testutil.SlackWebhook().Value},
		{"pypi_token", testutil.PyPIToken().Value},
		{"database_url_postgres", testutil.DatabaseURL("postgres", "u", "p", "h", "5432", "d").Value},
		{"database_url_mongo_srv", testutil.DatabaseURLNoPort("mongodb+srv", "u", "p", "cluster.example.com", "d").Value},
		{"anthropic_key", testutil.AnthropicKey().Value},
		{"circleci_token", testutil.CircleCIToken().Value},
		{"sentry_user_token", testutil.SentryUserToken().Value},
		{"rubygems_key", testutil.RubyGemsKey().Value},
		{"newrelic_key", testutil.NewRelicKey().Value},
		{"private_key_rsa", testutil.PrivateKey("RSA ").Value},
		{"private_key_generic", testutil.PrivateKey("").Value},
		{"env_secret_keyword", "SECRET_KEY=" + testutil.RandAlphaNum(24)},
		{"env_secret_colon", "AUTH_TOKEN: " + testutil.RandAlphaNum(20)},
		{"heuristic_secret_value", "WIDGET_CONFIG=" + heuristicVal},
	}

	caught := 0
	for _, c := range cases {
		if Scrub(c.text).Redacted {
			caught++
		} else {
			t.Errorf("false negative: %s not redacted\n  in: %q", c.name, c.text)
		}
	}
	t.Logf("recall: %d/%d synthetic secrets caught", caught, len(cases))

	// Realistic multi-secret payload: a .env dump inside a hook JSON.
	if r := Scrub(testutil.HookPayload()); r.Count < 8 {
		t.Errorf("hook payload recall low: caught %d, want >= 8", r.Count)
	} else {
		t.Logf("hook payload: %d secrets caught", r.Count)
	}
}
