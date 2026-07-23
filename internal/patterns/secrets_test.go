package patterns

import (
	"strings"
	"testing"

	"github.com/svn-arv/redacted/internal/testutil"
)

func TestScrub_BuiltinPatterns(t *testing.T) {
	// Generate all fake secrets at runtime to avoid GitHub push protection.
	awsKey := testutil.AWSAccessKey()
	awsSecretRaw := testutil.AWSSecretKey()
	awsSecret := testutil.EnvSecret("aws_secret_access_key", awsSecretRaw.Value)
	awsSecretColon := testutil.EnvSecretColon("aws_secret_access_key", awsSecretRaw.Value)

	ghpToken := testutil.GitHubToken("ghp_")
	ghsToken := testutil.GitHubToken("ghs_")
	ghoToken := testutil.GitHubToken("gho_")
	ghrToken := testutil.GitHubToken("ghr_")
	ghFineGrained := testutil.GitHubFineGrained()

	stripeLiveSK := testutil.StripeKey("sk_live_")
	stripeLivePK := testutil.StripeKey("pk_live_")
	stripeLiveRK := testutil.StripeKey("rk_live_")
	stripeTestSK := testutil.StripeKey("sk_test_")
	stripeTestPK := testutil.StripeKey("pk_test_")

	twilioAPI := testutil.TwilioSID("SK")
	twilioSID := testutil.TwilioSID("AC")

	doToken := testutil.DigitalOceanToken()
	doSpacesAccess := testutil.DigitalOceanSpaces("SPACES_ACCESS_KEY")
	doSpacesSecret := testutil.DigitalOceanSpaces("SPACES_SECRET_KEY")

	sentryDSN := testutil.SentryDSN()
	sentryDSNSub := testutil.SentryDSNSubdomain()

	slackBot := testutil.SlackToken("xoxb")
	slackUser := testutil.SlackToken("xoxp")
	slackApp := testutil.SlackToken("xoxa")

	sendgrid := testutil.SendGridKey()
	hubspotNA := testutil.HubSpotPAT("na1")
	hubspotEU := testutil.HubSpotPAT("eu1")

	rsaKey := testutil.PrivateKey("RSA ")
	ecKey := testutil.PrivateKey("EC ")
	opensshKey := testutil.PrivateKey("OPENSSH ")
	genericKey := testutil.PrivateKey("")

	jwt := testutil.JWT()

	// Passwords are randomized so these fixtures don't collide with the
	// allow_values placeholder-URL rows (a literal `:pass@` would be cleared).
	postgresURL := testutil.DatabaseURL("postgres", "user", testutil.RandAlphaNum(12), "db.example.com", "5432", "mydb")
	postgresParams := testutil.DatabaseURLWithParams("postgres", "user", testutil.RandAlphaNum(12), "host", "5432", "db", "sslmode=require")
	mysqlURL := testutil.DatabaseURL("mysql", "root", "secret", "localhost", "3306", "app")
	mongoURL := testutil.DatabaseURL("mongodb", "admin", testutil.RandAlphaNum(12), "cluster.example.com", "27017", "db")
	mongoSRV := testutil.DatabaseURLNoPort("mongodb+srv", "admin", testutil.RandAlphaNum(12), "cluster.example.com", "db")
	redisURL := testutil.DatabaseURL("redis", "default", testutil.RandAlphaNum(12), "redis.example.com", "6379", "")
	redissURL := testutil.DatabaseURL("rediss", "default", testutil.RandAlphaNum(12), "redis.example.com", "6379", "")
	amqpURL := testutil.DatabaseURL("amqp", "guest", "guest", "rabbitmq.example.com", "5672", "vhost")
	amqpsURL := testutil.DatabaseURL("amqps", "guest", "guest", "rabbitmq.example.com", "5671", "vhost")

	envSecretVal := "Xy7" + testutil.RandAlphaNum(12) // pinned digit: feeds lenient `:`/spaced-`=` rows
	envPassVal := testutil.RandAlphaNum(20)
	envTokenVal := testutil.RandAlphaNum(18)
	envGenericVal := testutil.RandAlphaNum(18)
	envAccessVal := testutil.RandAlphaNum(16)
	envCredVal := testutil.RandAlphaNum(20)
	envEncVal := "enc_" + testutil.RandAlphaNum(22)
	envSignVal := "sig_" + testutil.RandAlphaNum(22)

	yamlSecretBase := testutil.RandAlphaNum(20)
	yamlTokenVal := testutil.RandAlphaNum(18)
	yamlPassVal := testutil.RandAlphaNum(15) + "!"

	tests := []struct {
		name       string
		input      string
		wantClean  bool
		wantSubstr string
		wantHint   string
	}{
		// === AWS ===
		{"aws access key", "key: " + awsKey.Value, false, "[REDACTED:aws_access_key", awsKey.Hint},
		{"aws access key in url", "https://s3.amazonaws.com/?AWSAccessKeyId=" + awsKey.Value, false, "[REDACTED:aws_access_key", awsKey.Hint},
		{"aws secret key", awsSecret.Value, false, "aws_secret_access_key= [REDACTED", awsSecretRaw.Hint},
		{"aws secret key colon", awsSecretColon.Value, false, "aws_secret_access_key: [REDACTED", awsSecretRaw.Hint},

		// === GitHub ===
		{"github pat", "token=" + ghpToken.Value, false, "[REDACTED:github_token", ghpToken.Hint},
		{"github server", "token=" + ghsToken.Value, false, "[REDACTED:github_token", ghsToken.Hint},
		{"github oauth", ghoToken.Value, false, "[REDACTED:github_oauth", ghoToken.Hint},
		{"github refresh", ghrToken.Value, false, "[REDACTED:github_refresh", ghrToken.Hint},
		{"github fine grained", ghFineGrained.Value, false, "[REDACTED:github_fine_grained", ghFineGrained.Hint},

		// === Stripe ===
		{"stripe live secret", stripeLiveSK.Value, false, "[REDACTED:stripe_live", stripeLiveSK.Hint},
		{"stripe live publishable", stripeLivePK.Value, false, "[REDACTED:stripe_live", stripeLivePK.Hint},
		{"stripe live restricted", stripeLiveRK.Value, false, "[REDACTED:stripe_live", stripeLiveRK.Hint},
		{"stripe test secret", stripeTestSK.Value, false, "[REDACTED:stripe_test", stripeTestSK.Hint},
		{"stripe test publishable", stripeTestPK.Value, false, "[REDACTED:stripe_test", stripeTestPK.Hint},

		// === Twilio ===
		{"twilio api key", twilioAPI.Value, false, "[REDACTED:twilio_api_key", twilioAPI.Hint},
		{"twilio account sid", twilioSID.Value, false, "[REDACTED:twilio_account_sid", twilioSID.Hint},

		// === DigitalOcean ===
		{"do token", doToken.Value, false, "[REDACTED:digitalocean_token", doToken.Hint},
		{"do spaces access", doSpacesAccess.Value, false, "SPACES_ACCESS_KEY= [REDACTED", doSpacesAccess.Hint},
		{"do spaces secret", doSpacesSecret.Value, false, "SPACES_SECRET_KEY= [REDACTED", doSpacesSecret.Hint},

		// === Sentry ===
		{"sentry dsn", sentryDSN.Value, false, "[REDACTED:sentry_dsn", sentryDSN.Hint},
		{"sentry dsn with subdomain", sentryDSNSub.Value, false, "[REDACTED:sentry_dsn", sentryDSNSub.Hint},

		// === Slack ===
		{"slack bot token", slackBot.Value, false, "[REDACTED:slack_token", slackBot.Hint},
		{"slack user token", slackUser.Value, false, "[REDACTED:slack_token", slackUser.Hint},
		{"slack app token", slackApp.Value, false, "[REDACTED:slack_token", slackApp.Hint},

		// === SendGrid ===
		{"sendgrid key", sendgrid.Value, false, "[REDACTED:sendgrid_key", sendgrid.Hint},

		// === HubSpot ===
		{"hubspot key 2 char region", hubspotNA.Value, false, "[REDACTED:hubspot_key", hubspotNA.Hint},
		{"hubspot key 3 char region", hubspotEU.Value, false, "[REDACTED:hubspot_key", hubspotEU.Hint},

		// === Private keys ===
		{"rsa private key", rsaKey.Value, false, "[REDACTED:private_key", "----"},
		{"ec private key", ecKey.Value, false, "[REDACTED:private_key", "----"},
		{"openssh private key", opensshKey.Value, false, "[REDACTED:private_key", "----"},
		{"generic private key", genericKey.Value, false, "[REDACTED:private_key", "----"},

		// === JWTs ===
		{"jwt", jwt.Value, false, "[REDACTED:jwt", jwt.Hint},
		{"jwt in header", "Authorization: Bearer " + jwt.Value, false, "[REDACTED:jwt", jwt.Hint},

		// === Anthropic ===
		{"anthropic key", testutil.AnthropicKey().Value, false, "[REDACTED:anthropic_key", ""},

		// === CircleCI ===
		{"circleci token", testutil.CircleCIToken().Value, false, "[REDACTED:circleci_token", ""},

		// === Sentry user token ===
		{"sentry user token", testutil.SentryUserToken().Value, false, "[REDACTED:sentry_user_token", ""},

		// === RubyGems ===
		{"rubygems key", testutil.RubyGemsKey().Value, false, "[REDACTED:rubygems_key", ""},

		// === New Relic ===
		{"newrelic key", testutil.NewRelicKey().Value, false, "[REDACTED:newrelic_key", ""},

		// === Database URLs ===
		{"postgres url", postgresURL.Value, false, "[REDACTED:database_url", postgresURL.Hint},
		{"postgres with params", postgresParams.Value, false, "[REDACTED:database_url", postgresParams.Hint},
		{"mysql url", mysqlURL.Value, false, "[REDACTED:database_url", mysqlURL.Hint},
		{"mongodb url", mongoURL.Value, false, "[REDACTED:database_url", mongoURL.Hint},
		{"mongodb srv", mongoSRV.Value, false, "[REDACTED:database_url", mongoSRV.Hint},
		{"redis url", redisURL.Value, false, "[REDACTED:database_url", redisURL.Hint},
		{"redis tls url", redissURL.Value, false, "[REDACTED:database_url", redissURL.Hint},
		{"amqp url", amqpURL.Value, false, "[REDACTED:database_url", amqpURL.Hint},
		{"amqps url", amqpsURL.Value, false, "[REDACTED:database_url", amqpsURL.Hint},

		// === Env-style catch-all ===
		{"env secret key", "SECRET_KEY=" + envSecretVal, false, "SECRET_KEY= [REDACTED", envSecretVal[len(envSecretVal)-4:]},
		{"env password", "DB_PASSWORD=" + envPassVal, false, "DB_PASSWORD= [REDACTED", envPassVal[len(envPassVal)-4:]},
		{"env auth token", "AUTH_TOKEN=" + envTokenVal, false, "AUTH_TOKEN= [REDACTED", envTokenVal[len(envTokenVal)-4:]},
		{"env generic secret", "MY_SECRET_VALUE=" + envGenericVal, false, "MY_SECRET_VALUE= [REDACTED", envGenericVal[len(envGenericVal)-4:]},
		{"env access key", "ACCESS_KEY_ID=" + envAccessVal, false, "ACCESS_KEY_ID= [REDACTED", envAccessVal[len(envAccessVal)-4:]},
		{"env credential", "DB_CREDENTIAL=" + envCredVal, false, "DB_CREDENTIAL= [REDACTED", envCredVal[len(envCredVal)-4:]},
		{"env encryption key", "ENCRYPTION_KEY=" + envEncVal, false, "ENCRYPTION_KEY= [REDACTED", envEncVal[len(envEncVal)-4:]},
		{"env signing key", "SIGNING_KEY=" + envSignVal, false, "SIGNING_KEY= [REDACTED", envSignVal[len(envSignVal)-4:]},
		{"env with colon", "SECRET_KEY: " + envSecretVal, false, "SECRET_KEY: [REDACTED", envSecretVal[len(envSecretVal)-4:]},
		{"env with spaces", "SECRET_KEY = " + envSecretVal, false, "SECRET_KEY = [REDACTED", envSecretVal[len(envSecretVal)-4:]},

		// === Hyphen-separated keys (HTTP headers, YAML, CLI flags) ===
		{"hyphen api-key", "api-key=" + testutil.RandAlphaNum(24), false, "api-key= [REDACTED", ""},
		{"hyphen x-api-key header", "x-api-key: aB3" + testutil.RandAlphaNum(17), false, "x-api-key: [REDACTED", ""},
		{"hyphen private-key", "private-key=" + testutil.RandAlphaNum(30), false, "private-key= [REDACTED", ""},
		{"hyphen access-key", "AWS-ACCESS-KEY=" + testutil.RandAlphaNum(20), false, "AWS-ACCESS-KEY= [REDACTED", ""},
		{"hyphen database-url", "database-url=postgresql://host/db?a=bcdefghi", false, "database-url=[REDACTED", ""},
		{"hyphen db-pass", "db-pass=" + testutil.RandAlphaNum(16), false, "db-pass= [REDACTED", ""},
		{"hyphen dsn suffix", "sentry-dsn=https://abc.example.com/path/val", false, "sentry-dsn= [REDACTED", ""},
		{"hyphen sid suffix", "twilio-workspace-sid=WS" + testutil.RandAlphaNum(16), false, "twilio-workspace-sid= [REDACTED", ""},

		// === YAML catch-all ===
		{"yaml secret", "  - key: SECRET_KEY_BASE\n    value: " + yamlSecretBase, false, "key: [REDACTED", yamlSecretBase[len(yamlSecretBase)-4:]},
		{"yaml token", "  - key: AUTH_TOKEN\n    value: " + yamlTokenVal, false, "key: [REDACTED", yamlTokenVal[len(yamlTokenVal)-4:]},
		{"yaml password", "  - key: DB_PASSWORD\n    value: " + yamlPassVal, false, "key: [REDACTED", yamlPassVal[len(yamlPassVal)-4:]},

		// === New keyword coverage ===
		{"client id", "VOLTADE_CLIENT_ID=" + testutil.RandAlphaNum(20), false, "VOLTADE_CLIENT_ID= [REDACTED", ""},
		{"license key", "NEW_RELIC_LICENSE_KEY=" + envSecretVal, false, "NEW_RELIC_LICENSE_KEY= [REDACTED", envSecretVal[len(envSecretVal)-4:]},
		{"dsn var", "SENTRY_DSN=https://example.com/something/long", false, "SENTRY_DSN= [REDACTED", "long"},
		{"sid var", "TWILIO_WORKSPACE_SID=WS" + testutil.RandAlphaNum(16), false, "TWILIO_WORKSPACE_SID= [REDACTED", ""},
		{"account id", "AWS_ACCOUNT_ID=" + testutil.RandDigits(12), false, "AWS_ACCOUNT_ID= [REDACTED", ""},
		{"service key", "GCP_SERVICE_KEY=" + testutil.RandAlphaNum(22), false, "GCP_SERVICE_KEY= [REDACTED", ""},
		{"postgresql url", testutil.DatabaseURL("postgresql", "user", testutil.RandAlphaNum(12), "host", "5432", "db").Value, false, "[REDACTED:database_url", ""},

		// === Multi-secret in one string ===
		{"multiple secrets", "DB=" + postgresURL.Value + "\nKEY=" + awsKey.Value, false, "[REDACTED", ""},

		// === Should NOT redact ===
		{"clean text", "just normal command output, nothing secret here", true, "", ""},
		{"short values ignored", "TOKEN=abc", true, "", ""},
		{"normal git output", "On branch main\nYour branch is up to date with 'origin/main'.", true, "", ""},
		{"ls output", "total 8\n-rw-r--r-- 1 user user 1234 Jan 1 00:00 main.go", true, "", ""},
		{"npm install output", "added 150 packages in 3s", true, "", ""},
		{"go test output", "ok  \tgithub.com/example/pkg\t0.003s", true, "", ""},
		{"safe env var", "APP_NAME=myapplication", true, "", ""},
		{"safe port var", "PORT=3000", true, "", ""},
		{"safe log level", "LOG_LEVEL=debug", true, "", ""},
		{"safe rails env", "RAILS_ENV=production", true, "", ""},
		{"short password value", "PASSWORD=short", true, "", ""},
		{"safe order id", "ORDER_ID=12345", true, "", ""},
		{"safe base url", "BASE_URL=https://example.com", true, "", ""},
		{"safe app url", "APP_URL=https://myapp.com", true, "", ""},

		// === Bare URLs: a scheme colon (https://) is not a KEY:value separator ===
		{"bare github issue url", "https://github.com/Luce-MG/luce-product-design/issues/123", true, "", ""},
		{"bare github pull url in text", "See https://github.com/Luce-MG/luce-product-design/pull/4567 for details", true, "", ""},
		{"bare url mixed-case path", "https://docs.example.com/d/abcDEF123ghiJKL/edit", true, "", ""},
		// A port colon reads as a second host:port separator, but the token
		// carries a scheme, so the URL-context skip keeps it clean.
		{"port url uppercase path", "https://example.com:8080/FooBar/Baz123", true, "", ""},

		// === Identifier-like values in source code (should NOT redact) ===
		{"ruby assignment", "token = not_token", true, "", ""},
		{"ruby colon", "token: other_token", true, "", ""},
		{"ruby const assign", "TOKEN = OTHER_TOKEN_CONST", true, "", ""},
		{"python snake case", "secret_key = secret_key_var", true, "", ""},
		{"ruby hash access", "token = params[:token]", true, "", ""},
		{"ruby instance var", "token = @other_token", true, "", ""},
		{"cross string boundary", `{"SECRET_KEY=[REDACTED", more},`, true, "", ""},
		{"ruby method call value", "context_object: { credit_account_id: credit_account.id },", true, "", ""},
		{"dotted accessor", "client_id: user.account_id", true, "", ""},

		// === Real-looking values still redact ===
		{"value with digits", "TOKEN=my_token_123", false, "TOKEN= [REDACTED", "_123"},
		{"mixed case value", "TOKEN=MyRealSecretToken", false, "TOKEN= [REDACTED", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Scrub(tt.input)

			if tt.wantClean {
				if result.Redacted {
					t.Errorf("expected clean output, but got redacted: %s", result.Text)
				}
				if result.Text != tt.input {
					t.Errorf("expected unchanged text\n got: %s\nwant: %s", result.Text, tt.input)
				}
				return
			}

			if !result.Redacted {
				t.Errorf("expected redaction but text was unchanged: %s", result.Text)
			}
			if result.Count == 0 {
				t.Error("expected Count > 0")
			}
			if tt.wantSubstr != "" && !strings.Contains(result.Text, tt.wantSubstr) {
				t.Errorf("expected %q in output\ngot: %s", tt.wantSubstr, result.Text)
			}
			if tt.wantHint != "" && !strings.Contains(result.Text, "..."+tt.wantHint+"]") {
				t.Errorf("expected hint ...%s] in output\ngot: %s", tt.wantHint, result.Text)
			}
		})
	}
}

func TestRedact_ValueOnly(t *testing.T) {
	got := redact("stripe_live", "sk_live_abcdefghijklmnop", false)
	if got != "[REDACTED:stripe_live ...mnop]" {
		t.Errorf("value-only redact = %q", got)
	}
}

func TestRedact_KeyValue(t *testing.T) {
	got := redact("env_secret", "SECRET_KEY=abcdef123456789", true)
	want := "SECRET_KEY= [REDACTED ...6789]"
	if got != want {
		t.Errorf("key=value redact = %q, want %q", got, want)
	}
}

func TestRedact_KeyColon(t *testing.T) {
	got := redact("env_secret", "SECRET_KEY: abcdef123456789", true)
	want := "SECRET_KEY: [REDACTED ...6789]"
	if got != want {
		t.Errorf("key:value redact = %q, want %q", got, want)
	}
}

func TestScrub_MultipleSecretsCount(t *testing.T) {
	db := testutil.DatabaseURL("postgres", "u", "p", "h", "5432", "d")
	stripe := testutil.StripeKey("sk_live_")
	aws := testutil.AWSAccessKey()
	input := "DB=" + db.Value + "\nSTRIPE=" + stripe.Value + "\nKEY=" + aws.Value
	result := Scrub(input)

	if result.Count < 3 {
		t.Errorf("expected at least 3 redactions, got %d: %s", result.Count, result.Text)
	}
}

func TestScrub_PreservesContext(t *testing.T) {
	db := testutil.DatabaseURL("postgres", "u", "p", "h", "5432", "d")
	input := "Starting server on port 3000\nDATABASE_URL=" + db.Value + "\nReady to accept connections"
	result := Scrub(input)

	if !strings.Contains(result.Text, "Starting server on port 3000") {
		t.Error("non-secret text before secret was modified")
	}
	if !strings.Contains(result.Text, "Ready to accept connections") {
		t.Error("non-secret text after secret was modified")
	}
	if !result.Redacted {
		t.Error("expected redaction")
	}
}

func TestScrub_EmptyInput(t *testing.T) {
	result := Scrub("")
	if result.Redacted {
		t.Error("empty input should not be redacted")
	}
	if result.Text != "" {
		t.Errorf("expected empty output, got: %s", result.Text)
	}
	if result.Count != 0 {
		t.Errorf("expected count 0, got %d", result.Count)
	}
}

func TestScrubber_WithWhitelist(t *testing.T) {
	s := New(WithWhitelist("jwt", "stripe_test"))

	jwt := testutil.JWT()
	result := s.Scrub(jwt.Value)
	if result.Redacted {
		t.Errorf("jwt should be whitelisted, got: %s", result.Text)
	}

	stripeTest := testutil.StripeKey("sk_test_")
	result = s.Scrub(stripeTest.Value)
	if result.Redacted {
		t.Errorf("stripe_test should be whitelisted, got: %s", result.Text)
	}

	stripeLive := testutil.StripeKey("sk_live_")
	result = s.Scrub(stripeLive.Value)
	if !result.Redacted {
		t.Error("stripe_live should NOT be whitelisted")
	}
}

func TestScrubber_WithWhitelist_NonexistentPattern(t *testing.T) {
	s := New(WithWhitelist("nonexistent_pattern"))

	aws := testutil.AWSAccessKey()
	result := s.Scrub(aws.Value)
	if !result.Redacted {
		t.Error("whitelisting a nonexistent pattern should not break redaction")
	}
}

func TestScrubber_WithAllow(t *testing.T) {
	s := New(WithAllow("TWILIO_WORKFLOW_SID"))

	result := s.Scrub("TWILIO_WORKFLOW_SID=WW" + testutil.RandHex(30) + "e9")
	if result.Redacted {
		t.Errorf("TWILIO_WORKFLOW_SID should be allowed, got: %s", result.Text)
	}

	result = s.Scrub("TWILIO_WORKSPACE_SID=WS" + testutil.RandAlphaNum(16))
	if !result.Redacted {
		t.Error("TWILIO_WORKSPACE_SID should still be redacted")
	}
}

func TestScrubber_WithAllow_CaseInsensitive(t *testing.T) {
	s := New(WithAllow("twilio_workflow_sid"))

	result := s.Scrub("TWILIO_WORKFLOW_SID=WW" + testutil.RandHex(30) + "e9")
	if result.Redacted {
		t.Errorf("allow should be case-insensitive, got: %s", result.Text)
	}
}

func TestScrubber_WithExtra(t *testing.T) {
	s := New(WithExtra("custom_webhook", `https://hooks\.example\.com/services/\S+`))

	input := "WEBHOOK=https://hooks.example.com/services/T00/B00/xxxx"
	result := s.Scrub(input)

	if !result.Redacted {
		t.Error("expected custom pattern to match")
	}
	if !strings.Contains(result.Text, "[REDACTED") {
		t.Errorf("expected redaction, got: %s", result.Text)
	}
}

func TestScrubber_WithExtra_DoesNotBreakBuiltins(t *testing.T) {
	s := New(WithExtra("custom", `CUSTOM_THING_\d+`))

	aws := testutil.AWSAccessKey()
	result := s.Scrub(aws.Value)
	if !result.Redacted {
		t.Error("adding extra pattern should not break built-in patterns")
	}
	if !strings.Contains(result.Text, "[REDACTED:aws_access_key") {
		t.Errorf("expected aws_access_key redaction, got: %s", result.Text)
	}
}

func TestScrubber_WithKeywords(t *testing.T) {
	s := New(WithKeywords("MONGO", "ELASTIC"))

	result := s.Scrub("MONGO_URI=mongodb+srv://user:" + testutil.RandAlphaNum(12) + "@cluster.example.com")
	if !result.Redacted {
		t.Error("expected MONGO keyword to match")
	}

	result = s.Scrub("ELASTIC_PASSWORD=" + testutil.RandAlphaNum(20))
	if !result.Redacted {
		t.Error("expected ELASTIC keyword to match")
	}

	result = s.Scrub("APP_NAME=myapplication")
	if result.Redacted {
		t.Errorf("APP_NAME should not match, got: %s", result.Text)
	}
}

func TestScrubber_WithKeywords_Empty(t *testing.T) {
	s := New(WithKeywords())

	aws := testutil.AWSAccessKey()
	result := s.Scrub(aws.Value)
	if !result.Redacted {
		t.Error("empty keywords should not break built-in patterns")
	}
}

func TestScrubber_CombinedOptions(t *testing.T) {
	s := New(
		WithWhitelist("jwt"),
		WithExtra("custom_token", `ctk_[a-z0-9]{32}`),
		WithKeywords("KAFKA"),
		WithAllow("KAFKA_BROKER"),
	)

	jwt := testutil.JWT()
	result := s.Scrub(jwt.Value)
	if result.Redacted {
		t.Error("jwt should be whitelisted")
	}

	result = s.Scrub("ctk_abcdefghijklmnopqrstuvwxyz012345")
	if !result.Redacted {
		t.Error("custom token should be redacted")
	}

	result = s.Scrub("KAFKA_PASSWORD=" + testutil.RandAlphaNum(20))
	if !result.Redacted {
		t.Error("KAFKA keyword should trigger redaction")
	}

	result = s.Scrub("KAFKA_BROKER=broker.example.com:9092")
	if result.Redacted {
		t.Errorf("KAFKA_BROKER should be allowed, got: %s", result.Text)
	}

	stripe := testutil.StripeKey("sk_live_")
	result = s.Scrub(stripe.Value)
	if !result.Redacted {
		t.Error("built-in stripe should still work")
	}
}

func TestScrub_NoDoubleRedaction(t *testing.T) {
	doToken := testutil.DigitalOceanToken()
	stripe := testutil.StripeKey("sk_live_")
	sentry := testutil.SentryDSN()

	tests := []struct {
		name     string
		input    string
		wantKey  string
		denyType string
	}{
		{
			"do token in env var",
			"MY_TOKEN=" + doToken.Value,
			"[REDACTED:digitalocean_token",
			"env_secret",
		},
		{
			"stripe key in env var",
			"STRIPE_KEY=" + stripe.Value,
			"[REDACTED:stripe_live",
			"env_secret",
		},
		{
			"sentry dsn in env var",
			"MY_DSN=" + sentry.Value,
			"[REDACTED:sentry_dsn",
			"env_secret",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Scrub(tt.input)
			if !strings.Contains(result.Text, tt.wantKey) {
				t.Errorf("expected %s, got: %s", tt.wantKey, result.Text)
			}
			if strings.Contains(result.Text, "[REDACTED:"+tt.denyType) && strings.Contains(result.Text, tt.denyType+"=[REDACTED") {
				t.Errorf("double redaction detected, got: %s", result.Text)
			}
		})
	}
}

func TestNew_DefaultScrubberMatchesPackageLevel(t *testing.T) {
	s := New()
	aws := testutil.AWSAccessKey()

	pkgResult := Scrub(aws.Value)
	instanceResult := s.Scrub(aws.Value)

	if pkgResult.Text != instanceResult.Text {
		t.Errorf("package-level Scrub and New() Scrub differ:\npkg: %s\ninst: %s", pkgResult.Text, instanceResult.Text)
	}
	if pkgResult.Count != instanceResult.Count {
		t.Errorf("count differs: pkg=%d inst=%d", pkgResult.Count, instanceResult.Count)
	}
}

// TestScrub_DottedIdentifierGuardrail verifies that values with dots and
// digits (e.g. version strings, real-looking tokens with mixed content) are
// still redacted, even though plain dotted identifier paths are now skipped.
func TestScrub_DottedIdentifierGuardrail(t *testing.T) {
	result := Scrub("TOKEN=abc.def.ghi123")
	if !result.Redacted {
		t.Errorf("dotted value with digits should still redact, got: %s", result.Text)
	}
}

// Connection-string templates that use ${VAR} placeholders carry no literal
// credentials, so database_url must not match across the ${...}. A URL with
// real credentials must still redact even when a component is templated —
// the match simply stops at the ${, it is never exempted away.
//
// Operator forms like ${VAR:-default} are intentionally not covered: they can
// carry a value, so they stay subject to the normal patterns.
func TestScrub_DatabaseURLTemplate(t *testing.T) {
	passthrough := []string{
		"postgresql://${POSTGRES_HOST}/mydb",
		"redis://${REDIS_HOST}:${REDIS_PORT}/${REDIS_DB}",
		"mongodb://${USER}:${PASS}@${HOST}",
		"const url = `postgresql://${HOST}/db`",
	}
	for _, in := range passthrough {
		if result := Scrub(in); result.Redacted {
			t.Errorf("expected no redaction for template %q, got: %q", in, result.Text)
		}
	}

	// Real credentials redact even though the host is a ${...} placeholder.
	withCreds := "postgres://user:realpass@${HOST}/db"
	result := Scrub(withCreds)
	if !result.Redacted {
		t.Errorf("expected redaction for credentialed URL %q, got: %q", withCreds, result.Text)
	}
	if strings.Contains(result.Text, "realpass") {
		t.Errorf("real password leaked through templated URL: %q", result.Text)
	}
}

// Guardrail: value_safe_char excludes (, `, {, <, so these shapes don't form
// a matchable value. Test ensures a future loosening of that char class
// doesn't silently regress them.
func TestScrub_StructurallySafeBashConstructs(t *testing.T) {
	cases := []string{
		"PASSWORD=$(vault read secret/db_password)",
		"API_KEY=`get-key-from-secret-manager`",
		"TOKEN=$((1 + computed_value))",
		"SECRET=<(curl -s https://vault/secret)",
		"PASSWORD: ${{ secrets.DB_PASSWORD }}",
		"API_KEY: ${{ steps.auth.outputs.token }}",
		"SECRET={{ .Values.password }}",
	}
	for _, in := range cases {
		result := Scrub(in)
		if result.Redacted {
			t.Errorf("expected no redaction for %q, got: %q", in, result.Text)
		}
	}
}

func TestScrub_BashExpansionAdjacentRealSecret(t *testing.T) {
	aws := testutil.AWSAccessKey()
	input := "TEMPLATE=postgresql://${HOST}/db\nREAL=" + aws.Value
	result := Scrub(input)
	if !result.Redacted {
		t.Errorf("expected real secret to be redacted, got: %q", result.Text)
	}
	if !strings.Contains(result.Text, "[REDACTED:aws_access_key") {
		t.Errorf("expected aws_access_key redaction, got: %q", result.Text)
	}
	if !strings.Contains(result.Text, "postgresql://${HOST}/db") {
		t.Errorf("template should pass through unchanged, got: %q", result.Text)
	}
}

// TestScrub_EmptyValueDoesNotConsumeNextLine verifies that an empty
// `KEY=` (or `KEY:`) does not pull the following line's `NEXT_KEY=` into
// the match. Previously `\s*` after the separator could swallow the newline,
// causing the next line to be redacted as if it were the value.
func TestScrub_EmptyValueDoesNotConsumeNextLine(t *testing.T) {
	cases := []string{
		"AI_API_KEY=\nAI_BACKEND_URL=\n",
		"AI_API_KEY=\nAI_BACKEND_URL=",
		"# AI Setup\nAI_API_KEY=\nAI_BACKEND_URL=\n",
		"SECRET_KEY:\nSOME_OTHER_VAR=\n",
		"API_KEY = \nNEXT_VAR=\n",
	}
	for _, in := range cases {
		result := Scrub(in)
		if result.Redacted {
			t.Errorf("expected no redaction for empty-value input %q, got: %q", in, result.Text)
		}
	}
}

// TestScrub_HeuristicValues covers the secret_value catch-all: an assignment is
// redacted when the VALUE is statistically secret-like, regardless of whether
// the key contains a known keyword. This is the generalization past the fixed
// keyword list. Precision-first, so structured high-entropy shapes (UUIDs, git
// SHAs, hex digests) must pass through untouched.
func TestScrub_HeuristicValues(t *testing.T) {
	redact := []struct {
		name, input, wantSubstr string
	}{
		// Non-keyword keys whose values look like random credentials.
		{"non-keyword mixed token =", "WIDGET=aB3xK9pLq2mNz7rT4vWy", "WIDGET= [REDACTED"},
		{"non-keyword mixed token :", "thing: aB3xK9pLq2mNz7rT4vWy", "thing: [REDACTED"},
		{"unknown vendor key", "DECK_HANDLE=Zx9Kq2Lm8Pn4Rt6Vw1Yb3Hc", "DECK_HANDLE= [REDACTED"},
	}
	for _, tt := range redact {
		t.Run(tt.name, func(t *testing.T) {
			result := Scrub(tt.input)
			if !result.Redacted {
				t.Fatalf("expected redaction, got unchanged: %q", result.Text)
			}
			if !strings.Contains(result.Text, tt.wantSubstr) {
				t.Errorf("expected %q in output, got: %q", tt.wantSubstr, result.Text)
			}
		})
	}

	clean := []struct {
		name, input string
	}{
		{"git sha lowercase hex", "GIT_COMMIT=a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"},
		{"uuid", "BUILD_ID=550e8400-e29b-41d4-a716-446655440000"},
		{"sha256 hex digest", "CHECKSUM=ab12cd34ab12cd34ab12cd34ab12cd34ab12cd34ab12cd34ab12cd34ab12cd34"},
		{"semver", "RELEASE=v1.2.3-rc.1"},
		{"iso timestamp", "STAMP=2026-06-17T12:00:00Z"},
		{"single-case alnum value", "API_HASH=abcdef1234567890abcdef12"},
		{"low-entropy repetitive 3-class", "CODE=Aa1Aa1Aa1Aa1Aa1Aa1Aa1Aa1"},
		{"over max length", "BLOB=" + testutil.RandAlphaNum(140)},
		{"short mixed value", "NONCE=aB3xK9"},
		{"url without credentials", "ENDPOINT=https://api.example.com/v2/resources"},
		{"file path", "OUTPUT=/var/log/app/output/file.log"},
	}
	for _, tt := range clean {
		t.Run(tt.name, func(t *testing.T) {
			result := Scrub(tt.input)
			if result.Redacted {
				t.Errorf("expected no redaction, got: %q", result.Text)
			}
		})
	}
}

// TestScrub_CodeReferenceValues covers the main source-code false positive:
// when a keyword-named variable is assigned from an environment lookup, the
// captured value is the code reference (a constant path or method chain), not a
// literal secret, so it must pass through unredacted.
func TestScrub_CodeReferenceValues(t *testing.T) {
	clean := []string{
		// Dotted constant paths and method chains.
		"secret_key = ENV.fetch('SECRET_KEY')",
		"api_key: ENV.fetch('SECRET_KEY')",
		"SECRET_KEY = ENV.fetch('SECRET_KEY')",
		"config.secret_token = Rails.application.secrets.secret_key_base",
		"twilio_auth_token = Rails.application.credentials.dig(:twilio, :auth_token)",
		"password = ENV['DB_PASSWORD']",
		// Method calls and index access with no dot (trailing `(` or `[`).
		"queue_sid: GetTwilioSid(proxy_address, 'TWILIO_QUEUE_SID')",
		"auth_token: fetchToken(client)",
		"secret = configuration[:database]",
		// Ruby `::` namespace constant.
		"secret_key: MyApp::Config::TOKEN_V2",
	}
	for _, in := range clean {
		if result := Scrub(in); result.Redacted {
			t.Errorf("expected no redaction for code reference %q, got: %q", in, result.Text)
		}
	}

	// Guardrails: a real literal assigned in source must still be redacted, and a
	// single-case value (no uppercase code segment) is not exempted by a separator.
	redactGuards := []string{
		"secret_key = Xk7Pq9mW2vB8nZ4cA1fH",
		"TOKEN=abc.def.ghi123",
		"SECRET=abcdefgh::ijklmnopqr",
	}
	for _, in := range redactGuards {
		if result := Scrub(in); !result.Redacted {
			t.Errorf("expected redaction for %q, got: %q", in, result.Text)
		}
	}
}

// TestSecretLike checks each gate of the value scorer in isolation, so a change
// to one threshold can't silently weaken the others.
func TestSecretLike(t *testing.T) {
	cases := []struct {
		name string
		v    string
		want bool
	}{
		{"random mixed-case alphanumeric", "aB3xK9pLq2mNz7rT", true},
		{"too short", "aB3xK9pL", false},
		{"too long", strings.Repeat("aB3xK9pLq2mNz7rT", 9), false}, // 144 chars
		{"lowercase hex only (2 classes)", "a1b2c3d4e5f6a7b8c9d0", false},
		{"uppercase letters only (1 class)", "ABCDEFGHIJKLMNOP", false},
		{"mixed classes but repetitive (low entropy)", "Aa1Aa1Aa1Aa1Aa1Aa1", false},
		{"empty", "", false},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			if got := defaultScrubber.secretLike(tt.v); got != tt.want {
				t.Errorf("secretLike(%q) = %v, want %v", tt.v, got, tt.want)
			}
		})
	}
}

// TestSecretLike_PercentEncoded covers #35: values percent-decode before scoring.
// Encoded prose is rejected; encoded credentials and malformed escapes still score.
func TestSecretLike_PercentEncoded(t *testing.T) {
	cases := []struct {
		name string
		v    string
		want bool
	}{
		{"encoded prose decodes to spaces", "Re%3A%20Your%20letter&body=Hello%20world", false},
		{"encoded credential stays high-entropy", "Xy7%2BaK9mQ2rT8wZ4yP6vN3s%3D", true},
		{"malformed escape falls through to scoring", "Xy7%ZZaK9mQ2rT8wZ4yP6vN", true},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			if got := defaultScrubber.secretLike(tt.v); got != tt.want {
				t.Errorf("secretLike(%q) = %v, want %v", tt.v, got, tt.want)
			}
		})
	}
}

// TestShannonEntropy checks the ordering the scorer relies on: a varied string
// is less predictable (higher entropy) than a repetitive one of the same length.
func TestShannonEntropy(t *testing.T) {
	if h := shannonEntropy(""); h != 0 {
		t.Errorf("entropy of empty string = %v, want 0", h)
	}
	if h := shannonEntropy("aaaaaaaa"); h != 0 {
		t.Errorf("entropy of a single repeated rune = %v, want 0", h)
	}
	varied := shannonEntropy("abcdefgh")
	repetitive := shannonEntropy("aabbaabb")
	if varied <= repetitive {
		t.Errorf("expected varied (%v) > repetitive (%v)", varied, repetitive)
	}
}
