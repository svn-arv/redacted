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

	postgresURL := testutil.DatabaseURL("postgres", "user", "pass", "db.example.com", "5432", "mydb")
	postgresParams := testutil.DatabaseURLWithParams("postgres", "user", "pass", "host", "5432", "db", "sslmode=require")
	mysqlURL := testutil.DatabaseURL("mysql", "root", "secret", "localhost", "3306", "app")
	mongoURL := testutil.DatabaseURL("mongodb", "admin", "pass", "cluster.example.com", "27017", "db")
	mongoSRV := testutil.DatabaseURLNoPort("mongodb+srv", "admin", "pass", "cluster.example.com", "db")
	redisURL := testutil.DatabaseURL("redis", "default", "pass", "redis.example.com", "6379", "")
	redissURL := testutil.DatabaseURL("rediss", "default", "pass", "redis.example.com", "6379", "")
	amqpURL := testutil.DatabaseURL("amqp", "guest", "guest", "rabbitmq.example.com", "5672", "vhost")
	amqpsURL := testutil.DatabaseURL("amqps", "guest", "guest", "rabbitmq.example.com", "5671", "vhost")

	envSecretVal := testutil.RandAlphaNum(15)
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
		{"aws secret key", awsSecret.Value, false, "aws_secret_access_key=[REDACTED", awsSecretRaw.Hint},
		{"aws secret key colon", awsSecretColon.Value, false, "aws_secret_access_key=[REDACTED", awsSecretRaw.Hint},

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
		{"do spaces access", doSpacesAccess.Value, false, "SPACES_ACCESS_KEY=[REDACTED", doSpacesAccess.Hint},
		{"do spaces secret", doSpacesSecret.Value, false, "SPACES_SECRET_KEY=[REDACTED", doSpacesSecret.Hint},

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
		{"env secret key", "SECRET_KEY=" + envSecretVal, false, "SECRET_KEY=[REDACTED", envSecretVal[len(envSecretVal)-4:]},
		{"env password", "DB_PASSWORD=" + envPassVal, false, "DB_PASSWORD=[REDACTED", envPassVal[len(envPassVal)-4:]},
		{"env auth token", "AUTH_TOKEN=" + envTokenVal, false, "AUTH_TOKEN=[REDACTED", envTokenVal[len(envTokenVal)-4:]},
		{"env generic secret", "MY_SECRET_VALUE=" + envGenericVal, false, "MY_SECRET_VALUE=[REDACTED", envGenericVal[len(envGenericVal)-4:]},
		{"env access key", "ACCESS_KEY_ID=" + envAccessVal, false, "ACCESS_KEY_ID=[REDACTED", envAccessVal[len(envAccessVal)-4:]},
		{"env credential", "DB_CREDENTIAL=" + envCredVal, false, "DB_CREDENTIAL=[REDACTED", envCredVal[len(envCredVal)-4:]},
		{"env encryption key", "ENCRYPTION_KEY=" + envEncVal, false, "ENCRYPTION_KEY=[REDACTED", envEncVal[len(envEncVal)-4:]},
		{"env signing key", "SIGNING_KEY=" + envSignVal, false, "SIGNING_KEY=[REDACTED", envSignVal[len(envSignVal)-4:]},
		{"env with colon", "SECRET_KEY: " + envSecretVal, false, "SECRET_KEY=[REDACTED", envSecretVal[len(envSecretVal)-4:]},
		{"env with spaces", "SECRET_KEY = " + envSecretVal, false, "SECRET_KEY=[REDACTED", envSecretVal[len(envSecretVal)-4:]},

		// === YAML catch-all ===
		{"yaml secret", "  - key: SECRET_KEY_BASE\n    value: " + yamlSecretBase, false, "key=[REDACTED", yamlSecretBase[len(yamlSecretBase)-4:]},
		{"yaml token", "  - key: AUTH_TOKEN\n    value: " + yamlTokenVal, false, "key=[REDACTED", yamlTokenVal[len(yamlTokenVal)-4:]},
		{"yaml password", "  - key: DB_PASSWORD\n    value: " + yamlPassVal, false, "key=[REDACTED", yamlPassVal[len(yamlPassVal)-4:]},

		// === New keyword coverage ===
		{"client id", "VOLTADE_CLIENT_ID=" + testutil.RandAlphaNum(20), false, "VOLTADE_CLIENT_ID=[REDACTED", ""},
		{"license key", "NEW_RELIC_LICENSE_KEY=" + envSecretVal, false, "NEW_RELIC_LICENSE_KEY=[REDACTED", envSecretVal[len(envSecretVal)-4:]},
		{"dsn var", "SENTRY_DSN=https://example.com/something/long", false, "SENTRY_DSN=[REDACTED", "long"},
		{"sid var", "TWILIO_WORKSPACE_SID=WS" + testutil.RandAlphaNum(16), false, "TWILIO_WORKSPACE_SID=[REDACTED", ""},
		{"account id", "AWS_ACCOUNT_ID=" + testutil.RandDigits(12), false, "AWS_ACCOUNT_ID=[REDACTED", ""},
		{"service key", "GCP_SERVICE_KEY=" + testutil.RandAlphaNum(22), false, "GCP_SERVICE_KEY=[REDACTED", ""},
		{"postgresql url", testutil.DatabaseURL("postgresql", "user", "pass", "host", "5432", "db").Value, false, "[REDACTED:database_url", ""},

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
	want := "SECRET_KEY=[REDACTED ...6789]"
	if got != want {
		t.Errorf("key=value redact = %q, want %q", got, want)
	}
}

func TestRedact_KeyColon(t *testing.T) {
	got := redact("env_secret", "SECRET_KEY: abcdef123456789", true)
	want := "SECRET_KEY=[REDACTED ...6789]"
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

	result := s.Scrub("MONGO_URI=mongodb+srv://user:pass@cluster.example.com")
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
