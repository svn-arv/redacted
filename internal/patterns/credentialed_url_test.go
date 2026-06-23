package patterns

import "testing"

// Credentialed URLs (scheme://user:pass@host) must redact for any scheme; a URL
// with no credentials must pass through.
func TestCredentialedURL(t *testing.T) {
	mustRedact := []string{
		"postgis://test:testpassword@localhost:5432", // Sevian's case: scheme not in database_url
		"DATABASE_URL=postgis://test:testpassword@localhost:5432",
		"MY_DB=clickhouse://user:Secret123@host:9000/db", // non-keyword key, non-listed scheme
		"redis://:authpass@redis.example.com:6379",       // password-only userinfo
		"https://admin:hunter2@dashboard.example.com",    // http basic-auth in URL
	}
	for _, s := range mustRedact {
		if !Scrub(s).Redacted {
			t.Errorf("credentialed URL leaked (not redacted): %s", s)
		}
	}

	mustPass := []string{
		"https://github.com/Luce-MG/luce-product-design/issues/123",
		"link: https://docs.example.com/v2/GuideABC123/intro",
		"http://localhost:3000/api/v1/health",
	}
	for _, s := range mustPass {
		if r := Scrub(s); r.Redacted {
			t.Errorf("plain URL wrongly redacted: %s -> %s", s, r.Text)
		}
	}
}
