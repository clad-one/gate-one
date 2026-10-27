package proxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A proxified origin with a strict CSP: merge mode must append both
// the guard script hash and the guard stylesheet hash to the origin
// policy, so the guard runs under the origin's policy without
// 'unsafe-inline'. This is the integration test behind the CSP guide's
// "external sites" section.
func TestCSPMergeAmendsOriginWithGuardStyleHash(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set(
				"Content-Security-Policy",
				"default-src 'self'; script-src 'self'; style-src 'self'",
			)
			_, _ = w.Write([]byte("<html><body>origin</body></html>"))
		},
	))
	t.Cleanup(backend.Close)

	cfg := loadForTest(t, `{
		"routes": [{
			"host": "external.test", "path": "/*", "frontend": true,
			"backend": "`+backend.URL+`",
			"csp": {"mode": "merge"}
		}]
	}`)

	gw, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	resp := doGet(t, gw, "external.test", "/")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	policy := resp.Header.Get("Content-Security-Policy")
	if !strings.Contains(policy, "script-src 'self' 'sha256-") {
		t.Errorf("guard script hash not appended to origin script-src: %q", policy)
	}
	if !strings.Contains(policy, "style-src 'self' 'sha256-") {
		t.Errorf("guard style hash not appended to origin style-src: %q", policy)
	}
	if strings.Contains(policy, "'unsafe-inline'") {
		t.Errorf("merge added unsafe-inline: %q", policy)
	}
}
