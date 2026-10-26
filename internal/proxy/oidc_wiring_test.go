package proxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cladone/gate-one/internal/core"
)

// The OIDC provider is constructed at startup (discovery is
// fail-fast) and its dedicated login host is dispatched before route
// matching, exactly like the dev provider.
func TestOIDCProviderWiring(t *testing.T) {
	var issuer string
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration",
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"issuer":                                issuer,
				"authorization_endpoint":                issuer + "/authorize",
				"token_endpoint":                        issuer + "/token",
				"jwks_uri":                              issuer + "/jwks",
				"response_types_supported":              []string{"code"},
				"subject_types_supported":               []string{"public"},
				"id_token_signing_alg_values_supported": []string{"RS256"},
			})
		})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	issuer = srv.URL

	dir := t.TempDir()
	path := filepath.Join(dir, "routes.json")
	cfgJSON := `{
		"authProvider": {
			"type": "oidc",
			"issuer": "` + issuer + `",
			"clientId": "gate-one",
			"loginBaseUrl": "http://login.test:3000",
			"cookieDomain": "test"
		},
		"routes": [{
			"host": "app.test", "path": "/*", "frontend": true,
			"backend": "http://127.0.0.1:1", "auth": {}
		}]
	}`
	if err := os.WriteFile(path, []byte(cfgJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := core.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	gw, err := New(cfg, WithListenAddr("127.0.0.1:0"))
	if err != nil {
		t.Fatal(err)
	}
	if gw.ProviderName() != "oidc" {
		t.Fatalf("provider = %q, want oidc", gw.ProviderName())
	}
	if gw.ProviderLoginURL() != "http://login.test:3000/login" {
		t.Errorf("login URL = %q", gw.ProviderLoginURL())
	}

	// Anonymous app request → login host.
	req := httptest.NewRequest(http.MethodGet, "http://app.test/", nil)
	req.Host = "app.test"
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("anonymous = %d, want 302", rec.Code)
	}
	if loc := rec.Header().Get("Location"); !strings.HasPrefix(
		loc, "http://login.test:3000/login?returnTo=") {
		t.Errorf("Location = %q", loc)
	}

	// The login host serves the IdP redirect, not an app route.
	req = httptest.NewRequest(
		http.MethodGet,
		"http://login.test:3000/login?returnTo=http://app.test/",
		nil,
	)
	req.Host = "login.test:3000"
	rec = httptest.NewRecorder()
	gw.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("login = %d, want 302: %s", rec.Code, rec.Body.String())
	}
	if loc := rec.Header().Get("Location"); !strings.HasPrefix(
		loc, issuer+"/authorize?") {
		t.Errorf("authorization Location = %q", loc)
	}
}
