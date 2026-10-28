package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cladone/gate-one/internal/core"
)

func TestAC_AUTH_26_CheckWarnsOnMissingTTL(t *testing.T) {
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
		"authProviders": [{
			"id": "acme", "type": "oidc",
			"issuer": ` + quote(issuer) + `,
			"clientId": "gate-one",
			"loginBaseUrl": "https://login.acme.test",
			"cookieDomain": "acme.test",
			"sessionStore": {"type": "bolt", "path": "./acme.db"}
		}],
		"routes": []
	}`
	if err := os.WriteFile(path, []byte(cfgJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := core.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	checkOIDCRefreshTTL(&out, cfg)
	if !strings.Contains(out.String(), "does not advertise") ||
		!strings.Contains(out.String(), "revocationTtlSeconds") {
		t.Fatalf("warning missing: %s", out.String())
	}

	// An explicit TTL suppresses the probe/warning, even if unreachable.
	cfg.AuthProviders[0].Issuer = "http://127.0.0.1:1"
	cfg.AuthProviders[0].RevocationTTLSeconds = 3600
	out.Reset()
	checkOIDCRefreshTTL(&out, cfg)
	if out.Len() != 0 {
		t.Fatalf("unexpected warning with explicit TTL: %s", out.String())
	}
}

func quote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
