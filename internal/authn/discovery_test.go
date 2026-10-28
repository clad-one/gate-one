package authn

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAC_AUTH_26_RefreshTTLWarning(t *testing.T) {
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

	ttl, err := ProbeRefreshTTL(context.Background(), issuer, srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	if ttl != 0 {
		t.Fatalf("ttl = %d, want 0 (field absent)", ttl)
	}
	msg := RefreshTTLWarning(issuer, "acme")
	for _, want := range []string{
		"does not advertise",
		"revocationTtlSeconds",
		"30 days",
		"Keycloak",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("warning missing %q: %s", want, msg)
		}
	}
}

func TestAC_AUTH_26_StartupWarning(t *testing.T) {
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

	var logs bytes.Buffer
	old := log.Writer()
	log.SetOutput(&logs)
	defer log.SetOutput(old)
	_, err := NewOIDC(context.Background(), OIDCConfig{
		ProviderID:   "acme",
		Issuer:       issuer,
		ClientID:     "gate-one",
		LoginBaseURL: "http://login.test:3000",
		CookieDomain: "test",
		Store:        NewMemoryStore(),
		HTTPClient:   srv.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(logs.String(), "does not advertise") {
		t.Fatalf("startup warning missing: %s", logs.String())
	}
}
