package broker

import "testing"

func TestAC_AUTH_13_BrokerLocalRedirectURIs(t *testing.T) {
	ok := []string{
		"https://login.example.com/auth/callback",
		"http://localhost:8080/auth/callback",
		"http://127.0.0.1:8080/auth/callback",
		"http://[::1]:8080/auth/callback",
		"http://login.acme.localhost:8080/auth/callback",
		"http://app.acme.localhost:8080/*",
	}
	for _, raw := range ok {
		if !isLocalRedirect(raw) {
			t.Errorf("isLocalRedirect(%q) = false, want true", raw)
		}
	}

	bad := []string{
		"http://login.example.com/auth/callback",
		"ftp://localhost/x",
		"not-a-url",
		"",
	}
	for _, raw := range bad {
		if isLocalRedirect(raw) {
			t.Errorf("isLocalRedirect(%q) = true, want false", raw)
		}
	}

	cfg := &Config{
		PublicURL: "http://auth.acme.localhost:8081",
		Tenants: []Tenant{{
			ID:           "acme",
			ClientID:     "gate-one",
			ClientSecret: "secret",
			RedirectURIs: []string{
				"http://login.acme.localhost:8080/auth/callback",
			},
			PostLogoutRedirectURIs: []string{
				"http://login.acme.localhost:8080/*",
				"http://app.acme.localhost:8080/*",
			},
			Google: GoogleConfig{
				Issuer:   "http://idp.localhost:9000",
				ClientID: "google-client",
			},
		}},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("local Compose config rejected: %v", err)
	}

	badCfg := *cfg
	badCfg.Tenants = append([]Tenant(nil), cfg.Tenants...)
	badCfg.Tenants[0].RedirectURIs = []string{
		"http://login.example.com/auth/callback",
	}
	if err := badCfg.Validate(); err == nil {
		t.Fatal("public http redirect URI accepted")
	}
}
