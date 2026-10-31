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

func TestAC_AUTH_13_GoogleClientIDEnv(t *testing.T) {
	t.Setenv("E2E_GOOGLE_CLIENT_ID", "client-from-env")

	build := func() *Config {
		return &Config{
			PublicURL: "https://broker.test",
			Tenants: []Tenant{{
				ID:           "acme",
				ClientID:     "gate-one",
				ClientSecret: "secret",
				RedirectURIs: []string{
					"https://login.acme.test/auth/callback",
				},
				Google: GoogleConfig{
					Issuer:      "https://accounts.google.com",
					ClientIDEnv: "E2E_GOOGLE_CLIENT_ID",
				},
			}},
		}
	}

	cfg := build()
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if got := cfg.Tenants[0].Google.ClientID; got != "client-from-env" {
		t.Fatalf("google.clientId = %q", got)
	}

	t.Setenv("E2E_GOOGLE_CLIENT_ID", "")
	if err := build().Validate(); err == nil {
		t.Fatal("empty google clientIdEnv accepted")
	}
}

func TestAC_AUTH_13_BrokerPostLogoutWildcard(t *testing.T) {
	cases := []struct {
		list []string
		raw  string
		want bool
	}{
		{[]string{"https://app.example.com/*"}, "https://app.example.com/", true},
		{[]string{"https://app.example.com/*"}, "https://app.example.com/a/b", true},
		{[]string{"https://app.example.com/*"}, "https://evil.example.com/", false},
		{[]string{"https://exact.example.com/"}, "https://exact.example.com/", true},
		{[]string{"https://exact.example.com/"}, "https://exact.example.com/x", false},
	}
	for _, c := range cases {
		if got := redirectAllowed(c.list, c.raw); got != c.want {
			t.Errorf("redirectAllowed(%v, %q) = %t, want %t",
				c.list, c.raw, got, c.want)
		}
	}
}

func TestLocalAccountsConfigValidation(t *testing.T) {
	t.Setenv("TEST_REG_SECRET", "s3cret")
	base := func() *Config {
		return &Config{
			PublicURL: "https://broker.test",
			Tenants: []Tenant{{
				ID:                    "acme",
				ClientID:              "gate-one",
				RedirectURIs:          []string{"https://login.test/callback"},
				Google:                GoogleConfig{ClientID: "google-client"},
				LocalAccounts:         true,
				AppOrigins:            []string{"https://app.test"},
				RegistrationSecretEnv: "TEST_REG_SECRET",
			}},
		}
	}

	cfg := base()
	if err := cfg.Validate(); err == nil {
		t.Fatal("localAccounts without smtp accepted")
	}

	cfg = base()
	cfg.SMTP = &SMTPConfig{Host: "smtp.test", From: "a@b.test"}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("valid localAccounts config rejected: %v", err)
	}
	if cfg.Tenants[0].RegistrationSecret != "s3cret" {
		t.Fatal("registration secret not resolved")
	}
}
