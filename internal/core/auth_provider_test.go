package core

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func loadAuthTest(t *testing.T, cfgJSON string) (*Config, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "routes.json")
	if err := os.WriteFile(path, []byte(cfgJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	return Load(path)
}

func TestAuthProviderDevDefaults(t *testing.T) {
	cfg, err := loadAuthTest(t, `{
		"authProvider": {
			"type": "dev",
			"loginBaseUrl": "http://login.demo.localhost:3000",
			"cookieDomain": "demo.localhost"
		},
		"routes": [{
			"host": "app.demo.localhost", "path": "/*",
			"frontend": true, "backend": "http://127.0.0.1:8080",
			"auth": {}
		}]
	}`)
	if err != nil {
		t.Fatal(err)
	}
	ap := cfg.AuthProvider
	if ap == nil {
		t.Fatal("authProvider not resolved")
	}
	if ap.Type != "dev" {
		t.Errorf("type = %q", ap.Type)
	}
	if ap.LoginURL != "http://login.demo.localhost:3000/login" {
		t.Errorf("login = %q", ap.LoginURL)
	}
	if ap.Issuer != "http://login.demo.localhost:3000/dev" {
		t.Errorf("issuer = %q", ap.Issuer)
	}
	if got := cfg.LoginURLFor(&cfg.Routes[0]); got != ap.LoginURL {
		t.Errorf("LoginURLFor = %q", got)
	}
	if got := cfg.AuthIssuer(); got != ap.Issuer {
		t.Errorf("AuthIssuer = %q", got)
	}
}

func TestAuthProviderDevRequiresDomain(t *testing.T) {
	_, err := loadAuthTest(t, `{
		"authProvider": {"type": "dev",
			"loginBaseUrl": "http://login.demo.localhost:3000"},
		"routes": [{
			"host": "app.test", "path": "/*", "frontend": true,
			"backend": "http://127.0.0.1:1"
		}]
	}`)
	if err == nil || !strings.Contains(err.Error(), "cookieDomain") {
		t.Fatalf("err = %v, want cookieDomain refusal", err)
	}
}

func TestAuthProviderUnknownType(t *testing.T) {
	_, err := loadAuthTest(t, `{
		"authProvider": {"type": "saml"},
		"routes": [{"host": "a.test", "path": "/*",
			"backend": "http://127.0.0.1:1"}]
	}`)
	if err == nil || !strings.Contains(err.Error(), "unknown provider") {
		t.Fatalf("err = %v, want unknown provider refusal", err)
	}
}

func TestLegacyOIDCTranslatesToHTTP(t *testing.T) {
	cfg, err := loadAuthTest(t, `{
		"oidc": {
			"loginUrl": "https://login.example.com/login",
			"issuer": "https://auth.example.com/realms/example"
		},
		"routes": [{
			"host": "app.example.com", "path": "/*", "frontend": true,
			"backend": "http://127.0.0.1:1", "auth": {}
		}]
	}`)
	if err != nil {
		t.Fatal(err)
	}
	ap := cfg.AuthProvider
	if ap == nil || ap.Type != "http" {
		t.Fatalf("authProvider = %+v, want an http translation", ap)
	}
	if ap.LoginURL != "https://login.example.com/login" {
		t.Errorf("login = %q", ap.LoginURL)
	}
	if ap.Issuer != "https://auth.example.com/realms/example" {
		t.Errorf("issuer = %q", ap.Issuer)
	}
	if ap.VerifyURL == "" || ap.MCPVerifyURL == "" || ap.HealthURL == "" {
		t.Errorf("http endpoints not derived: %+v", ap)
	}
}

func TestPublicRouteNeedsNoProvider(t *testing.T) {
	cfg, err := loadAuthTest(t, `{
		"routes": [{
			"host": "static.localhost", "path": "/*", "frontend": true,
			"backend": "http://127.0.0.1:1"
		}]
	}`)
	if err != nil {
		t.Fatalf("public route refused: %v", err)
	}
	if cfg.AuthProvider != nil {
		t.Errorf("authProvider = %+v, want none", cfg.AuthProvider)
	}
}

func TestAuthRouteWithoutLoginRefused(t *testing.T) {
	_, err := loadAuthTest(t, `{
		"routes": [{
			"host": "app.test", "path": "/*", "frontend": true,
			"backend": "http://127.0.0.1:1", "auth": {}
		}]
	}`)
	if err == nil || !strings.Contains(err.Error(), "no login URL") {
		t.Fatalf("err = %v, want no login URL refusal", err)
	}
}
