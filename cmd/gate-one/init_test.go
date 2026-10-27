package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestDeriveDevHosts(t *testing.T) {
	cases := []struct{ host, domain, login string }{
		{"app.localhost", "app.localhost", "login.app.localhost"},
		{"app.demo.localhost", "demo.localhost", "login.demo.localhost"},
		{"app.acme.com", "acme.com", "login.acme.com"},
	}
	for _, c := range cases {
		domain, login := deriveDevHosts(c.host)
		if domain != c.domain || login != c.login {
			t.Errorf("deriveDevHosts(%q) = (%q,%q), want (%q,%q)",
				c.host, domain, login, c.domain, c.login)
		}
	}
}

func TestNormalizeInitHost(t *testing.T) {
	cases := map[string]string{
		"https://App.Demo.Localhost:8443/": "app.demo.localhost",
		"app.localhost":                    "app.localhost",
		"http://app.localhost/path?q=1":    "app.localhost",
	}
	for in, want := range cases {
		if got := normalizeInitHost(in); got != want {
			t.Errorf("normalizeInitHost(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRunInitDevAndStatic(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "api-routes.json")

	if code := runInit([]string{
		"--host", "app.demo.localhost",
		"--backend", "http://127.0.0.1:8080",
		"--port", "3990",
		"--out", out,
	}); code != 0 {
		t.Fatalf("dev init = %d", code)
	}

	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		AuthProvider *struct {
			Type         string `json:"type"`
			LoginBaseURL string `json:"loginBaseUrl"`
			CookieDomain string `json:"cookieDomain"`
		} `json:"authProvider"`
		Routes []struct {
			Host  string         `json:"host"`
			Auth  *struct{}      `json:"auth"`
			Badge map[string]any `json:"userBadge"`
		} `json:"routes"`
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.AuthProvider == nil || cfg.AuthProvider.Type != "dev" {
		t.Fatalf("authProvider = %+v, want dev", cfg.AuthProvider)
	}
	if cfg.AuthProvider.LoginBaseURL != "http://login.demo.localhost:3990" {
		t.Errorf("loginBaseUrl = %q", cfg.AuthProvider.LoginBaseURL)
	}
	if cfg.AuthProvider.CookieDomain != "demo.localhost" {
		t.Errorf("cookieDomain = %q", cfg.AuthProvider.CookieDomain)
	}
	if len(cfg.Routes) != 1 || cfg.Routes[0].Host != "app.demo.localhost" {
		t.Fatalf("routes = %+v", cfg.Routes)
	}
	if cfg.Routes[0].Auth == nil {
		t.Error("dev template must require authentication")
	}
	if cfg.Routes[0].Badge == nil {
		t.Error("dev template must inject a user badge")
	}

	// --force is required to overwrite.
	if code := runInit([]string{"--host", "app.localhost", "--out", out}); code == 0 {
		t.Error("init overwrote an existing file without --force")
	}

	static := filepath.Join(dir, "static.json")
	if code := runInit([]string{
		"--static", "--host", "static.localhost",
		"--backend", "http://127.0.0.1:8080", "--out", static,
	}); code != 0 {
		t.Fatalf("static init = %d", code)
	}
	raw, err = os.ReadFile(static)
	if err != nil {
		t.Fatal(err)
	}
	var sc struct {
		AuthProvider *struct{} `json:"authProvider"`
		Routes       []struct {
			Auth *struct{} `json:"auth"`
		} `json:"routes"`
	}
	if err := json.Unmarshal(raw, &sc); err != nil {
		t.Fatal(err)
	}
	if sc.AuthProvider != nil {
		t.Error("static template must not declare an authProvider")
	}
	if len(sc.Routes) != 1 || sc.Routes[0].Auth != nil {
		t.Error("static template must be public")
	}
}

func TestRunInitOIDC(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "oidc.json")
	if code := runInit([]string{
		"--oidc",
		"--host", "app.demo.localhost",
		"--backend", "http://127.0.0.1:8080",
		"--issuer", "https://auth.example.com/realms/acme",
		"--client-id", "gate-one",
		"--client-secret-env", "ACME_OIDC_SECRET",
		"--out", out,
	}); code != 0 {
		t.Fatalf("oidc init = %d", code)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		AuthProvider struct {
			Type              string `json:"type"`
			LoginBaseURL      string `json:"loginBaseUrl"`
			CookieDomain      string `json:"cookieDomain"`
			Issuer            string `json:"issuer"`
			ClientID          string `json:"clientId"`
			ClientSecretEnv   string `json:"clientSecretEnv"`
			SessionTTLSeconds int    `json:"sessionTtlSeconds"`
			SessionStore      struct {
				Type string `json:"type"`
				Path string `json:"path"`
			} `json:"sessionStore"`
		} `json:"authProvider"`
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	ap := cfg.AuthProvider
	if ap.Type != "oidc" || ap.ClientID != "gate-one" ||
		ap.Issuer != "https://auth.example.com/realms/acme" ||
		ap.ClientSecretEnv != "ACME_OIDC_SECRET" {
		t.Errorf("authProvider = %+v", ap)
	}
	if ap.LoginBaseURL != "https://login.demo.localhost" {
		t.Errorf("loginBaseUrl = %q", ap.LoginBaseURL)
	}
	if ap.CookieDomain != "demo.localhost" {
		t.Errorf("cookieDomain = %q", ap.CookieDomain)
	}
	if ap.SessionTTLSeconds != 3600 {
		t.Errorf("sessionTtlSeconds = %d", ap.SessionTTLSeconds)
	}
	if ap.SessionStore.Type != "bolt" ||
		ap.SessionStore.Path != "./gate-one-state.db" {
		t.Errorf("sessionStore = %+v", ap.SessionStore)
	}
}
