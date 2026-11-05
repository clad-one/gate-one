package core

import (
	"strings"
	"testing"
)

func TestSSOGroupsExpandProvidersAndHosts(t *testing.T) {
	t.Setenv("SSO_SESSION_KEY", "test-session-key")
	cfg, err := loadAuthTest(t, `{
		"ssoGroups": [{
			"id": "acme",
			"type": "oidc",
			"issuer": "https://idp.test/realms/acme",
			"clientId": "gate-one",
			"sessionKeyEnv": "SSO_SESSION_KEY",
			"sessionStore": {
				"type": "redis",
				"url": "redis://127.0.0.1:6379/0",
				"prefix": "cladone:auth:test:"
			},
			"providers": [
				{
					"id": "app-a",
					"loginBaseUrl": "https://login.app-a.test",
					"cookieDomain": "app-a.test",
					"defaultAppUrl": "https://app-a.test/"
				},
				{
					"id": "app-b",
					"loginBaseUrl": "https://login.app-b.test",
					"cookieDomain": "app-b.test",
					"defaultAppUrl": "https://app-b.test/"
				}
			]
		}],
		"defaultAuthProvider": "app-a",
		"routes": [{
			"hosts": ["app-a.test", "app-b.test"],
			"path": "/*",
			"backend": "http://127.0.0.1:1",
			"frontend": true,
			"auth": {}
		}]
	}`)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.AuthProviders) != 2 {
		t.Fatalf("providers = %d, want 2", len(cfg.AuthProviders))
	}
	a := cfg.AuthProviderByID("app-a")
	b := cfg.AuthProviderByID("app-b")
	if a == nil || b == nil {
		t.Fatalf("providers = %+v", cfg.AuthProviders)
	}
	if a.Issuer != b.Issuer || a.ClientID != b.ClientID ||
		a.SessionKeyEnv != b.SessionKeyEnv {
		t.Fatalf("shared fields diverged: a=%+v b=%+v", a, b)
	}
	if a.SSOGroupID() != "acme" || b.SSOGroupID() != "acme" {
		t.Fatalf("ssoGroup = %q/%q", a.SSOGroupID(), b.SSOGroupID())
	}
	if a.DefaultAppURL != "https://app-a.test/" ||
		b.DefaultAppURL != "https://app-b.test/" {
		t.Fatalf("defaultAppUrl = %q/%q",
			a.DefaultAppURL, b.DefaultAppURL)
	}
	if len(cfg.Routes) != 2 {
		t.Fatalf("routes = %d, want 2", len(cfg.Routes))
	}
	if cfg.Routes[0].Host != "app-a.test" ||
		cfg.Routes[0].Auth == nil ||
		cfg.Routes[0].Auth.Provider != "app-a" {
		t.Fatalf("route[0] = %+v", cfg.Routes[0])
	}
	if cfg.Routes[1].Host != "app-b.test" ||
		cfg.Routes[1].Auth == nil ||
		cfg.Routes[1].Auth.Provider != "app-b" {
		t.Fatalf("route[1] = %+v", cfg.Routes[1])
	}
	if cfg.Routes[0].Hosts != nil || cfg.Routes[1].Hosts != nil {
		t.Fatal("hosts[] not cleared after expansion")
	}
}

func TestSSOGroupsRejectSharedFieldInProvider(t *testing.T) {
	t.Setenv("SSO_SESSION_KEY", "test-session-key")
	_, err := loadAuthTest(t, `{
		"ssoGroups": [{
			"id": "acme",
			"issuer": "https://idp.test",
			"clientId": "gate-one",
			"sessionKeyEnv": "SSO_SESSION_KEY",
			"sessionStore": {"type": "redis", "url": "redis://127.0.0.1:6379/0"},
			"providers": [{
				"id": "app-a",
				"issuer": "https://other.test",
				"loginBaseUrl": "https://login.app-a.test",
				"cookieDomain": "app-a.test"
			}]
		}],
		"routes": []
	}`)
	if err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("err = %v, want unknown field", err)
	}
}

func TestSSOGroupsRejectLoginHostOutsideCookieDomain(t *testing.T) {
	_, err := loadAuthTest(t, `{
		"ssoGroups": [{
			"id": "acme",
			"issuer": "https://idp.test",
			"clientId": "gate-one",
			"providers": [{
				"id": "app-a",
				"loginBaseUrl": "https://login.other.test",
				"cookieDomain": "app-a.test"
			}]
		}],
		"routes": []
	}`)
	if err == nil || !strings.Contains(err.Error(), "not covered by cookieDomain") {
		t.Fatalf("err = %v, want cookieDomain coverage error", err)
	}
}

func TestSSOGroupsRejectOverlappingCookieDomains(t *testing.T) {
	t.Setenv("SSO_SESSION_KEY", "test-session-key")
	_, err := loadAuthTest(t, `{
		"ssoGroups": [{
			"id": "acme",
			"issuer": "https://idp.test",
			"clientId": "gate-one",
			"sessionKeyEnv": "SSO_SESSION_KEY",
			"sessionStore": {"type": "redis", "url": "redis://127.0.0.1:6379/0"},
			"providers": [
				{"id": "a", "loginBaseUrl": "https://login.app.test", "cookieDomain": "app.test"},
				{"id": "b", "loginBaseUrl": "https://login.sub.app.test", "cookieDomain": "sub.app.test"}
			]
		}],
		"routes": []
	}`)
	if err == nil || !strings.Contains(err.Error(), "overlaps") {
		t.Fatalf("err = %v, want overlap error", err)
	}
}

func TestSSOGroupsMultiProviderRequiresRedis(t *testing.T) {
	_, err := loadAuthTest(t, `{
		"ssoGroups": [{
			"id": "acme",
			"issuer": "https://idp.test",
			"clientId": "gate-one",
			"sessionStore": {"type": "bolt", "path": "./state.db"},
			"providers": [
				{"id": "a", "loginBaseUrl": "https://login.a.test", "cookieDomain": "a.test"},
				{"id": "b", "loginBaseUrl": "https://login.b.test", "cookieDomain": "b.test"}
			]
		}],
		"routes": []
	}`)
	if err == nil || !strings.Contains(err.Error(), "redis") {
		t.Fatalf("err = %v, want redis requirement", err)
	}
}

func TestSSOGroupsRejectLegacyAuthProvider(t *testing.T) {
	_, err := loadAuthTest(t, `{
		"authProvider": {"type": "dev", "loginBaseUrl": "http://login.demo.localhost:3000", "cookieDomain": "demo.localhost"},
		"ssoGroups": [{
			"id": "acme",
			"issuer": "https://idp.test",
			"clientId": "gate-one",
			"providers": [{"id": "a", "loginBaseUrl": "https://login.a.test", "cookieDomain": "a.test"}]
		}],
		"routes": []
	}`)
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("err = %v, want mutual exclusion", err)
	}
}

func TestRouteHostsRejectUncoveredHost(t *testing.T) {
	t.Setenv("SSO_SESSION_KEY", "test-session-key")
	_, err := loadAuthTest(t, `{
		"ssoGroups": [{
			"id": "acme",
			"issuer": "https://idp.test",
			"clientId": "gate-one",
			"sessionKeyEnv": "SSO_SESSION_KEY",
			"sessionStore": {"type": "redis", "url": "redis://127.0.0.1:6379/0"},
			"providers": [{"id": "a", "loginBaseUrl": "https://login.a.test", "cookieDomain": "a.test"}]
		}],
		"defaultAuthProvider": "a",
		"routes": [{
			"hosts": ["a.test", "other.test"],
			"path": "/*",
			"backend": "http://127.0.0.1:1",
			"auth": {}
		}]
	}`)
	if err == nil || !strings.Contains(err.Error(), "no auth provider") {
		t.Fatalf("err = %v, want provider inference error", err)
	}
}

func TestRouteHostsRejectExplicitProviderMismatch(t *testing.T) {
	t.Setenv("SSO_SESSION_KEY", "test-session-key")
	_, err := loadAuthTest(t, `{
		"ssoGroups": [{
			"id": "acme",
			"issuer": "https://idp.test",
			"clientId": "gate-one",
			"sessionKeyEnv": "SSO_SESSION_KEY",
			"sessionStore": {"type": "redis", "url": "redis://127.0.0.1:6379/0"},
			"providers": [{"id": "a", "loginBaseUrl": "https://login.a.test", "cookieDomain": "a.test"}]
		}],
		"defaultAuthProvider": "a",
		"routes": [{
			"hosts": ["b.test"],
			"path": "/*",
			"backend": "http://127.0.0.1:1",
			"auth": {"provider": "a"}
		}]
	}`)
	if err == nil || !strings.Contains(err.Error(), "not covered by provider") {
		t.Fatalf("err = %v, want provider coverage error", err)
	}
}

func TestRouteHostsShapeRejects(t *testing.T) {
	cases := []struct {
		name string
		cfg  string
		want string
	}{
		{
			name: "host_and_hosts",
			cfg:  `{"routes":[{"host":"a.test","hosts":["a.test"],"path":"/*","backend":"http://127.0.0.1:1"}]}`,
			want: "mutually exclusive",
		},
		{
			name: "hosts_and_wildcard",
			cfg:  `{"routes":[{"hosts":["a.test"],"wildcard":{"x":["a"]},"path":"/*","backend":"http://127.0.0.1:1"}]}`,
			want: "mutually exclusive",
		},
		{
			name: "invalid_host",
			cfg:  `{"routes":[{"hosts":["a.test:3000"],"path":"/*","backend":"http://127.0.0.1:1"}]}`,
			want: "invalid literal host",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := loadAuthTest(t, c.cfg)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want %q", err, c.want)
			}
		})
	}
}

func TestSSOGroupsProviderIDsAreGlobal(t *testing.T) {
	t.Setenv("SSO_SESSION_KEY", "test-session-key")
	_, err := loadAuthTest(t, `{
		"ssoGroups": [{
			"id": "acme",
			"issuer": "https://idp.test",
			"clientId": "gate-one",
			"sessionKeyEnv": "SSO_SESSION_KEY",
			"sessionStore": {"type": "redis", "url": "redis://127.0.0.1:6379/0"},
			"providers": [{"id": "dup", "loginBaseUrl": "https://login.a.test", "cookieDomain": "a.test"}]
		}],
		"authProviders": [{
			"id": "dup", "type": "jwt", "issuer": "https://api.test",
			"jwksUrl": "https://api.test/jwks.json"
		}],
		"routes": []
	}`)
	if err == nil || !strings.Contains(err.Error(), "duplicate id") {
		t.Fatalf("err = %v, want duplicate id", err)
	}
}

func TestProviderDefaultAppURLRejectsForeignHost(t *testing.T) {
	_, err := loadAuthTest(t, `{
		"authProvider": {
			"type": "dev",
			"loginBaseUrl": "http://login.dev.test:3000",
			"cookieDomain": "dev.test",
			"defaultAppUrl": "https://other.test/"
		},
		"routes": [{
			"host": "app.dev.test", "path": "/*", "frontend": true,
			"backend": "http://127.0.0.1:1"
		}]
	}`)
	if err == nil || !strings.Contains(err.Error(), "defaultAppUrl") {
		t.Fatalf("err = %v, want defaultAppUrl coverage error", err)
	}
}
