package core

import (
	"strings"
	"testing"
)

func TestAC_AUTH_13_ConfigValidation(t *testing.T) {
	t.Run("two_providers_per_route", func(t *testing.T) {
		cfg, err := loadAuthTest(t, `{
			"authProviders": [
				{
					"id": "mycompany", "type": "oidc",
					"issuer": "https://auth.test/t/mycompany",
					"clientId": "cladone-go",
					"loginBaseUrl": "https://login.mycompany.test",
					"cookieDomain": "mycompany.test",
					"cookieName": "mycompany_session",
					"sessionStore": {"type": "bolt", "path": "./mycompany.db"}
				},
				{
					"id": "contoso", "type": "jwt",
					"issuer": "https://auth.test/t/contoso",
					"jwksUrl": "https://auth.test/t/contoso/jwks.json",
					"audience": "cladone-go"
				}
			],
			"defaultAuthProvider": "mycompany",
			"routes": [
				{"host": "app.mycompany.test", "path": "/*", "frontend": true,
				 "backend": "http://127.0.0.1:1", "auth": {"provider": "mycompany"}},
				{"host": "api.contoso.test", "path": "/*",
				 "backend": "http://127.0.0.1:1", "auth": {"provider": "contoso"}}
			]
		}`)
		if err != nil {
			t.Fatal(err)
		}
		if len(cfg.AuthProviders) != 2 {
			t.Fatalf("providers = %d", len(cfg.AuthProviders))
		}
		mycompany := cfg.AuthProviderByID("mycompany")
		if mycompany == nil || mycompany.CookieName != "mycompany_session" {
			t.Fatalf("mycompany = %+v", mycompany)
		}
		contoso := cfg.AuthProviderByID("contoso")
		if contoso == nil || contoso.JWKSURL == "" {
			t.Fatalf("contoso = %+v", contoso)
		}
		if got := cfg.LoginURLFor(&cfg.Routes[0]); got != "https://login.mycompany.test/login" {
			t.Errorf("mycompany login = %q", got)
		}
		if got := cfg.LoginURLFor(&cfg.Routes[1]); got != "" {
			t.Errorf("contoso login = %q, want empty", got)
		}
		if got := cfg.AuthIssuerFor(&cfg.Routes[1]); got != "https://auth.test/t/contoso" {
			t.Errorf("contoso issuer = %q", got)
		}
	})

	t.Run("duplicate_provider_id", func(t *testing.T) {
		_, err := loadAuthTest(t, `{
			"authProviders": [
				{"id": "a", "type": "jwt", "issuer": "https://a.test",
				 "jwksUrl": "https://a.test/jwks"},
				{"id": "a", "type": "jwt", "issuer": "https://b.test",
				 "jwksUrl": "https://b.test/jwks"}
			],
			"routes": []
		}`)
		if err == nil || !strings.Contains(err.Error(), "duplicate id") {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("default_required_with_multiple", func(t *testing.T) {
		_, err := loadAuthTest(t, `{
			"authProviders": [
				{"id": "a", "type": "jwt", "issuer": "https://a.test",
				 "jwksUrl": "https://a.test/jwks"},
				{"id": "b", "type": "jwt", "issuer": "https://b.test",
				 "jwksUrl": "https://b.test/jwks"}
			],
			"routes": []
		}`)
		if err == nil || !strings.Contains(err.Error(), "defaultAuthProvider") {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("singular_and_plural_mutually_exclusive", func(t *testing.T) {
		_, err := loadAuthTest(t, `{
			"authProvider": {"type": "http-bridge", "baseUrl": "http://bridge:3000"},
			"authProviders": [
				{"id": "a", "type": "jwt", "issuer": "https://a.test",
				 "jwksUrl": "https://a.test/jwks"}
			],
			"routes": []
		}`)
		if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("unknown_route_provider", func(t *testing.T) {
		_, err := loadAuthTest(t, `{
			"authProviders": [
				{"id": "a", "type": "jwt", "issuer": "https://a.test",
				 "jwksUrl": "https://a.test/jwks"}
			],
			"routes": [{"host": "a.test", "path": "/*",
				"backend": "http://127.0.0.1:1", "auth": {"provider": "b"}}]
		}`)
		if err == nil || !strings.Contains(err.Error(), "unknown provider") {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("jwt_requires_jwks", func(t *testing.T) {
		_, err := loadAuthTest(t, `{
			"authProviders": [
				{"id": "a", "type": "jwt", "issuer": "https://a.test"}
			],
			"routes": []
		}`)
		if err == nil || !strings.Contains(err.Error(), "jwksUrl") {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("duplicate_cookie_name", func(t *testing.T) {
		_, err := loadAuthTest(t, `{
			"authProviders": [
				{"id": "a", "type": "oidc", "issuer": "https://a.test",
				 "clientId": "c", "loginBaseUrl": "https://login-a.test",
				 "cookieDomain": "a.test", "cookieName": "same",
				 "sessionStore": {"type": "bolt", "path": "./a.db"}},
				{"id": "b", "type": "oidc", "issuer": "https://b.test",
				 "clientId": "c", "loginBaseUrl": "https://login-b.test",
				 "cookieDomain": "a.test", "cookieName": "same",
				 "sessionStore": {"type": "bolt", "path": "./b.db"}}
			],
			"defaultAuthProvider": "a",
			"routes": []
		}`)
		if err == nil || !strings.Contains(err.Error(), "cookie") {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestAC_AUTH_07_ProviderPluginRejected(t *testing.T) {
	_, err := loadAuthTest(t, `{
		"authProvider": {"type": "plugin"},
		"routes": [{"host": "a.test", "path": "/*",
			"backend": "http://127.0.0.1:1", "auth": {}}]
	}`)
	if err == nil || !strings.Contains(err.Error(), "unknown provider") {
		t.Fatalf("err = %v, want unknown provider refusal", err)
	}
}

func TestAC_AUTH_18_RedisConfigValidation(t *testing.T) {
	t.Run("oidc_redis_requires_session_key_env", func(t *testing.T) {
		_, err := loadAuthTest(t, `{
			"authProviders": [{
				"id": "a", "type": "oidc",
				"issuer": "https://a.test", "clientId": "c",
				"loginBaseUrl": "https://login.a.test",
				"cookieDomain": "a.test",
				"sessionStore": {
					"type": "redis", "url": "redis://127.0.0.1:6379/0"
				}
			}],
			"routes": []
		}`)
		if err == nil || !strings.Contains(err.Error(), "sessionKeyEnv") {
			t.Fatalf("err = %v, want sessionKeyEnv refusal", err)
		}
	})

	t.Run("oidc_redis_ok", func(t *testing.T) {
		t.Setenv("TEST_SESSION_KEY", "shared-key")
		cfg, err := loadAuthTest(t, `{
			"authProviders": [{
				"id": "a", "type": "oidc",
				"issuer": "https://a.test", "clientId": "c",
				"loginBaseUrl": "https://login.a.test",
				"cookieDomain": "a.test",
				"sessionKeyEnv": "TEST_SESSION_KEY",
				"sessionStore": {
					"type": "redis", "url": "redis://127.0.0.1:6379/0",
					"prefix": "test:auth:v1:"
				}
			}],
			"routes": []
		}`)
		if err != nil {
			t.Fatal(err)
		}
		st := cfg.AuthProviderByID("a").SessionStore
		if st == nil || st.Type != "redis" || st.Prefix != "test:auth:v1:" {
			t.Fatalf("sessionStore = %+v", st)
		}
	})

	t.Run("jwt_redis_ok_without_session_key", func(t *testing.T) {
		cfg, err := loadAuthTest(t, `{
			"authProviders": [{
				"id": "a", "type": "jwt",
				"issuer": "https://a.test",
				"jwksUrl": "https://a.test/jwks",
				"sessionStore": {
					"type": "redis", "url": "redis://127.0.0.1:6379/0"
				}
			}],
			"routes": []
		}`)
		if err != nil {
			t.Fatal(err)
		}
		if cfg.AuthProviderByID("a").SessionStore.Type != "redis" {
			t.Fatal("jwt redis store not kept")
		}
	})

	t.Run("plural_rejects_http", func(t *testing.T) {
		_, err := loadAuthTest(t, `{
			"authProviders": [{"id": "a", "type": "http-bridge",
				"baseUrl": "http://bridge:3000"}],
			"routes": []
		}`)
		if err == nil || !strings.Contains(err.Error(), "not allowed") {
			t.Fatalf("err = %v, want http refusal", err)
		}
	})
}
