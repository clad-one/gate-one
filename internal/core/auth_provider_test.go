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

func TestLegacyOIDCTranslatesToHTTPBridge(t *testing.T) {
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
	if ap == nil || ap.Type != "http-bridge" {
		t.Fatalf("authProvider = %+v, want an http-bridge translation", ap)
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

func TestAuthProviderOIDCConfig(t *testing.T) {
	t.Setenv("MYCOMPANY_OIDC_SECRET", "s3cret")
	cfg, err := loadAuthTest(t, `{
		"authProvider": {
			"type": "oidc",
			"issuer": "https://auth.example.com/realms/mycompany",
			"clientId": "gate-one",
			"clientSecretEnv": "MYCOMPANY_OIDC_SECRET",
			"loginBaseUrl": "https://login.example.com",
			"cookieDomain": "example.com"
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
	if ap.Type != "oidc" {
		t.Errorf("type = %q", ap.Type)
	}
	if ap.ClientSecret != "s3cret" {
		t.Errorf("client secret not resolved")
	}
	if ap.LoginURL != "https://login.example.com/login" {
		t.Errorf("login = %q", ap.LoginURL)
	}
	if ap.RedirectURL != "https://login.example.com/auth/callback" {
		t.Errorf("redirect = %q", ap.RedirectURL)
	}
	if got := cfg.AuthIssuer(); got != "https://auth.example.com/realms/mycompany" {
		t.Errorf("issuer = %q", got)
	}
	if ap.SessionStore == nil || ap.SessionStore.Type != "bolt" {
		t.Fatalf("sessionStore = %+v, want bolt", ap.SessionStore)
	}
	if !filepath.IsAbs(ap.SessionStore.Path) ||
		!strings.HasSuffix(ap.SessionStore.Path, "gate-one-state.db") {
		t.Errorf("sessionStore.path = %q, want an absolute gate-one-state.db",
			ap.SessionStore.Path)
	}
}

func TestOIDCSessionStoreRedisRequiresURL(t *testing.T) {
	_, err := loadAuthTest(t, `{
		"authProvider": {
			"type": "oidc",
			"issuer": "https://auth.example.com/realms/mycompany",
			"clientId": "gate-one",
			"loginBaseUrl": "https://login.example.com",
			"cookieDomain": "example.com",
			"sessionStore": {"type": "redis"}
		},
		"routes": [{"host": "app.example.com", "path": "/*",
			"backend": "http://127.0.0.1:1"}]
	}`)
	if err == nil || !strings.Contains(err.Error(), "url or masterName") {
		t.Fatalf("err = %v, want redis URL refusal", err)
	}
}

func TestOIDCSessionKeyEnvMissing(t *testing.T) {
	_, err := loadAuthTest(t, `{
		"authProvider": {
			"type": "oidc",
			"issuer": "https://auth.example.com/realms/mycompany",
			"clientId": "gate-one",
			"loginBaseUrl": "https://login.example.com",
			"cookieDomain": "example.com",
			"sessionKeyEnv": "MISSING_SESSION_KEY"
		},
		"routes": [{"host": "app.example.com", "path": "/*",
			"backend": "http://127.0.0.1:1"}]
	}`)
	if err == nil || !strings.Contains(err.Error(), "MISSING_SESSION_KEY") {
		t.Fatalf("err = %v, want missing session key refusal", err)
	}
}

func TestSessionStoreRejectedForHTTP(t *testing.T) {
	_, err := loadAuthTest(t, `{
		"authProvider": {
			"type": "http-bridge",
			"baseUrl": "http://auth-bridge:3000",
			"sessionStore": {"type": "bolt"}
		},
		"routes": [{"host": "app.example.com", "path": "/*",
			"backend": "http://127.0.0.1:1"}]
	}`)
	if err == nil || !strings.Contains(err.Error(), "only valid for type oidc") {
		t.Fatalf("err = %v, want sessionStore rejection", err)
	}
}

func TestAuthProviderOIDCRequiresIssuerAndClient(t *testing.T) {
	_, err := loadAuthTest(t, `{
		"authProvider": {
			"type": "oidc",
			"loginBaseUrl": "https://login.example.com",
			"cookieDomain": "example.com"
		},
		"routes": [{"host": "app.example.com", "path": "/*",
			"backend": "http://127.0.0.1:1"}]
	}`)
	if err == nil || !strings.Contains(err.Error(), "issuer is required") {
		t.Fatalf("err = %v, want issuer refusal", err)
	}
}

func TestAuthProviderOIDCMissingSecret(t *testing.T) {
	_, err := loadAuthTest(t, `{
		"authProvider": {
			"type": "oidc",
			"issuer": "https://auth.example.com/realms/mycompany",
			"clientId": "gate-one",
			"clientSecretEnv": "MISSING_OIDC_SECRET",
			"loginBaseUrl": "https://login.example.com",
			"cookieDomain": "example.com"
		},
		"routes": [{"host": "app.example.com", "path": "/*",
			"backend": "http://127.0.0.1:1"}]
	}`)
	if err == nil || !strings.Contains(err.Error(), "MISSING_OIDC_SECRET") {
		t.Fatalf("err = %v, want missing secret refusal", err)
	}
}

func TestOIDCTypeInferredFromClientID(t *testing.T) {
	cfg, err := loadAuthTest(t, `{
		"authProvider": {
			"issuer": "https://auth.example.com/realms/mycompany",
			"clientId": "gate-one",
			"loginBaseUrl": "https://login.example.com",
			"cookieDomain": "example.com"
		},
		"routes": [{"host": "app.example.com", "path": "/*",
			"backend": "http://127.0.0.1:1"}]
	}`)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AuthProvider.Type != "oidc" {
		t.Errorf("type = %q, want oidc", cfg.AuthProvider.Type)
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

func TestSessionStoreSentinelAuthTLSResolved(t *testing.T) {
	t.Setenv("TEST_SESSION_KEY", "session-key")
	t.Setenv("TEST_SENTINEL_PASSWORD", "sentinel-secret")
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caPath, []byte("dummy"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadAuthTest(t, `{
		"authProvider": {
			"type": "oidc",
			"issuer": "https://auth.example.com/realms/mycompany",
			"clientId": "gate-one",
			"loginBaseUrl": "https://login.example.com",
			"cookieDomain": "example.com",
			"sessionKeyEnv": "TEST_SESSION_KEY",
			"sessionStore": {
				"type": "redis",
				"masterName": "authmaster",
				"sentinelAddrs": ["s1:26379", "s2:26379"],
				"sentinelUsername": "sentinel-user",
				"sentinelPasswordEnv": "TEST_SENTINEL_PASSWORD",
				"username": "app",
				"tls": true,
				"tlsCaFile": "`+caPath+`",
				"tlsServerName": "redis.internal"
			}
		},
		"routes": [{"host": "app.example.com", "path": "/*",
			"backend": "http://127.0.0.1:1"}]
	}`)
	if err != nil {
		t.Fatal(err)
	}
	st := cfg.AuthProvider.SessionStore
	if st.SentinelUsername != "sentinel-user" ||
		st.SentinelPassword != "sentinel-secret" {
		t.Errorf("sentinel auth = %q/%q",
			st.SentinelUsername, st.SentinelPassword)
	}
	if !st.TLS || st.TLSCaFile != caPath ||
		st.TLSServerName != "redis.internal" {
		t.Errorf("tls = %v/%q/%q", st.TLS, st.TLSCaFile, st.TLSServerName)
	}
}

func TestSessionStoreSentinelFieldsRequireSentinelMode(t *testing.T) {
	t.Setenv("TEST_SESSION_KEY", "session-key")
	_, err := loadAuthTest(t, `{
		"authProvider": {
			"type": "oidc",
			"issuer": "https://auth.example.com/realms/mycompany",
			"clientId": "gate-one",
			"loginBaseUrl": "https://login.example.com",
			"cookieDomain": "example.com",
			"sessionKeyEnv": "TEST_SESSION_KEY",
			"sessionStore": {
				"type": "redis",
				"url": "redis://redis:6379/0",
				"sentinelUsername": "sentinel-user"
			}
		},
		"routes": [{"host": "app.example.com", "path": "/*",
			"backend": "http://127.0.0.1:1"}]
	}`)
	if err == nil || !strings.Contains(err.Error(), "only valid in sentinel mode") {
		t.Fatalf("err = %v, want sentinel-mode refusal", err)
	}
}

func TestSessionStoreTLSHelpersRequireTLS(t *testing.T) {
	t.Setenv("TEST_SESSION_KEY", "session-key")
	_, err := loadAuthTest(t, `{
		"authProvider": {
			"type": "oidc",
			"issuer": "https://auth.example.com/realms/mycompany",
			"clientId": "gate-one",
			"loginBaseUrl": "https://login.example.com",
			"cookieDomain": "example.com",
			"sessionKeyEnv": "TEST_SESSION_KEY",
			"sessionStore": {
				"type": "redis",
				"masterName": "authmaster",
				"sentinelAddrs": ["s1:26379"],
				"tlsServerName": "redis.internal"
			}
		},
		"routes": [{"host": "app.example.com", "path": "/*",
			"backend": "http://127.0.0.1:1"}]
	}`)
	if err == nil || !strings.Contains(err.Error(), "require tls=true") {
		t.Fatalf("err = %v, want tls=true refusal", err)
	}
}

func TestSessionStoreTLSCaFileMissing(t *testing.T) {
	t.Setenv("TEST_SESSION_KEY", "session-key")
	_, err := loadAuthTest(t, `{
		"authProvider": {
			"type": "oidc",
			"issuer": "https://auth.example.com/realms/mycompany",
			"clientId": "gate-one",
			"loginBaseUrl": "https://login.example.com",
			"cookieDomain": "example.com",
			"sessionKeyEnv": "TEST_SESSION_KEY",
			"sessionStore": {
				"type": "redis",
				"masterName": "authmaster",
				"sentinelAddrs": ["s1:26379"],
				"tls": true,
				"tlsCaFile": "/nonexistent/ca.pem"
			}
		},
		"routes": [{"host": "app.example.com", "path": "/*",
			"backend": "http://127.0.0.1:1"}]
	}`)
	if err == nil || !strings.Contains(err.Error(), "tlsCaFile") {
		t.Fatalf("err = %v, want missing CA refusal", err)
	}
}

func TestLegacyHTTPTypeIsNormalized(t *testing.T) {
	cfg, err := loadAuthTest(t, `{
		"authProvider": {"type": "http", "baseUrl": "http://bridge:3000"},
		"routes": [{
			"host": "app.example.com", "path": "/*", "frontend": true,
			"backend": "http://127.0.0.1:1", "auth": {}
		}]
	}`)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AuthProvider == nil || cfg.AuthProvider.Type != "http-bridge" {
		t.Fatalf("type = %+v, want http-bridge", cfg.AuthProvider)
	}
}
