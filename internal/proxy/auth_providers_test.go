package proxy

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"cladone/gate-one/internal/authn"
	"cladone/gate-one/internal/core"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-jose/go-jose/v4"
)

func TestAC_AUTH_02_CrossTenantTokenRejected(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
		}))
	t.Cleanup(backend.Close)

	privA, pubA := testKey(t)
	privB, pubB := testKey(t)
	_, urlA := testJWKS(t, pubA, "mycompany-1")
	_, urlB := testJWKS(t, pubB, "contoso-1")

	cfg := loadProxyAuthConfig(t, fmt.Sprintf(`{
		"authProviders": [
			{"id": "mycompany", "type": "jwt",
			 "issuer": "https://auth.test/t/mycompany",
			 "jwksUrl": %q, "audience": "cladone-go",
			 "roleClaims": ["roles"]},
			{"id": "contoso", "type": "jwt",
			 "issuer": "https://auth.test/t/contoso",
			 "jwksUrl": %q, "audience": "cladone-go",
			 "roleClaims": ["roles"]}
		],
		"defaultAuthProvider": "mycompany",
		"routes": [
			{"host": "mycompany.test", "path": "/*", "backend": %q,
			 "auth": {"provider": "mycompany"}},
			{"host": "contoso.test", "path": "/*", "backend": %q,
			 "auth": {"provider": "contoso"}}
		]
	}`, urlA, urlB, backend.URL, backend.URL))

	gw, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	tokenA := testToken(t, privA, "mycompany-1", map[string]any{
		"iss": "https://auth.test/t/mycompany", "sub": "user-a",
		"aud": "cladone-go", "exp": now.Add(5 * time.Minute).Unix(),
		"iat": now.Unix(), "roles": []string{"user"},
	})
	tokenB := testToken(t, privB, "contoso-1", map[string]any{
		"iss": "https://auth.test/t/contoso", "sub": "user-b",
		"aud": "cladone-go", "exp": now.Add(5 * time.Minute).Unix(),
		"iat": now.Unix(), "roles": []string{"user"},
	})

	cases := []struct {
		name  string
		host  string
		token string
		want  int
	}{
		{"mycompany_ok", "mycompany.test", tokenA, 200},
		{"cross_a_to_b", "contoso.test", tokenA, 401},
		{"contoso_ok", "contoso.test", tokenB, 200},
		{"cross_b_to_a", "mycompany.test", tokenB, 401},
		{"wrong_audience", "mycompany.test", testToken(t, privA, "mycompany-1", map[string]any{
			"iss": "https://auth.test/t/mycompany", "sub": "u",
			"aud": "other", "exp": now.Add(time.Minute).Unix(),
		}), 401},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := doAuthRequest(gw, tc.host, tc.token)
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d: %s",
					rec.Code, tc.want, rec.Body.String())
			}
		})
	}
}

func TestAC_AUTH_06_BrokerDownDegradesOnlyTenant(t *testing.T) {
	priv, pub := testKey(t)
	_, jwksURL := testJWKS(t, pub, "contoso-1")
	bad := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "down", http.StatusServiceUnavailable)
		}))
	badURL := bad.URL
	bad.Close()
	backend := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
		}))
	t.Cleanup(backend.Close)

	cfg := loadProxyAuthConfig(t, fmt.Sprintf(`{
		"authProviders": [
			{"id": "mycompany", "type": "oidc",
			 "issuer": %q,
			 "clientId": "cladone-go",
			 "loginBaseUrl": "https://login.mycompany.test",
			 "cookieDomain": "mycompany.test",
			 "cookieName": "mycompany_session",
			 "sessionStore": {"type": "bolt", "path": "./mycompany.db"}},
			{"id": "contoso", "type": "jwt",
			 "issuer": "https://auth.test/t/contoso",
			 "jwksUrl": %q, "audience": "cladone-go"}
		],
		"defaultAuthProvider": "contoso",
		"routes": [
			{"host": "mycompany.test", "path": "/*", "backend": %q,
			 "auth": {"provider": "mycompany"}},
			{"host": "contoso.test", "path": "/*", "backend": %q,
			 "auth": {"provider": "contoso"}}
		]
	}`, badURL, jwksURL, backend.URL, backend.URL))

	gw, err := New(cfg)
	if err != nil {
		t.Fatalf("a degraded provider must not block startup: %v", err)
	}
	if p := gw.providers["mycompany"]; p == nil || !p.degraded {
		t.Fatalf("mycompany provider = %+v, want degraded", p)
	}
	if p := gw.providers["contoso"]; p == nil || p.degraded {
		t.Fatalf("contoso provider = %+v, want ready", p)
	}

	// The broken tenant fails closed...
	rec := doAuthRequest(gw, "mycompany.test", "")
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("mycompany status = %d, want 502: %s", rec.Code, rec.Body.String())
	}
	// ...while the other tenant keeps working.
	token := testToken(t, priv, "contoso-1", map[string]any{
		"iss": "https://auth.test/t/contoso", "sub": "u",
		"aud": "cladone-go", "exp": time.Now().Add(time.Minute).Unix(),
	})
	rec = doAuthRequest(gw, "contoso.test", token)
	if rec.Code != http.StatusOK {
		t.Fatalf("contoso status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
}

func TestAC_AUTH_14_InvalidTokenVsUnavailable(t *testing.T) {
	priv, pub := testKey(t)
	jwksSrv, jwksURL := testJWKS(t, pub, "k1")
	backend := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
		}))
	t.Cleanup(backend.Close)

	cfg := loadProxyAuthConfig(t, fmt.Sprintf(`{
		"authProviders": [
			{"id": "mycompany", "type": "jwt",
			 "issuer": "https://auth.test/t/mycompany",
			 "jwksUrl": %q, "audience": "cladone-go"}
		],
		"routes": [
			{"host": "mycompany.test", "path": "/*", "backend": %q,
			 "auth": {"provider": "mycompany"}}
		]
	}`, jwksURL, backend.URL))
	gw, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	valid := testToken(t, priv, "k1", map[string]any{
		"iss": "https://auth.test/t/mycompany", "sub": "u",
		"aud": "cladone-go", "exp": now.Add(5 * time.Minute).Unix(),
	})
	if rec := doAuthRequest(gw, "mycompany.test", valid); rec.Code != 200 {
		t.Fatalf("valid = %d: %s", rec.Code, rec.Body.String())
	}

	// Invalid signature with a reachable JWKS = 401.
	bad := valid[:len(valid)-2] + "xx"
	if rec := doAuthRequest(gw, "mycompany.test", bad); rec.Code != 401 {
		t.Fatalf("bad signature = %d, want 401", rec.Code)
	}
	// Expired with a reachable/cached key = 401.
	expired := testToken(t, priv, "k1", map[string]any{
		"iss": "https://auth.test/t/mycompany", "sub": "u",
		"aud": "cladone-go", "exp": now.Add(-time.Minute).Unix(),
	})
	if rec := doAuthRequest(gw, "mycompany.test", expired); rec.Code != 401 {
		t.Fatalf("expired = %d, want 401", rec.Code)
	}

	// Cached key: a valid token still works with the broker down.
	jwksSrv.Close()
	if rec := doAuthRequest(gw, "mycompany.test", valid); rec.Code != 200 {
		t.Fatalf("cached valid = %d, want 200", rec.Code)
	}
	// Expired token with the key cached is an invalid token, not an outage.
	if rec := doAuthRequest(gw, "mycompany.test", expired); rec.Code != 401 {
		t.Fatalf("cached expired = %d, want 401", rec.Code)
	}
	// Unknown kid requires a fetch; broker down = 502.
	unknown := testToken(t, priv, "k-other", map[string]any{
		"iss": "https://auth.test/t/mycompany", "sub": "u",
		"aud": "cladone-go", "exp": now.Add(time.Minute).Unix(),
	})
	rec := doAuthRequest(gw, "mycompany.test", unknown)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("unknown kid + outage = %d, want 502: %s",
			rec.Code, rec.Body.String())
	}
	if rec.Header().Get("WWW-Authenticate") != "" {
		t.Fatalf("502 must not carry a WWW-Authenticate challenge")
	}
}

func loadProxyAuthConfig(t *testing.T, raw string) *core.Config {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "routes.json")
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := core.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func doAuthRequest(gw *Gateway, host, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "http://"+host+"/", nil)
	req.Host = host
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)
	return rec
}

func testKey(t *testing.T) (ed25519.PrivateKey, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv, pub
}

func testJWKS(
	t *testing.T, pub ed25519.PublicKey, kid string,
) (*httptest.Server, string) {
	t.Helper()
	set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		Key: pub, KeyID: kid, Algorithm: "EdDSA", Use: "sig",
	}}}
	mux := http.NewServeMux()
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(set)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, srv.URL + "/jwks"
}

func testToken(
	t *testing.T, priv ed25519.PrivateKey, kid string, claims map[string]any,
) string {
	t.Helper()
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.EdDSA, Key: priv},
		(&jose.SignerOptions{}).WithHeader("kid", kid))
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	obj, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := obj.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(raw)
}

func TestAC_AUTH_15_DegradedStartupAndReload(t *testing.T) {
	good := newOIDCDiscovery(t)
	bad := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "down", http.StatusServiceUnavailable)
		}))
	badURL := bad.URL
	bad.Close()

	_, pub := testKey(t)
	_, jwksURL := testJWKS(t, pub, "contoso-1")
	backend := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
	t.Cleanup(backend.Close)

	cfgFor := func(mycompanyIssuer string) *core.Config {
		return loadProxyAuthConfig(t, fmt.Sprintf(`{
			"authProviders": [
				{"id": "mycompany", "type": "oidc",
				 "issuer": %q, "clientId": "cladone-go",
				 "loginBaseUrl": "https://login.mycompany.test",
				 "cookieDomain": "mycompany.test",
				 "cookieName": "mycompany_session",
				 "sessionStore": {"type": "bolt", "path": "./mycompany.db"}},
				{"id": "contoso", "type": "jwt",
				 "issuer": "https://auth.test/t/contoso",
				 "jwksUrl": %q, "audience": "cladone-go"}
			],
			"defaultAuthProvider": "contoso",
			"routes": [
				{"host": "mycompany.test", "path": "/*", "backend": %q,
				 "auth": {"provider": "mycompany"}},
				{"host": "contoso.test", "path": "/*", "backend": %q,
				 "auth": {"provider": "contoso"}}
			]
		}`, mycompanyIssuer, jwksURL, backend.URL, backend.URL))
	}

	gw1, err := New(cfgFor(badURL))
	if err != nil {
		t.Fatalf("degraded startup: %v", err)
	}
	if p := gw1.providers["mycompany"]; p == nil || !p.degraded {
		t.Fatalf("mycompany startup = %+v, want degraded", p)
	}

	gw2, err := New(cfgFor(good))
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if p := gw2.providers["mycompany"]; p == nil || p.degraded {
		t.Fatalf("mycompany reload = %+v, want ready", p)
	}

	h := &Reloadable{}
	h.Store(gw1)
	h.Store(gw2)
	if got := h.current.Load(); got != gw2 {
		t.Fatal("reload did not swap the gateway")
	}
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
}

func newOIDCDiscovery(t *testing.T) string {
	t.Helper()
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
				"id_token_signing_alg_values_supported": []string{"EdDSA"},
			})
		})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	issuer = srv.URL
	return srv.URL
}

// TestAC_AUTH_12_PerRouteIsolation is the acceptance traceability
// alias: two providers share no token/cache identity.
func TestAC_AUTH_12_PerRouteIsolation(t *testing.T) {
	TestAC_AUTH_02_CrossTenantTokenRejected(t)
}

func TestAC_AUTH_19_RedisFailClosedAndImmediateRevocation(t *testing.T) {
	mr := miniredis.RunT(t)
	priv, pub := testKey(t)
	_, jwksURL := testJWKS(t, pub, "k1")
	backend := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
	t.Cleanup(backend.Close)

	cfg := loadProxyAuthConfig(t, fmt.Sprintf(`{
		"authProviders": [{
			"id": "mycompany", "type": "jwt",
			"issuer": "https://auth.test/t/mycompany",
			"jwksUrl": %q, "audience": "cladone-go",
			"sessionStore": {
				"type": "redis",
				"url": "redis://%s/0",
				"prefix": "test:proxy:auth:v1:"
			}
		}],
		"routes": [{"host": "mycompany.test", "path": "/*",
			"backend": %q, "auth": {"provider": "mycompany"}}]
	}`, jwksURL, mr.Addr(), backend.URL))
	gw, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer gw.Close()

	now := time.Now()
	token := testToken(t, priv, "k1", map[string]any{
		"iss": "https://auth.test/t/mycompany", "sub": "user-1", "sid": "sid-1",
		"aud": "cladone-go", "exp": now.Add(time.Hour).Unix(),
	})
	if rec := doAuthRequest(gw, "mycompany.test", token); rec.Code != 200 {
		t.Fatalf("before revoke = %d: %s", rec.Code, rec.Body.String())
	}

	store, err := authn.OpenRedisStore(t.Context(), authn.RedisConfig{
		URL:    "redis://" + mr.Addr() + "/0",
		Prefix: "test:proxy:auth:v1:",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Revoke(t.Context(), "https://auth.test/t/mycompany",
		"sid-1", "", now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if rec := doAuthRequest(gw, "mycompany.test", token); rec.Code != 401 {
		t.Fatalf("after revoke = %d, want 401: %s", rec.Code, rec.Body.String())
	}

	// Redis outage: fail closed on the auth hot path.
	mr.Close()
	rec := doAuthRequest(gw, "mycompany.test", token)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("redis down = %d, want 502: %s", rec.Code, rec.Body.String())
	}
}

func TestAC_AUTH_17_NoSecretLeak(t *testing.T) {
	_, pub := testKey(t)
	_, jwksURL := testJWKS(t, pub, "k1")
	backend := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
	t.Cleanup(backend.Close)
	cfg := loadProxyAuthConfig(t, fmt.Sprintf(`{
		"authProviders": [{
			"id": "mycompany", "type": "jwt",
			"issuer": "https://auth.test/t/mycompany",
			"jwksUrl": %q, "audience": "cladone-go"
		}],
		"routes": [{"host": "mycompany.test", "path": "/*",
			"backend": %q, "auth": {"provider": "mycompany"}}]
	}`, jwksURL, backend.URL))
	gw, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer gw.Close()

	secret := "SUPERSECRET-TOKEN-0123456789"
	var logs bytes.Buffer
	old := log.Writer()
	log.SetOutput(&logs)
	defer log.SetOutput(old)

	rec := doAuthRequest(gw, "mycompany.test", secret)
	if strings.Contains(rec.Body.String(), secret) {
		t.Fatal("response body leaked the bearer token")
	}
	if strings.Contains(logs.String(), secret) {
		t.Fatal("logs leaked the bearer token")
	}
}

func TestAC_AUTH_23_CrossInstanceRevocation(t *testing.T) {
	mr := miniredis.RunT(t)
	priv, pub := testKey(t)
	_, jwksURL := testJWKS(t, pub, "k1")
	backend := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
	t.Cleanup(backend.Close)
	cfgJSON := fmt.Sprintf(`{
		"authProviders": [{
			"id": "mycompany", "type": "jwt",
			"issuer": "https://auth.test/t/mycompany",
			"jwksUrl": %q, "audience": "cladone-go",
			"sessionStore": {
				"type": "redis", "url": "redis://%s/0",
				"prefix": "test:cross:auth:v1:"
			}
		}],
		"routes": [{"host": "mycompany.test", "path": "/*",
			"backend": %q, "auth": {"provider": "mycompany"}}]
	}`, jwksURL, mr.Addr(), backend.URL)
	gw1, err := New(loadProxyAuthConfig(t, cfgJSON))
	if err != nil {
		t.Fatal(err)
	}
	defer gw1.Close()
	gw2, err := New(loadProxyAuthConfig(t, cfgJSON))
	if err != nil {
		t.Fatal(err)
	}
	defer gw2.Close()

	now := time.Now()
	token := testToken(t, priv, "k1", map[string]any{
		"iss": "https://auth.test/t/mycompany", "sub": "user-1", "sid": "sid-cross",
		"aud": "cladone-go", "exp": now.Add(time.Hour).Unix(),
	})
	if rec := doAuthRequest(gw1, "mycompany.test", token); rec.Code != 200 {
		t.Fatalf("gw1 before = %d", rec.Code)
	}
	if rec := doAuthRequest(gw2, "mycompany.test", token); rec.Code != 200 {
		t.Fatalf("gw2 before = %d", rec.Code)
	}
	store, err := authn.OpenRedisStore(t.Context(), authn.RedisConfig{
		URL:    "redis://" + mr.Addr() + "/0",
		Prefix: "test:cross:auth:v1:",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Revoke(t.Context(), "https://auth.test/t/mycompany",
		"sid-cross", "", now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if rec := doAuthRequest(gw1, "mycompany.test", token); rec.Code != 401 {
		t.Fatalf("gw1 after = %d, want 401", rec.Code)
	}
	if rec := doAuthRequest(gw2, "mycompany.test", token); rec.Code != 401 {
		t.Fatalf("gw2 after = %d, want 401", rec.Code)
	}
}

// TestReadyz_LocalProviderState covers /readyz: local state only, and
// a single broken tenant must not mark the whole instance unready.
func TestReadyz_LocalProviderState(t *testing.T) {
	_, pub := testKey(t)
	_, jwksURL := testJWKS(t, pub, "contoso-1")
	bad := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "down", http.StatusServiceUnavailable)
		}))
	badURL := bad.URL
	bad.Close()
	backend := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
	t.Cleanup(backend.Close)

	degradedMycompany := fmt.Sprintf(`{"id": "mycompany", "type": "oidc",
		 "issuer": %q, "clientId": "cladone-go",
		 "loginBaseUrl": "https://login.mycompany.test",
		 "cookieDomain": "mycompany.test", "cookieName": "mycompany_session",
		 "sessionStore": {"type": "bolt", "path": "./mycompany.db"}}`, badURL)
	healthyJWT := fmt.Sprintf(`{"id": "contoso", "type": "jwt",
		 "issuer": "https://auth.test/t/contoso",
		 "jwksUrl": %q, "audience": "cladone-go"}`, jwksURL)

	build := func(providers string) *Gateway {
		t.Helper()
		cfg := loadProxyAuthConfig(t, fmt.Sprintf(`{
			"authProviders": [%s],
			"defaultAuthProvider": "mycompany",
			"routes": [
				{"host": "mycompany.test", "path": "/*", "backend": %q,
				 "auth": {"provider": "mycompany"}}
			]
		}`, providers, backend.URL))
		gw, err := New(cfg)
		if err != nil {
			t.Fatal(err)
		}
		return gw
	}

	readReady := func(gw *Gateway) (int, map[string]any) {
		t.Helper()
		resp := doGet(t, gw, "mycompany.test", "/readyz")
		defer resp.Body.Close()
		var body map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		return resp.StatusCode, body
	}

	// One degraded tenant, one healthy: the instance stays ready.
	code, body := readReady(build(degradedMycompany + "," + healthyJWT))
	if code != http.StatusOK {
		t.Fatalf("mixed providers /readyz = %d, want 200: %v", code, body)
	}
	providers, _ := body["providers"].(map[string]any)
	mycompany, _ := providers["mycompany"].(map[string]any)
	if mycompany["status"] != "degraded" {
		t.Fatalf("mycompany status = %v, want degraded", mycompany["status"])
	}
	if _, leaked := mycompany["error"]; leaked {
		t.Fatal("error details exposed without ?verbose=1")
	}
	contoso, _ := providers["contoso"].(map[string]any)
	if contoso["status"] != "ok" {
		t.Fatalf("contoso status = %v, want ok", contoso["status"])
	}

	// Only a degraded provider: fail-closed readiness.
	code, body = readReady(build(degradedMycompany))
	if code != http.StatusServiceUnavailable {
		t.Fatalf("all-degraded /readyz = %d, want 503: %v", code, body)
	}
	if body["status"] != "degraded" {
		t.Fatalf("status = %v, want degraded", body["status"])
	}
}
