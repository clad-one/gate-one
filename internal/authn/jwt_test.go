package authn

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-jose/go-jose/v4"
)

func TestAC_AUTH_08_JWTRejectsInvalidTokens(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	priv, pub := newTestEd25519(t)
	srv, jwksURL := newJWKSServer(t, pub, "k1")

	base := JWTConfig{
		Issuer:      "https://issuer.test",
		Audience:    "cladone-go",
		JWKSURL:     jwksURL,
		RoleClaims:  []string{"roles"},
		ScopesClaim: "scope",
		Now:         func() time.Time { return now },
	}
	j, err := NewJWT(context.Background(), base)
	if err != nil {
		t.Fatal(err)
	}

	valid := mintJWT(t, priv, "k1", map[string]any{
		"iss":   "https://issuer.test",
		"sub":   "user-1",
		"aud":   "cladone-go",
		"exp":   now.Add(5 * time.Minute).Unix(),
		"iat":   now.Unix(),
		"scope": "openid mcp-tools",
		"roles": []string{"user"},
	})
	if _, err := j.Verify(context.Background(), bearerReq(valid)); err != nil {
		t.Fatalf("valid token rejected: %v", err)
	}

	cases := []struct {
		name  string
		token string
		want  error
	}{
		{"wrong_issuer", mintJWT(t, priv, "k1", map[string]any{
			"iss": "https://evil.test", "sub": "u", "aud": "cladone-go",
			"exp": now.Add(time.Minute).Unix(),
		}), ErrUnauthenticated},
		{"wrong_audience", mintJWT(t, priv, "k1", map[string]any{
			"iss": "https://issuer.test", "sub": "u", "aud": "other",
			"exp": now.Add(time.Minute).Unix(),
		}), ErrUnauthenticated},
		{"expired", mintJWT(t, priv, "k1", map[string]any{
			"iss": "https://issuer.test", "sub": "u", "aud": "cladone-go",
			"exp": now.Add(-time.Minute).Unix(),
		}), ErrUnauthenticated},
		{"missing_kid", mintJWT(t, priv, "", map[string]any{
			"iss": "https://issuer.test", "sub": "u", "aud": "cladone-go",
			"exp": now.Add(time.Minute).Unix(),
		}), ErrUnauthenticated},
		{"tampered", valid[:len(valid)-2] + "xx", ErrUnauthenticated},
		{"alg_none", algNoneToken(), ErrUnauthenticated},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := j.Verify(context.Background(), bearerReq(tc.token))
			if err == nil || !strings.Contains(err.Error(), tc.want.Error()) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}

	// MCP scope enforcement.
	if _, err := j.VerifyMCP(
		context.Background(), bearerReq(valid), "mcp-admin", "",
	); err != ErrInsufficientScope {
		t.Fatalf("scope err = %v, want ErrInsufficientScope", err)
	}

	// Provider outage is not an invalid token: unknown kid + JWKS down.
	srv.Close()
	unknown := mintJWT(t, priv, "k-other", map[string]any{
		"iss": "https://issuer.test", "sub": "u", "aud": "cladone-go",
		"exp": now.Add(time.Minute).Unix(),
	})
	if _, err := j.Verify(context.Background(), bearerReq(unknown)); err == nil ||
		!strings.Contains(err.Error(), ErrProviderUnavailable.Error()) {
		t.Fatalf("outage err = %v, want provider unavailable", err)
	}
}

func bearerReq(token string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "http://app.test/", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	return r
}

func newTestEd25519(t *testing.T) (ed25519.PrivateKey, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv, pub
}

func newJWKSServer(
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

func mintJWT(
	t *testing.T, priv ed25519.PrivateKey, kid string, claims map[string]any,
) string {
	t.Helper()
	opts := &jose.SignerOptions{}
	if kid != "" {
		opts = opts.WithHeader("kid", kid)
	}
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.EdDSA, Key: priv}, opts)
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
	return raw
}

func algNoneToken() string {
	// {"alg":"none","typ":"JWT"} . {"sub":"u","iss":"https://issuer.test",
	// "aud":"cladone-go","exp":9999999999} .
	header := "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0"
	payload := "eyJzdWIiOiJ1IiwiaXNzIjoiaHR0cHM6Ly9pc3N1ZXIudGVzdCIsImF1ZCI6ImNsYWRvbmUtZ28iLCJleHAiOjk5OTk5OTk5OTl9"
	return header + "." + payload + "."
}

func TestAC_AUTH_04_KeyRotationKeepsSessions(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	current := now
	priv1, pub1 := newTestEd25519(t)
	priv2, pub2 := newTestEd25519(t)

	var mu sync.Mutex
	set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		Key: pub1, KeyID: "k1", Algorithm: "EdDSA", Use: "sig",
	}}}
	mux := http.NewServeMux()
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		s := set
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(s)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	j, err := NewJWT(context.Background(), JWTConfig{
		Issuer: "https://issuer.test", Audience: "cladone-go",
		JWKSURL: srv.URL + "/jwks",
		Now:     func() time.Time { return current },
	})
	if err != nil {
		t.Fatal(err)
	}
	claims := func(kid string) map[string]any {
		return map[string]any{
			"iss": "https://issuer.test", "sub": "u", "aud": "cladone-go",
			"exp": now.Add(time.Hour).Unix(), "iat": now.Unix(),
		}
	}
	t1 := mintJWT(t, priv1, "k1", claims("k1"))
	t2 := mintJWT(t, priv2, "k2", claims("k2"))
	if _, err := j.Verify(context.Background(), bearerReq(t1)); err != nil {
		t.Fatalf("k1 before rotation: %v", err)
	}
	if _, err := j.Verify(context.Background(), bearerReq(t2)); err == nil {
		t.Fatal("k2 accepted before publication")
	}

	mu.Lock()
	set.Keys = append(set.Keys, jose.JSONWebKey{
		Key: pub2, KeyID: "k2", Algorithm: "EdDSA", Use: "sig",
	})
	mu.Unlock()
	if _, err := j.Verify(context.Background(), bearerReq(t1)); err != nil {
		t.Fatalf("k1 during overlap: %v", err)
	}
	if _, err := j.Verify(context.Background(), bearerReq(t2)); err != nil {
		t.Fatalf("k2 during overlap: %v", err)
	}

	mu.Lock()
	set.Keys = []jose.JSONWebKey{{
		Key: pub2, KeyID: "k2", Algorithm: "EdDSA", Use: "sig",
	}}
	mu.Unlock()
	current = now.Add(10 * time.Minute) // JWKS cache TTL elapsed
	if _, err := j.Verify(context.Background(), bearerReq(t2)); err != nil {
		t.Fatalf("k2 after rotation: %v", err)
	}
	if _, err := j.Verify(context.Background(), bearerReq(t1)); err == nil {
		t.Fatal("retired k1 still accepted")
	}
}

func TestAC_AUTH_03_MCPValidationUsesJWKSOnly(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	priv, pub := newTestEd25519(t)
	set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		Key: pub, KeyID: "k1", Algorithm: "EdDSA", Use: "sig",
	}}}
	var calls atomic.Int64
	mux := http.NewServeMux()
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(set)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	j, err := NewJWT(context.Background(), JWTConfig{
		Issuer: "https://issuer.test", JWKSURL: srv.URL + "/jwks",
		Audience: "https://mcp.test", Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	tok := mintJWT(t, priv, "k1", map[string]any{
		"iss": "https://issuer.test", "sub": "u", "aud": "https://mcp.test",
		"exp": now.Add(5 * time.Minute).Unix(), "scope": "mcp-tools",
	})
	req := bearerReq(tok)
	if _, err := j.VerifyMCP(context.Background(), req, "mcp-tools", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := j.VerifyMCP(context.Background(), req, "mcp-tools", ""); err != nil {
		t.Fatal(err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("JWKS fetches = %d, want 1 (cached validation)", got)
	}
}

func TestAC_AUTH_19_JWTImmediateRevocation(t *testing.T) {
	mr := miniredis.RunT(t)
	store, err := OpenRedisStore(context.Background(), RedisConfig{
		URL: "redis://" + mr.Addr() + "/0",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	now := time.Unix(1_800_000_000, 0)
	priv, pub := newTestEd25519(t)
	_, jwksURL := newJWKSServer(t, pub, "k1")
	j, err := NewJWT(context.Background(), JWTConfig{
		Issuer: "https://issuer.test", Audience: "cladone-go",
		JWKSURL: jwksURL, Store: store,
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	tok := mintJWT(t, priv, "k1", map[string]any{
		"iss": "https://issuer.test", "sub": "user-1", "sid": "sid-1",
		"aud": "cladone-go", "exp": now.Add(time.Hour).Unix(),
	})
	req := bearerReq(tok)
	if _, err := j.Verify(context.Background(), req); err != nil {
		t.Fatalf("before revoke: %v", err)
	}
	if err := store.Revoke(context.Background(), "https://issuer.test",
		"sid-1", "", now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := j.Verify(context.Background(), req); !errors.Is(
		err, ErrUnauthenticated) {
		t.Fatalf("after revoke = %v, want ErrUnauthenticated", err)
	}

	// Redis outage = provider unavailable, not invalid token.
	mr.Close()
	if _, err := j.Verify(context.Background(), bearerReq(tok)); !errors.Is(
		err, ErrProviderUnavailable) {
		t.Fatalf("redis outage = %v, want ErrProviderUnavailable", err)
	}
}

func TestAC_AUTH_24_JWTGlobalLogout(t *testing.T) {
	mr := miniredis.RunT(t)
	store, err := OpenRedisStore(context.Background(), RedisConfig{
		URL: "redis://" + mr.Addr() + "/0",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	now := time.Unix(1_800_000_000, 0)
	priv, pub := newTestEd25519(t)
	_, jwksURL := newJWKSServer(t, pub, "k1")
	j, err := NewJWT(context.Background(), JWTConfig{
		Issuer: "https://issuer.test", Audience: "cladone-go",
		JWKSURL: jwksURL, Store: store,
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	mint := func(iat time.Time) string {
		return mintJWT(t, priv, "k1", map[string]any{
			"iss": "https://issuer.test", "sub": "user-1", "sid": "sid-1",
			"aud": "cladone-go", "iat": iat.Unix(),
			"exp": now.Add(time.Hour).Unix(),
		})
	}
	old := mint(now.Add(-time.Minute))
	if _, err := j.Verify(context.Background(), bearerReq(old)); err != nil {
		t.Fatalf("before logout: %v", err)
	}
	revokedAt := now.Add(-time.Second)
	if err := store.RevokeSubject(context.Background(),
		"https://issuer.test", "user-1",
		revokedAt, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := j.Verify(context.Background(), bearerReq(old)); !errors.Is(
		err, ErrUnauthenticated) {
		t.Fatalf("old token after global logout = %v", err)
	}
	// A token minted after the logout is allowed (no user lockout).
	fresh := mint(now)
	if _, err := j.Verify(context.Background(), bearerReq(fresh)); err != nil {
		t.Fatalf("fresh token = %v", err)
	}
}
