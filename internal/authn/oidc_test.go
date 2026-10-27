package authn

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// mockOIDC is a minimal OpenID Provider: discovery, authorization
// code, token endpoint and JWKS. It returns a real RS256 ID token and
// a real access token, so the gateway's verification path is
// exercised end to end.
type mockOIDC struct {
	srv  *httptest.Server
	key  *rsa.PrivateKey
	seq  int64
	mu   sync.Mutex
	code map[string]mockCode

	accessToken string
	idToken     string
}

type mockCode struct {
	nonce       string
	redirectURI string
}

func newMockOIDC(t *testing.T) *mockOIDC {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	m := &mockOIDC{key: key, code: map[string]mockCode{}}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration",
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"issuer":                                m.srv.URL,
				"authorization_endpoint":                m.srv.URL + "/authorize",
				"token_endpoint":                        m.srv.URL + "/token",
				"jwks_uri":                              m.srv.URL + "/jwks",
				"end_session_endpoint":                  m.srv.URL + "/logout",
				"backchannel_logout_supported":          true,
				"backchannel_logout_session_supported":  true,
				"response_types_supported":              []string{"code"},
				"subject_types_supported":               []string{"public"},
				"id_token_signing_alg_values_supported": []string{"RS256"},
				"scopes_supported": []string{
					"openid", "profile", "email", "offline_access",
				},
			})
		})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]any{{
				"kty": "RSA",
				"kid": "test-key",
				"use": "sig",
				"alg": "RS256",
				"n": base64.RawURLEncoding.EncodeToString(
					key.N.Bytes()),
				"e": base64.RawURLEncoding.EncodeToString(
					big.NewInt(int64(key.E)).Bytes()),
			}},
		})
	})
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		code := fmt.Sprintf("code-%d",
			atomic.AddInt64(&m.seq, 1))
		m.mu.Lock()
		m.code[code] = mockCode{
			nonce:       q.Get("nonce"),
			redirectURI: q.Get("redirect_uri"),
		}
		m.mu.Unlock()

		u, err := url.Parse(q.Get("redirect_uri"))
		if err != nil {
			http.Error(w, "bad redirect_uri", http.StatusBadRequest)
			return
		}
		rq := u.Query()
		rq.Set("code", code)
		rq.Set("state", q.Get("state"))
		u.RawQuery = rq.Encode()
		http.Redirect(w, r, u.String(), http.StatusFound)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		code := r.FormValue("code")
		m.mu.Lock()
		c, ok := m.code[code]
		delete(m.code, code)
		m.mu.Unlock()
		if !ok {
			http.Error(w, "invalid code", http.StatusBadRequest)
			return
		}
		now := time.Now()
		idClaims := map[string]any{
			"iss": m.srv.URL, "aud": "gate-one",
			"sub": "user-123", "sid": "sid-123", "nonce": c.nonce,
			"iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
			"preferred_username": "alice",
			"email":              "alice@example.com",
			"email_verified":     true,
			"realm_access": map[string]any{
				"roles": []string{"user", "offline_access"},
			},
			"resource_access": map[string]any{
				"gate-one": map[string]any{
					"roles": []string{"admin"},
				},
			},
			"groups": []string{"team-a"},
			"scope":  "openid profile email mcp-tools",
		}
		accessClaims := map[string]any{
			"iss": m.srv.URL, "aud": "mcp-resource",
			"sub": "user-123", "sid": "sid-123",
			"iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
			"preferred_username": "alice",
			"email":              "alice@example.com",
			"scope":              "openid mcp-tools",
		}
		idToken := m.sign(idClaims)
		accessToken := m.sign(accessClaims)
		m.mu.Lock()
		m.idToken = idToken
		m.accessToken = accessToken
		m.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":  accessToken,
			"refresh_token": "refresh-123",
			"token_type":    "Bearer",
			"expires_in":    300,
			"id_token":      idToken,
		})
	})
	mux.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		target := r.URL.Query().Get("post_logout_redirect_uri")
		if target == "" {
			target = "/"
		}
		http.Redirect(w, r, target, http.StatusFound)
	})

	m.srv = httptest.NewServer(mux)
	t.Cleanup(m.srv.Close)
	return m
}

func (m *mockOIDC) sign(claims map[string]any) string {
	header := map[string]any{
		"alg": "RS256", "typ": "JWT", "kid": "test-key",
	}
	hb, _ := json.Marshal(header)
	cb, _ := json.Marshal(claims)
	input := base64.RawURLEncoding.EncodeToString(hb) + "." +
		base64.RawURLEncoding.EncodeToString(cb)
	sum := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(
		rand.Reader, m.key, crypto.SHA256, sum[:])
	if err != nil {
		panic(err)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func (m *mockOIDC) logoutToken(
	sid, sub, jti string,
	iat time.Time,
) string {
	claims := map[string]any{
		"iss": m.srv.URL,
		"aud": "gate-one",
		"iat": iat.Unix(),
		"exp": iat.Add(2 * time.Minute).Unix(),
		"jti": jti,
		"events": map[string]any{
			"http://schemas.openid.net/event/backchannel-logout": map[string]any{},
		},
	}
	if sid != "" {
		claims["sid"] = sid
	}
	if sub != "" {
		claims["sub"] = sub
	}
	return m.sign(claims)
}

func newTestOIDC(t *testing.T, m *mockOIDC, now *time.Time) *OIDC {
	t.Helper()
	return newTestOIDCWith(t, m, now, nil)
}

func newTestOIDCWith(
	t *testing.T,
	m *mockOIDC,
	now *time.Time,
	mutate func(*OIDCConfig),
) *OIDC {
	t.Helper()
	cfg := OIDCConfig{
		Issuer:       m.srv.URL,
		ClientID:     "gate-one",
		ClientSecret: "secret",
		LoginBaseURL: "http://login.test:3000",
		CookieDomain: "test",
		AllowedHosts: []string{"app.test"},
		RedirectURL:  "http://login.test:3000/auth/callback",
		HTTPClient:   m.srv.Client(),
		SessionTTL:   time.Hour,
		Store:        NewMemoryStore(),
		Now:          func() time.Time { return *now },
	}
	if mutate != nil {
		mutate(&cfg)
	}
	o, err := NewOIDC(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	return o
}

func findCookie(rec *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// performLogin runs the full code + PKCE flow against the mock IdP and
// returns the RP session cookie.
func performLogin(t *testing.T, m *mockOIDC, o *OIDC) *http.Cookie {
	t.Helper()
	rec := performLoginRec(t, m, o)
	session := findCookie(rec, oidcSessionCookie)
	if session == nil {
		t.Fatal("session cookie missing")
	}
	return session
}

func performLoginRec(
	t *testing.T,
	m *mockOIDC,
	o *OIDC,
) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(
		http.MethodGet,
		"http://login.test:3000/login?returnTo=http://app.test/",
		nil,
	)
	o.ServeLogin(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("login = %d, want 302", rec.Code)
	}
	tx := findCookie(rec, oidcTxCookie)
	if tx == nil {
		t.Fatal("tx cookie missing")
	}
	client := m.srv.Client()
	client.CheckRedirect = func(
		req *http.Request, via []*http.Request,
	) error {
		return http.ErrUseLastResponse
	}
	resp, err := client.Get(rec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	callback := resp.Header.Get("Location")
	if callback == "" {
		t.Fatalf("authorize = %d, no Location", resp.StatusCode)
	}
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, callback, nil)
	req.AddCookie(tx)
	o.ServeLogin(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("callback = %d: %s", rec.Code, rec.Body.String())
	}
	return rec
}

func backchannelRequest(
	t *testing.T,
	o *OIDC,
	token string,
) *httptest.ResponseRecorder {
	t.Helper()
	form := url.Values{"logout_token": {token}}
	req := httptest.NewRequest(
		http.MethodPost, "http://login.test:3000/backchannel-logout",
		strings.NewReader(form.Encode()),
	)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	o.ServeLogin(rec, req)
	return rec
}

func TestOIDCLoginAndMCP(t *testing.T) {
	m := newMockOIDC(t)
	now := time.Now()
	o := newTestOIDC(t, m, &now)

	// 1. /login → IdP authorization URL, with PKCE and state cookie.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(
		http.MethodGet,
		"http://login.test:3000/login?returnTo=http://app.test/",
		nil,
	)
	o.ServeLogin(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("login = %d, want 302", rec.Code)
	}
	authURL := rec.Header().Get("Location")
	if !strings.HasPrefix(authURL, m.srv.URL+"/authorize") {
		t.Fatalf("authorization URL = %q", authURL)
	}
	for _, want := range []string{
		"code_challenge=", "code_challenge_method=S256",
		"nonce=", "state=",
	} {
		if !strings.Contains(authURL, want) {
			t.Errorf("authorization URL missing %q: %s", want, authURL)
		}
	}
	tx := findCookie(rec, oidcTxCookie)
	if tx == nil || tx.Value == "" {
		t.Fatal("tx cookie missing")
	}

	// 2. Follow the IdP authorization (no auto-follow to the login
	// host, which the test does not serve).
	client := m.srv.Client()
	client.CheckRedirect = func(
		req *http.Request, via []*http.Request,
	) error {
		return http.ErrUseLastResponse
	}
	resp, err := client.Get(authURL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("authorize = %d, want 302", resp.StatusCode)
	}
	callback := resp.Header.Get("Location")
	if !strings.HasPrefix(
		callback, "http://login.test:3000/auth/callback?") {
		t.Fatalf("callback = %q", callback)
	}

	// 3. Callback: code exchange, ID token verification, session.
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, callback, nil)
	req.AddCookie(tx)
	o.ServeLogin(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("callback = %d, want 302: %s",
			rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Location"); got != "http://app.test/" {
		t.Errorf("callback redirect = %q", got)
	}
	session := findCookie(rec, oidcSessionCookie)
	if session == nil || session.Value == "" {
		t.Fatal("session cookie missing")
	}

	// 4. Verify on an application host.
	req = httptest.NewRequest(http.MethodGet, "http://app.test/", nil)
	req.AddCookie(session)
	res, err := o.Verify(context.Background(), req)
	if err != nil {
		t.Fatalf("Verify = %v", err)
	}
	if res.UserID != "user-123" || res.Username != "alice" {
		t.Errorf("identity = %+v", res.Identity)
	}
	for _, role := range []string{
		"user", "offline_access", "admin", "team-a",
	} {
		if !contains(res.Roles, role) {
			t.Errorf("roles = %v, missing %q", res.Roles, role)
		}
	}
	if !contains(res.Scopes, "mcp-tools") {
		t.Errorf("scopes = %v, missing mcp-tools", res.Scopes)
	}

	// 5. MCP: local JWT verification, scope enforcement.
	m.mu.Lock()
	access := m.accessToken
	m.mu.Unlock()
	req = httptest.NewRequest(http.MethodPost, "http://mcp.test/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+access)
	res, err = o.VerifyMCP(
		context.Background(), req, "mcp-tools", "")
	if err != nil {
		t.Fatalf("VerifyMCP = %v", err)
	}
	if res.Username != "alice" {
		t.Errorf("MCP user = %q", res.Username)
	}
	if _, err := o.VerifyMCP(
		context.Background(), req, "mcp-admin", "",
	); !errors.Is(err, ErrInsufficientScope) {
		t.Errorf("missing scope = %v, want ErrInsufficientScope", err)
	}

	// 6. Logout: RP-initiated end_session with id_token_hint.
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(
		http.MethodGet,
		"http://login.test:3000/logout?returnTo=http://app.test/",
		nil,
	)
	req.AddCookie(session)
	o.ServeLogin(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("logout = %d, want 302", rec.Code)
	}
	loc := rec.Header().Get("Location")
	if !strings.HasPrefix(loc, m.srv.URL+"/logout?") ||
		!strings.Contains(loc, "id_token_hint=") ||
		!strings.Contains(loc, "post_logout_redirect_uri=") {
		t.Errorf("logout location = %q", loc)
	}
	if c := findCookie(rec, oidcSessionCookie); c == nil || c.MaxAge >= 0 {
		t.Error("logout did not clear the session cookie")
	}

	// 7. Session expiry: the RP session TTL (1h in this test).
	now = now.Add(2 * time.Hour)
	req = httptest.NewRequest(http.MethodGet, "http://app.test/", nil)
	req.AddCookie(session)
	if _, err := o.Verify(
		context.Background(), req,
	); !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("expired session = %v, want ErrUnauthenticated", err)
	}
}

func TestOIDCBackchannelLogout(t *testing.T) {
	m := newMockOIDC(t)
	now := time.Now()
	o := newTestOIDC(t, m, &now)
	session := performLogin(t, m, o)

	req := httptest.NewRequest(http.MethodGet, "http://app.test/", nil)
	req.AddCookie(session)
	res, err := o.Verify(context.Background(), req)
	if err != nil {
		t.Fatalf("Verify before logout = %v", err)
	}
	if res.SessionID != "sid-123" {
		t.Errorf("SessionID = %q, want sid-123", res.SessionID)
	}

	// A back-channel logout token revokes the session.
	token := m.logoutToken("sid-123", "user-123", "jti-1", now)
	rec := backchannelRequest(t, o, token)
	if rec.Code != http.StatusOK {
		t.Fatalf("backchannel = %d: %s", rec.Code, rec.Body.String())
	}
	if _, err := o.Verify(context.Background(), req); !errors.Is(
		err, ErrUnauthenticated,
	) {
		t.Errorf("Verify after logout = %v, want ErrUnauthenticated", err)
	}

	// The same jti is a replay.
	if rec := backchannelRequest(t, o, token); rec.Code != http.StatusBadRequest {
		t.Errorf("replayed backchannel = %d, want 400", rec.Code)
	}

	// A stale iat is refused.
	stale := m.logoutToken("sid-999", "", "jti-stale", now.Add(-10*time.Minute))
	if rec := backchannelRequest(t, o, stale); rec.Code != http.StatusBadRequest {
		t.Errorf("stale backchannel = %d, want 400", rec.Code)
	}

	// An invalid token is refused.
	if rec := backchannelRequest(t, o, "not-a-jwt"); rec.Code != http.StatusBadRequest {
		t.Errorf("invalid backchannel = %d, want 400", rec.Code)
	}
}

func TestOIDCBackchannelLogoutBySubject(t *testing.T) {
	m := newMockOIDC(t)
	now := time.Now()
	o := newTestOIDC(t, m, &now)
	session := performLogin(t, m, o)

	// No sid: the revocation applies to every session of the user.
	token := m.logoutToken("", "user-123", "jti-sub", now)
	rec := backchannelRequest(t, o, token)
	if rec.Code != http.StatusOK {
		t.Fatalf("backchannel = %d: %s", rec.Code, rec.Body.String())
	}
	req := httptest.NewRequest(http.MethodGet, "http://app.test/", nil)
	req.AddCookie(session)
	if _, err := o.Verify(
		context.Background(), req,
	); !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("Verify after sub logout = %v, want ErrUnauthenticated", err)
	}
}

func TestOIDCBackchannelOptOut(t *testing.T) {
	m := newMockOIDC(t)
	now := time.Now()
	off := false
	o, err := NewOIDC(context.Background(), OIDCConfig{
		Issuer:            m.srv.URL,
		ClientID:          "gate-one",
		ClientSecret:      "secret",
		LoginBaseURL:      "http://login.test:3000",
		CookieDomain:      "test",
		AllowedHosts:      []string{"app.test"},
		RedirectURL:       "http://login.test:3000/auth/callback",
		HTTPClient:        m.srv.Client(),
		SessionTTL:        time.Hour,
		Store:             NewMemoryStore(),
		BackchannelLogout: &off,
		Now:               func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	rec := backchannelRequest(t, o, "irrelevant")
	if rec.Code != http.StatusNotFound {
		t.Errorf("disabled backchannel = %d, want 404", rec.Code)
	}
}

func TestOIDCLegacyTokenCookies(t *testing.T) {
	m := newMockOIDC(t)
	now := time.Now()
	o := newTestOIDCWith(t, m, &now, func(c *OIDCConfig) {
		c.LegacyTokenCookies = true
	})
	rec := performLoginRec(t, m, o)

	for _, name := range []string{
		"access_token", "refresh_token", "id_token",
	} {
		c := findCookie(rec, name)
		if c == nil || c.Value == "" {
			t.Errorf("legacy cookie %s missing", name)
		}
	}

	session := findCookie(rec, oidcSessionCookie)
	if session == nil {
		t.Fatal("session cookie missing")
	}
	rec = httptest.NewRecorder()
	req := httptest.NewRequest(
		http.MethodGet,
		"http://login.test:3000/logout?returnTo=http://app.test/",
		nil,
	)
	req.AddCookie(session)
	o.ServeLogin(rec, req)
	for _, name := range []string{
		"access_token", "refresh_token", "id_token",
	} {
		c := findCookie(rec, name)
		if c == nil || c.MaxAge >= 0 {
			t.Errorf("legacy cookie %s not cleared on logout", name)
		}
	}
}

func TestOIDCMCPAudienceAuto(t *testing.T) {
	m := newMockOIDC(t)
	now := time.Now()
	o := newTestOIDCWith(t, m, &now, func(c *OIDCConfig) {
		c.MCPAudience = "auto"
	})
	_ = performLogin(t, m, o)

	m.mu.Lock()
	access := m.accessToken
	m.mu.Unlock()
	req := httptest.NewRequest(http.MethodPost, "http://mcp.test/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+access)

	if _, err := o.VerifyMCP(
		context.Background(), req, "mcp-tools", "mcp-resource",
	); err != nil {
		t.Fatalf("matching auto audience = %v", err)
	}
	if _, err := o.VerifyMCP(
		context.Background(), req, "mcp-tools", "other-resource",
	); !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("wrong auto audience = %v, want ErrUnauthenticated", err)
	}
}

func TestOIDCRejectsBadState(t *testing.T) {
	m := newMockOIDC(t)
	now := time.Now()
	o := newTestOIDC(t, m, &now)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(
		http.MethodGet,
		"http://login.time:3000/auth/callback?code=x&state=bad",
		nil,
	)
	o.ServeLogin(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("callback without tx = %d, want 400", rec.Code)
	}
}

func TestOIDCDiscoveryFailure(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := NewOIDC(ctx, OIDCConfig{
		Issuer:       "http://127.0.0.1:1",
		ClientID:     "gate-one",
		LoginBaseURL: "http://login.test:3000",
		CookieDomain: "test",
	})
	if err == nil || !strings.Contains(err.Error(), "cannot discover") {
		t.Fatalf("err = %v, want discovery refusal", err)
	}
}
