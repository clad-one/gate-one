package iam

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"cladone/gate-one/internal/authn"
	"cladone/gate-one/internal/testutil/fakegoogle"
	"cladone/gate-one/pkg/identityadapter"
	"cladone/gate-one/pkg/identityadapter/conformance"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-jose/go-jose/v4"
)

func TestAC_AUTH_01_GoogleLoginCreatesSession(t *testing.T) {
	google := newFakeGoogle(t)
	b, srv := newTestIAM(t, google)
	_ = b

	verifier := "verifier-0123456789-0123456789-0123456789"
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	redirectURI := "https://login.mycompany.test/auth/callback"
	state := "client-state"
	client := &http.Client{CheckRedirect: func(
		*http.Request, []*http.Request,
	) error {
		return http.ErrUseLastResponse
	}}

	q := url.Values{}
	q.Set("client_id", "cladone-go")
	q.Set("redirect_uri", redirectURI)
	q.Set("response_type", "code")
	q.Set("scope", "openid profile email")
	q.Set("state", state)
	q.Set("nonce", "nonce-1")
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")

	resp, err := client.Get(srv.URL + "/t/mycompany/authorize?" + q.Encode())
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("authorize = %d", resp.StatusCode)
	}
	googleURL, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(googleURL.String(), google.srv.URL+"/authorize") {
		t.Fatalf("google location = %s", googleURL)
	}

	// Fake Google auto-consents and redirects to the IAM callback.
	resp, err = client.Get(googleURL.String())
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("google authorize = %d", resp.StatusCode)
	}
	cb, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}

	// IAM callback exchanges the code and redirects to the client.
	resp, err = client.Get(cb.String())
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("IAM callback = %d: %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	clientRedirect, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if clientRedirect.Scheme+"://"+clientRedirect.Host+clientRedirect.Path != redirectURI {
		t.Fatalf("client redirect = %s", clientRedirect)
	}
	if clientRedirect.Query().Get("state") != state {
		t.Fatalf("state = %q", clientRedirect.Query().Get("state"))
	}
	if len(resp.Cookies()) == 0 {
		t.Fatal("the IAM did not set its SSO session cookie")
	}
	iamCode := clientRedirect.Query().Get("code")
	if iamCode == "" {
		t.Fatal("no IAM code")
	}

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", iamCode)
	form.Set("client_id", "cladone-go")
	form.Set("client_secret", "secret")
	form.Set("redirect_uri", redirectURI)
	form.Set("code_verifier", verifier)
	resp, err = http.PostForm(srv.URL+"/t/mycompany/token", form)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("token = %d: %s", resp.StatusCode, body)
	}
	var tokens map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&tokens); err != nil {
		t.Fatal(err)
	}
	access, _ := tokens["access_token"].(string)
	id, _ := tokens["id_token"].(string)
	if access == "" || id == "" {
		t.Fatalf("tokens = %+v", tokens)
	}

	pub := b.tenants["mycompany"].activeKey().pub

	accessClaims := verifyJWT(t, pub, access)
	if accessClaims["iss"] != srv.URL+"/t/mycompany" {
		t.Errorf("iss = %v", accessClaims["iss"])
	}
	if accessClaims["tenant"] != "mycompany" {
		t.Errorf("tenant = %v", accessClaims["tenant"])
	}
	if accessClaims["email"] != "alice@mycompany.test" {
		t.Errorf("email = %v", accessClaims["email"])
	}
	if accessClaims["sid"] == "" {
		t.Error("sid missing")
	}
	idClaims := verifyJWT(t, pub, id)
	if idClaims["nonce"] != "nonce-1" {
		t.Errorf("nonce = %v", idClaims["nonce"])
	}
	if idClaims["aud"] != "cladone-go" {
		t.Errorf("id aud = %v", idClaims["aud"])
	}
}

func TestAC_AUTH_09_IdentityAdapterConformance(t *testing.T) {
	// The IAM upstream adapter is the OIDC/Google adapter; the
	// generic conformance suite is exercised in pkg/identityadapter.
	// Here we assert the IAM emits a conformant discovery + JWKS.
	google := newFakeGoogle(t)
	b, srv := newTestIAM(t, google)
	_ = b

	resp, err := http.Get(srv.URL + "/t/mycompany/.well-known/openid-configuration")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var disc map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&disc); err != nil {
		t.Fatal(err)
	}
	if disc["issuer"] != srv.URL+"/t/mycompany" {
		t.Fatalf("issuer = %v", disc["issuer"])
	}
	for _, k := range []string{
		"authorization_endpoint", "token_endpoint", "jwks_uri",
		"code_challenge_methods_supported",
		"cladone_refresh_token_ttl_seconds",
	} {
		if disc[k] == nil {
			t.Errorf("discovery missing %s", k)
		}
	}

	resp, err = http.Get(srv.URL + "/t/mycompany/jwks.json")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var set jose.JSONWebKeySet
	if err := json.NewDecoder(resp.Body).Decode(&set); err != nil {
		t.Fatal(err)
	}
	if len(set.Keys) != 1 || set.Keys[0].KeyID == "" {
		t.Fatalf("jwks = %+v", set)
	}
}

func TestAC_AUTH_09_ClientCredentials(t *testing.T) {
	google := newFakeGoogle(t)
	b, srv := newTestIAM(t, google)
	_ = b

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", "cladone-go")
	form.Set("client_secret", "secret")
	form.Set("audience", "https://mcp.mycompany.test")
	form.Set("scope", "mcp-tools")
	resp, err := http.PostForm(srv.URL+"/t/mycompany/token", form)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("token = %d: %s", resp.StatusCode, body)
	}
	var tokens map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&tokens); err != nil {
		t.Fatal(err)
	}
	access, _ := tokens["access_token"].(string)
	if access == "" {
		t.Fatal("no access token")
	}
	pub := b.tenants["mycompany"].activeKey().pub
	claims := verifyJWT(t, pub, access)
	if claims["sub"] != "cladone-go" {
		t.Errorf("sub = %v", claims["sub"])
	}
	if claims["aud"] != "https://mcp.mycompany.test" {
		t.Errorf("aud = %v", claims["aud"])
	}
	if claims["tenant"] != "mycompany" {
		t.Errorf("tenant = %v", claims["tenant"])
	}
}

func TestAC_AUTH_13_IAMRejectsBadRedirect(t *testing.T) {
	google := newFakeGoogle(t)
	_, srv := newTestIAM(t, google)
	resp, err := http.Get(srv.URL + "/t/mycompany/authorize?client_id=cladone-go&" +
		"redirect_uri=https://evil.test/cb&response_type=code&scope=openid&state=x")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func newTestIAM(t *testing.T, google *fakeGoogle) (*IAM, *httptest.Server) {
	t.Helper()
	cfg := &Config{
		PublicURL: "http://placeholder.test",
		Tenants: []Tenant{{
			ID:           "mycompany",
			ClientID:     "cladone-go",
			ClientSecret: "secret",
			RedirectURIs: []string{"https://login.mycompany.test/auth/callback"},
			Audiences:    []string{"https://mcp.mycompany.test"},
			Google: GoogleConfig{
				Issuer:       google.srv.URL,
				ClientID:     "google-client",
				ClientSecret: "google-secret",
				HostedDomain: "mycompany.test",
				Scopes:       []string{"openid", "profile", "email"},
			},
			DefaultRoles:   []string{"user"},
			AllowedDomains: []string{"mycompany.test"},
			AdminEmails:    []string{"admin@mycompany.test"},
		}},
	}
	b, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(b.Handler())
	t.Cleanup(srv.Close)
	b.SetPublicURL(srv.URL)
	return b, srv
}

type fakeGoogle struct {
	srv *httptest.Server
}

func newFakeGoogle(t *testing.T) *fakeGoogle {
	t.Helper()
	fg, err := fakegoogle.New(fakegoogle.Config{
		ClientID: "google-client",
		Users: []fakegoogle.User{{
			Sub:               "google-sub-1",
			Email:             "alice@mycompany.test",
			EmailVerified:     true,
			HostedDomain:      "mycompany.test",
			PreferredUsername: "alice",
			Name:              "Alice",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(fg)
	t.Cleanup(srv.Close)
	fg.SetIssuer(srv.URL)
	return &fakeGoogle{srv: srv}
}

func verifyJWT(
	t *testing.T, pub ed25519.PublicKey, raw string,
) map[string]any {
	t.Helper()
	jws, err := jose.ParseSigned(raw, []jose.SignatureAlgorithm{jose.EdDSA})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := jws.Verify(pub)
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	return claims
}

func TestAC_AUTH_18_IAMRedisStore(t *testing.T) {
	mr := miniredis.RunT(t)
	google := newFakeGoogle(t)
	cfg := testIAMConfig(google)
	cfg.Redis = &RedisConfig{
		URL:        "redis://" + mr.Addr() + "/0",
		AuthPrefix: "test:auth:v1:",
	}
	b, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	ctx := context.Background()
	f := &flow{Tenant: "mycompany", ClientID: "cladone-go", Expires: time.Now().Add(time.Minute)}
	if err := b.store.PutFlow(ctx, "mycompany", "flow-1", f, time.Minute); err != nil {
		t.Fatal(err)
	}
	got, err := b.store.TakeFlow(ctx, "mycompany", "flow-1")
	if err != nil || got == nil || got.ClientID != "cladone-go" {
		t.Fatalf("flow = %+v, %v", got, err)
	}
	got, _ = b.store.TakeFlow(ctx, "mycompany", "flow-1")
	if got != nil {
		t.Fatal("flow was not consumed")
	}

	// A second IAM instance sees the same code store.
	b2, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer b2.Close()
	c := &authCode{Tenant: "mycompany", ClientID: "cladone-go", Expires: time.Now().Add(time.Minute)}
	if err := b.store.PutCode(ctx, "mycompany", "code-1", c, time.Minute); err != nil {
		t.Fatal(err)
	}
	gotCode, err := b2.store.TakeCode(ctx, "mycompany", "code-1")
	if err != nil || gotCode == nil || gotCode.ClientID != "cladone-go" {
		t.Fatalf("code across instances = %+v, %v", gotCode, err)
	}

	// IAM revocation is readable by Gate One's shared store.
	if err := b.Revoke(ctx, "mycompany", "sid-1", "", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	gs, err := authn.OpenRedisStore(ctx, authn.RedisConfig{
		URL:    "redis://" + mr.Addr() + "/0",
		Prefix: "test:auth:v1:",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer gs.Close()
	revoked, err := gs.IsRevoked(ctx, b.issuer(b.tenants["mycompany"]), "sid-1", "")
	if err != nil || !revoked {
		t.Fatalf("gate one sees revocation = %v, %v", revoked, err)
	}
}

func testIAMConfig(google *fakeGoogle) *Config {
	return &Config{
		PublicURL: "https://iam.test",
		Tenants: []Tenant{{
			ID:           "mycompany",
			ClientID:     "cladone-go",
			ClientSecret: "secret",
			RedirectURIs: []string{"https://login.mycompany.test/auth/callback"},
			Audiences:    []string{"https://mcp.mycompany.test"},
			Google: GoogleConfig{
				Issuer:       google.srv.URL,
				ClientID:     "google-client",
				ClientSecret: "google-secret",
				HostedDomain: "mycompany.test",
			},
			DefaultRoles:   []string{"user"},
			AllowedDomains: []string{"mycompany.test"},
		}},
	}
}

func TestAC_AUTH_09_GoogleAdapterConformance(t *testing.T) {
	google := newFakeGoogle(t)
	tnt := testIAMConfig(google).Tenants[0]
	a, err := newOIDCAdapter(context.Background(), tnt,
		"https://iam.test", nil, time.Now, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	conformance.Run(t, a)
}

func TestAC_AUTH_09_GoogleAdapterStartContinue(t *testing.T) {
	google := newFakeGoogle(t)
	tnt := testIAMConfig(google).Tenants[0]
	a, err := newOIDCAdapter(context.Background(), tnt,
		"https://iam.test", nil, time.Now, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	step, err := a.Start(context.Background(), identityadapter.Request{
		Tenant: "mycompany",
		Params: map[string]string{
			"iam_state": "flow-1",
			"nonce":     "nonce-adapter",
		},
		Header: map[string][]string{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if step.Kind != identityadapter.StepRedirect {
		t.Fatalf("step = %s", step.Kind)
	}
	// Fake Google stores the code/nonce and redirects to the IAM.
	client := &http.Client{CheckRedirect: func(
		*http.Request, []*http.Request,
	) error {
		return http.ErrUseLastResponse
	}}
	resp, err := client.Get(step.RedirectURL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("google authorize = %d", resp.StatusCode)
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatal("fake google returned no code")
	}
	cont, err := a.Continue(context.Background(), identityadapter.Request{
		Tenant: "mycompany",
		Params: map[string]string{"code": code},
	}, step.State)
	if err != nil {
		t.Fatal(err)
	}
	if cont.Kind != identityadapter.StepResult || cont.Assertion == nil {
		t.Fatalf("continue = %+v, want result", cont)
	}
	if cont.Assertion.Email != "alice@mycompany.test" {
		t.Errorf("email = %q", cont.Assertion.Email)
	}
}

func TestAC_AUTH_20_IAMKeyRotation(t *testing.T) {
	google := newFakeGoogle(t)
	dir := t.TempDir()
	writeKey := func(name string) (string, ed25519.PublicKey) {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, name)
		body := base64.RawURLEncoding.EncodeToString(priv.Seed())
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return path, pub
	}
	k1, _ := writeKey("k1.key")
	k2, pub2 := writeKey("k2.key")
	cfg := testIAMConfig(google)
	cfg.Tenants[0].KeyFiles = []string{k1, k2}
	b, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	rt := b.tenants["mycompany"]
	if len(rt.keys) != 2 {
		t.Fatalf("keys = %d", len(rt.keys))
	}
	if rt.activeKey().kid == rt.keys[0].kid {
		t.Fatal("active key is not the newest")
	}
	if got := len(mergeJWKS(rt.keys).Keys); got != 2 {
		t.Fatalf("jwks keys = %d", got)
	}
	claims := map[string]any{"iss": "https://iam.test/t/mycompany", "sub": "u"}
	tok, err := rt.activeKey().sign(claims)
	if err != nil {
		t.Fatal(err)
	}
	jws, err := jose.ParseSigned(tok, []jose.SignatureAlgorithm{jose.EdDSA})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := jws.Verify(pub2); err != nil {
		t.Fatalf("active key verify: %v", err)
	}
}

func TestAC_AUTH_21_RevokeWithConfig(t *testing.T) {
	mr := miniredis.RunT(t)
	google := newFakeGoogle(t)
	cfg := testIAMConfig(google)
	cfg.Redis = &RedisConfig{
		URL:        "redis://" + mr.Addr() + "/0",
		AuthPrefix: "test:revoke:v1:",
	}
	ctx := context.Background()
	if err := RevokeWithConfig(ctx, cfg, "mycompany", "sid-cli", "", time.Hour); err != nil {
		t.Fatal(err)
	}
	gs, err := authn.OpenRedisStore(ctx, authn.RedisConfig{
		URL:    "redis://" + mr.Addr() + "/0",
		Prefix: "test:revoke:v1:",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer gs.Close()
	revoked, err := gs.IsRevoked(ctx, cfg.PublicURL+"/t/mycompany", "sid-cli", "")
	if err != nil || !revoked {
		t.Fatalf("revoked = %v, %v", revoked, err)
	}
	if err := RevokeWithConfig(ctx, cfg, "nope", "sid", "", time.Hour); err == nil {
		t.Fatal("unknown tenant accepted")
	}
}

func TestAC_AUTH_22_LogoutRevokesSharedSID(t *testing.T) {
	google := newFakeGoogle(t)
	b, srv := newTestIAM(t, google)
	ctx := context.Background()
	rt := b.tenants["mycompany"]

	// A browser session shared by two apps in the same browser.
	if err := b.store.PutSession(ctx, "mycompany", "browser-1", "sid-shared", "user-1",
		time.Now().Add(-time.Minute), time.Hour); err != nil {
		t.Fatal(err)
	}
	q := url.Values{}
	q.Set("client_id", "cladone-go")
	q.Set("redirect_uri", "https://login.mycompany.test/auth/callback")
	q.Set("response_type", "code")
	q.Set("scope", "openid")
	q.Set("state", "client-state")
	q.Set("nonce", "nonce-1")
	q.Set("code_challenge", "challenge")
	q.Set("code_challenge_method", "S256")
	req := httptest.NewRequest(http.MethodGet,
		srv.URL+"/t/mycompany/authorize?"+q.Encode(), nil)
	req.AddCookie(&http.Cookie{Name: b.cfg.SessionCookieName, Value: "browser-1"})
	rec := httptest.NewRecorder()
	b.serveHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("authorize = %d: %s", rec.Code, rec.Body.String())
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	flowID := loc.Query().Get("state")
	f, err := b.store.TakeFlow(ctx, "mycompany", flowID)
	if err != nil || f == nil {
		t.Fatalf("flow = %+v, %v", f, err)
	}
	if f.SID != "sid-shared" {
		t.Fatalf("flow sid = %q, want sid-shared", f.SID)
	}

	// Logout via the IAM cookie revokes the shared sid immediately.
	req = httptest.NewRequest(http.MethodGet, srv.URL+"/t/mycompany/logout", nil)
	req.AddCookie(&http.Cookie{Name: b.cfg.SessionCookieName, Value: "browser-1"})
	rec = httptest.NewRecorder()
	b.serveHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("logout = %d: %s", rec.Code, rec.Body.String())
	}
	revoked, err := b.store.IsRevoked(ctx, b.issuer(rt), "sid-shared", "")
	if err != nil || !revoked {
		t.Fatalf("revoked = %v, %v", revoked, err)
	}
	// Global user logout: old sessions are revoked, a fresh login is not.
	old, err := b.store.IsSubjectRevoked(ctx, b.issuer(rt), "user-1",
		time.Now().Add(-time.Minute))
	if err != nil || !old {
		t.Fatalf("old subject = %v, %v", old, err)
	}
	fresh, err := b.store.IsSubjectRevoked(ctx, b.issuer(rt), "user-1",
		time.Now().Add(time.Minute))
	if err != nil || fresh {
		t.Fatalf("fresh subject = %v, %v", fresh, err)
	}
	// A new login after the logout can reuse its new browser session.
	if err := b.store.PutSession(ctx, "mycompany", "browser-2", "sid-new",
		"user-1", time.Now().Add(time.Minute), time.Hour); err != nil {
		t.Fatal(err)
	}
	req = httptest.NewRequest(http.MethodGet, srv.URL+"/t/mycompany/authorize", nil)
	req.AddCookie(&http.Cookie{Name: b.cfg.SessionCookieName, Value: "browser-2"})
	_, gotSID, _, _, err := b.browserSession(ctx, rt, req)
	if err != nil || gotSID != "sid-new" {
		t.Fatalf("fresh browser session = %q, %v", gotSID, err)
	}

	// id_token_hint path (no cookie): a valid IAM ID token revokes its sid.
	hint, err := rt.activeKey().sign(map[string]any{
		"iss": b.issuer(rt), "sub": "user-1", "sid": "sid-hint",
		"aud": "cladone-go", "exp": time.Now().Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	req = httptest.NewRequest(http.MethodGet,
		srv.URL+"/t/mycompany/logout?id_token_hint="+url.QueryEscape(hint), nil)
	rec = httptest.NewRecorder()
	b.serveHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("logout hint = %d: %s", rec.Code, rec.Body.String())
	}
	revoked, err = b.store.IsRevoked(ctx, b.issuer(rt), "sid-hint", "")
	if err != nil || !revoked {
		t.Fatalf("hint revoked = %v, %v", revoked, err)
	}
}
