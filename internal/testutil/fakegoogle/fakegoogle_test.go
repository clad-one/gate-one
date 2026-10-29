package fakegoogle

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/go-jose/go-jose/v4"
)

func newTestServer(t *testing.T, cfg Config) (*Server, *httptest.Server) {
	t.Helper()
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(s)
	t.Cleanup(ts.Close)
	s.SetIssuer(ts.URL)
	return s, ts
}

func TestDiscoveryAndJWKS(t *testing.T) {
	s, ts := newTestServer(t, Config{ClientID: "google-client"})

	var disco map[string]any
	getJSON(t, ts.URL+"/.well-known/openid-configuration", &disco)
	if disco["issuer"] != ts.URL {
		t.Fatalf("issuer = %v, want %s", disco["issuer"], ts.URL)
	}
	if disco["jwks_uri"] != ts.URL+"/jwks" {
		t.Fatalf("jwks_uri = %v", disco["jwks_uri"])
	}

	var set jose.JSONWebKeySet
	getJSON(t, ts.URL+"/jwks", &set)
	if len(set.Keys) != 1 || set.Keys[0].KeyID == "" {
		t.Fatalf("jwks = %+v", set)
	}
	_ = s
}

func TestAuthorizeToken(t *testing.T) {
	_, ts := newTestServer(t, Config{
		ClientID: "google-client",
		Users: []User{{
			Sub: "google-sub-1", Email: "alice@acme.test",
			EmailVerified: true, HostedDomain: "acme.test",
			PreferredUsername: "alice", Name: "Alice",
			Groups: []string{"admins"},
		}},
	})

	code, state := authorize(t, ts.URL, "nonce-1", "")
	if state != "state-1" {
		t.Fatalf("state = %q", state)
	}
	tokens := exchange(t, ts.URL, code, "https://broker.test/callback")
	raw, _ := tokens["id_token"].(string)
	if raw == "" {
		t.Fatal("missing id_token")
	}

	var set jose.JSONWebKeySet
	getJSON(t, ts.URL+"/jwks", &set)
	claims := verify(t, set, raw)
	if claims["iss"] != ts.URL {
		t.Errorf("iss = %v", claims["iss"])
	}
	if claims["aud"] != "google-client" {
		t.Errorf("aud = %v", claims["aud"])
	}
	if claims["nonce"] != "nonce-1" {
		t.Errorf("nonce = %v", claims["nonce"])
	}
	if claims["email"] != "alice@acme.test" {
		t.Errorf("email = %v", claims["email"])
	}
	if claims["hd"] != "acme.test" {
		t.Errorf("hd = %v", claims["hd"])
	}
	if claims["preferred_username"] != "alice" {
		t.Errorf("preferred_username = %v", claims["preferred_username"])
	}
}

func TestToggles(t *testing.T) {
	s, ts := newTestServer(t, Config{})

	s.SetFailDiscovery(true)
	if code := status(t, ts.URL+"/.well-known/openid-configuration"); code != 503 {
		t.Fatalf("fail discovery = %d", code)
	}
	s.SetFailDiscovery(false)

	s.SetFailJWKS(true)
	if code := status(t, ts.URL+"/jwks"); code != 503 {
		t.Fatalf("fail jwks = %d", code)
	}
	s.SetFailJWKS(false)

	s.SetInvalidJWKS(true)
	var body map[string]any
	getJSON(t, ts.URL+"/jwks", &body)
	if body["keys"] == nil {
		t.Fatalf("invalid jwks body = %v", body)
	}
	s.SetInvalidJWKS(false)

	s.SetFailToken(true)
	resp, err := http.PostForm(ts.URL+"/token", url.Values{"code": {"x"}})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 500 {
		t.Fatalf("fail token = %d", resp.StatusCode)
	}
}

func TestRotateKey(t *testing.T) {
	s, ts := newTestServer(t, Config{})

	var before jose.JSONWebKeySet
	getJSON(t, ts.URL+"/jwks", &before)
	if len(before.Keys) != 1 {
		t.Fatalf("initial keys = %d", len(before.Keys))
	}
	kid1 := before.Keys[0].KeyID

	if err := s.RotateKey(); err != nil {
		t.Fatal(err)
	}
	var overlap jose.JSONWebKeySet
	getJSON(t, ts.URL+"/jwks", &overlap)
	if len(overlap.Keys) != 2 {
		t.Fatalf("overlap keys = %d", len(overlap.Keys))
	}
	if overlap.Keys[0].KeyID != kid1 {
		t.Fatalf("old key disappeared: %+v", overlap.Keys)
	}

	s.RetireOldKeys()
	var after jose.JSONWebKeySet
	getJSON(t, ts.URL+"/jwks", &after)
	if len(after.Keys) != 1 || after.Keys[0].KeyID == kid1 {
		t.Fatalf("retired keys = %+v", after.Keys)
	}
}

func TestLoginHintSelectsUser(t *testing.T) {
	s, ts := newTestServer(t, Config{
		Users: []User{
			{Sub: "a", Email: "alice@acme.test", PreferredUsername: "alice"},
			{Sub: "b", Email: "bob@contoso.test", PreferredUsername: "bob"},
		},
	})
	if err := s.SetDefaultUser("alice@acme.test"); err != nil {
		t.Fatal(err)
	}

	code, _ := authorize(t, ts.URL, "n1", "")
	tokens := exchange(t, ts.URL, code, "https://broker.test/callback")
	var set jose.JSONWebKeySet
	getJSON(t, ts.URL+"/jwks", &set)
	claims := verify(t, set, tokens["id_token"].(string))
	if claims["email"] != "alice@acme.test" {
		t.Fatalf("default email = %v", claims["email"])
	}

	code, _ = authorize(t, ts.URL, "n2", "bob@contoso.test")
	tokens = exchange(t, ts.URL, code, "https://broker.test/callback")
	claims = verify(t, set, tokens["id_token"].(string))
	if claims["email"] != "bob@contoso.test" {
		t.Fatalf("login_hint email = %v", claims["email"])
	}
}

func authorize(t *testing.T, base, nonce, loginHint string) (string, string) {
	t.Helper()
	q := url.Values{}
	q.Set("client_id", "google-client")
	q.Set("redirect_uri", "https://broker.test/callback")
	q.Set("response_type", "code")
	q.Set("scope", "openid profile email")
	q.Set("state", "state-1")
	q.Set("nonce", nonce)
	if loginHint != "" {
		q.Set("login_hint", loginHint)
	}
	client := &http.Client{CheckRedirect: func(
		*http.Request, []*http.Request,
	) error {
		return http.ErrUseLastResponse
	}}
	resp, err := client.Get(base + "/authorize?" + q.Encode())
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("authorize = %d", resp.StatusCode)
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatal("no code")
	}
	return code, loc.Query().Get("state")
}

func exchange(t *testing.T, base, code, redirect string) map[string]any {
	t.Helper()
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", redirect)
	form.Set("client_id", "google-client")
	form.Set("client_secret", "google-secret")
	form.Set("code_verifier", "verifier")
	resp, err := http.PostForm(base+"/token", form)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("token = %d", resp.StatusCode)
	}
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out
}

func verify(t *testing.T, set jose.JSONWebKeySet, raw string) map[string]any {
	t.Helper()
	jws, err := jose.ParseSigned(raw, []jose.SignatureAlgorithm{jose.EdDSA})
	if err != nil {
		t.Fatal(err)
	}
	kid := jws.Signatures[0].Header.KeyID
	var pub any
	for _, k := range set.Keys {
		if k.KeyID == kid {
			pub = k.Key
		}
	}
	if pub == nil {
		t.Fatalf("kid %q not in jwks", kid)
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

func getJSON(t *testing.T, rawURL string, out any) {
	t.Helper()
	resp, err := http.Get(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s = %d", rawURL, resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		t.Fatal(err)
	}
}

func status(t *testing.T, rawURL string) int {
	t.Helper()
	resp, err := http.Get(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}
