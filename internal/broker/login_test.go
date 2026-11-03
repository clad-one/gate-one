package broker

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func newLoginTestBroker(t *testing.T) (*Broker, *tenantRuntime) {
	t.Helper()
	old := pbkdf2Iterations
	pbkdf2Iterations = 1000
	t.Cleanup(func() { pbkdf2Iterations = old })

	b := &Broker{
		cfg: &Config{
			PublicURL:         "https://broker.test",
			SessionCookieName: "broker_sid",
		},
		tenants:  map[string]*tenantRuntime{},
		store:    newMemoryStore(),
		accounts: newMemoryAccounts(),
		now:      time.Now,
		rand:     rand.Reader,
	}
	rt := &tenantRuntime{cfg: Tenant{
		ID:                "mycompany",
		ClientID:          "gate-one",
		RedirectURIs:      []string{"https://login.test/callback"},
		LocalAccounts:     true,
		AppOrigins:        []string{"https://app.test"},
		DefaultRoles:      []string{"user"},
		SessionTTLSeconds: 3600,
	}}
	b.tenants["mycompany"] = rt
	t.Cleanup(func() { _ = b.Close() })
	return b, rt
}

func putTestUser(t *testing.T, b *Broker, email, password string, verified bool) {
	t.Helper()
	hash, err := hashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	u := &localUser{
		ID:            "user-" + email,
		Tenant:        "mycompany",
		Email:         email,
		Name:          "Alice",
		PasswordHash:  hash,
		EmailVerified: verified,
		Roles:         []string{"user"},
		CreatedAt:     time.Now(),
	}
	if err := b.accounts.PutUser(context.Background(), u); err != nil {
		t.Fatal(err)
	}
}

func authorizeURL(challenge, idp string) string {
	return "https://broker.test/t/mycompany/authorize?client_id=gate-one" +
		"&redirect_uri=" + url.QueryEscape("https://login.test/callback") +
		"&response_type=code&state=st&scope=openid" +
		"&code_challenge=" + challenge + "&code_challenge_method=S256" +
		"&idp=" + url.QueryEscape(idp)
}

func formField(t *testing.T, body, name string) string {
	t.Helper()
	marker := `name="` + name + `" value="`
	i := strings.Index(body, marker)
	if i < 0 {
		t.Fatalf("field %q not found in:\n%s", name, body)
	}
	rest := body[i+len(marker):]
	j := strings.Index(rest, `"`)
	if j < 0 {
		t.Fatalf("unterminated field %q", name)
	}
	return rest[:j]
}

func postLogin(
	t *testing.T, b *Broker, flow, csrf, email, password string,
) *httptest.ResponseRecorder {
	t.Helper()
	form := url.Values{
		"flow":     {flow},
		"csrf":     {csrf},
		"email":    {email},
		"password": {password},
	}
	req := httptest.NewRequest(http.MethodPost,
		"https://broker.test/t/mycompany/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	b.Handler().ServeHTTP(rec, req)
	return rec
}

func TestLocalLoginFlow(t *testing.T) {
	b, _ := newLoginTestBroker(t)
	putTestUser(t, b, "alice@app.test", "long-enough-pass", true)

	verifier := "verifier-0123456789-0123456789-0123456789-0123456789"
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	// authorize?idp=local -> broker login page
	rec := httptest.NewRecorder()
	b.Handler().ServeHTTP(rec, httptest.NewRequest(
		http.MethodGet, authorizeURL(challenge, "local"), nil))
	if rec.Code != http.StatusFound {
		t.Fatalf("authorize = %d: %s", rec.Code, rec.Body.String())
	}
	loginLoc := rec.Header().Get("Location")
	if !strings.HasPrefix(loginLoc, "https://broker.test/t/mycompany/login?flow=") {
		t.Fatalf("authorize redirect = %q", loginLoc)
	}

	// login page exposes flow + CSRF
	rec = httptest.NewRecorder()
	b.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, loginLoc, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("login page = %d", rec.Code)
	}
	page := rec.Body.String()
	flow := formField(t, page, "flow")
	csrf := formField(t, page, "csrf")
	if flow == "" || csrf == "" {
		t.Fatal("missing flow/csrf")
	}

	// wrong password: generic 401, the flow stays usable
	rec = postLogin(t, b, flow, csrf, "alice@app.test", "wrong-password")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong password = %d, want 401", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Identifiants invalides") {
		t.Fatalf("unexpected error page: %s", rec.Body.String())
	}

	// correct password: code issued for the RP callback
	rec = postLogin(t, b, flow, csrf, "alice@app.test", "long-enough-pass")
	if rec.Code != http.StatusFound {
		t.Fatalf("login = %d: %s", rec.Code, rec.Body.String())
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if loc.Host != "login.test" || loc.Path != "/callback" {
		t.Fatalf("callback = %s", loc)
	}
	if loc.Query().Get("state") != "st" {
		t.Fatalf("state lost: %s", loc)
	}
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatal("no code")
	}
	c, err := b.store.TakeCode(context.Background(), "mycompany", code)
	if err != nil || c == nil {
		t.Fatalf("code store: %v %v", c, err)
	}
	if c.Email != "alice@app.test" || c.Subject == "" {
		t.Fatalf("code identity = %+v", c)
	}
	if len(c.Roles) != 1 || c.Roles[0] != "user" {
		t.Fatalf("code roles = %v", c.Roles)
	}
	if c.SID == "" {
		t.Fatal("code has no sid")
	}
	if c.CodeChallenge != challenge {
		t.Fatal("PKCE challenge not carried to the code")
	}
}

func TestLocalLoginRejectsUnverifiedAndBadCSRF(t *testing.T) {
	b, _ := newLoginTestBroker(t)
	putTestUser(t, b, "bob@app.test", "long-enough-pass", false)

	rec := httptest.NewRecorder()
	b.Handler().ServeHTTP(rec, httptest.NewRequest(
		http.MethodGet, authorizeURL("challenge", "local"), nil))
	loginLoc := rec.Header().Get("Location")

	rec = httptest.NewRecorder()
	b.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, loginLoc, nil))
	page := rec.Body.String()
	flow := formField(t, page, "flow")
	csrf := formField(t, page, "csrf")

	// Unverified account: same generic refusal as a bad password.
	rec = postLogin(t, b, flow, csrf, "bob@app.test", "long-enough-pass")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unverified login = %d, want 401", rec.Code)
	}

	// Bad CSRF: refused, flow re-issued.
	rec = postLogin(t, b, flow, "wrong-csrf", "bob@app.test", "long-enough-pass")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad csrf = %d, want 400", rec.Code)
	}
}

func TestLocalLoginDisabled(t *testing.T) {
	b, rt := newLoginTestBroker(t)
	rt.cfg.LocalAccounts = false
	rec := httptest.NewRecorder()
	b.Handler().ServeHTTP(rec, httptest.NewRequest(
		http.MethodGet, authorizeURL("challenge", "local"), nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("disabled local login = %d, want 400", rec.Code)
	}
}

func TestLocalLoginUnknownFlow(t *testing.T) {
	b, _ := newLoginTestBroker(t)
	rec := httptest.NewRecorder()
	b.Handler().ServeHTTP(rec, httptest.NewRequest(
		http.MethodGet, "https://broker.test/t/mycompany/login?flow=unknown", nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown flow = %d, want 400", rec.Code)
	}
}

func TestIdPChooser(t *testing.T) {
	b, rt := newLoginTestBroker(t)
	rt.cfg.Upstreams = map[string]GoogleConfig{
		"google":    {DisplayName: "Google"},
		"microsoft": {DisplayName: "Microsoft"},
	}
	rt.adapterOrder = []string{"google", "microsoft"}

	rec := httptest.NewRecorder()
	b.Handler().ServeHTTP(rec, httptest.NewRequest(
		http.MethodGet, authorizeURL("challenge", ""), nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("chooser = %d: %s", rec.Code, rec.Body.String())
	}
	page := rec.Body.String()
	for _, want := range []string{
		"Choisissez votre méthode",
		"Compte local (e-mail / mot de passe)",
		"Google",
		"Microsoft",
		"idp=local", "idp=google", "idp=microsoft",
	} {
		if !strings.Contains(page, want) {
			t.Fatalf("chooser missing %q:\n%s", want, page)
		}
	}
}

func TestIdPUnknownRejected(t *testing.T) {
	b, rt := newLoginTestBroker(t)
	rt.cfg.Upstreams = map[string]GoogleConfig{"google": {DisplayName: "Google"}}
	rt.adapterOrder = []string{"google"}

	rec := httptest.NewRecorder()
	b.Handler().ServeHTTP(rec, httptest.NewRequest(
		http.MethodGet, authorizeURL("challenge", "unknown"), nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown idp = %d, want 400", rec.Code)
	}
}
