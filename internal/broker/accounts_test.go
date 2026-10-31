package broker

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestPasswordHashRoundTrip(t *testing.T) {
	old := pbkdf2Iterations
	pbkdf2Iterations = 1000
	t.Cleanup(func() { pbkdf2Iterations = old })

	hash, err := hashPassword("correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if !verifyPassword(hash, "correct horse battery") {
		t.Fatal("valid password rejected")
	}
	if verifyPassword(hash, "wrong password") {
		t.Fatal("wrong password accepted")
	}
	if verifyPassword("garbage", "correct horse battery") {
		t.Fatal("malformed hash accepted")
	}
}

func TestVerifyTokenSingleUse(t *testing.T) {
	raw, hash, err := newVerifyToken()
	if err != nil {
		t.Fatal(err)
	}
	if raw == "" || hash == "" || raw == hash {
		t.Fatalf("bad token pair: raw=%q hash=%q", raw, hash)
	}
	store := newMemoryAccounts()
	ctx := context.Background()
	if err := store.PutVerifyToken(ctx, "acme", hash, &verifyToken{
		Email:   "a@b.test",
		Expires: time.Now().Add(time.Minute),
	}, time.Minute); err != nil {
		t.Fatal(err)
	}
	if _, err := store.TakeVerifyToken(ctx, "acme", hash); err != nil {
		t.Fatal(err)
	}
	if _, err := store.TakeVerifyToken(ctx, "acme", hash); err == nil {
		t.Fatal("token replayed")
	}
}

func TestContinueURLAllowed(t *testing.T) {
	rt := &tenantRuntime{cfg: Tenant{
		AppOrigins: []string{"https://app.test", "https://vers.test"},
	}}
	for _, ok := range []string{
		"https://app.test/",
		"https://app.test/verify?x=1",
		"https://vers.test/path",
	} {
		if !rt.continueURLAllowed(ok) {
			t.Errorf("%q rejected", ok)
		}
	}
	for _, bad := range []string{
		"", "http://app.test.evil/", "https://evil.test/",
		"//app.test/", "https://app.test@evil.test/",
	} {
		if rt.continueURLAllowed(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
}

type fakeMailer struct {
	to, link string
	err      error
}

func (f *fakeMailer) SendVerification(_ context.Context, to, link string) error {
	f.to, f.link = to, link
	return f.err
}

func newAccountsTestBroker(t *testing.T) (*Broker, *tenantRuntime, *fakeMailer) {
	t.Helper()
	old := pbkdf2Iterations
	pbkdf2Iterations = 1000
	t.Cleanup(func() { pbkdf2Iterations = old })

	mail := &fakeMailer{}
	b := &Broker{
		cfg:      &Config{PublicURL: "https://broker.test"},
		tenants:  map[string]*tenantRuntime{},
		accounts: newMemoryAccounts(),
		mailer:   mail,
		now:      time.Now,
		rand:     rand.Reader,
	}
	rt := &tenantRuntime{cfg: Tenant{
		ID:                    "acme",
		LocalAccounts:         true,
		AppOrigins:            []string{"https://app.test"},
		RegistrationSecret:    "s3cret",
		DefaultRoles:          []string{"user"},
		RegistrationSecretEnv: "X",
	}}
	b.tenants["acme"] = rt
	t.Cleanup(func() { _ = b.Close() })
	return b, rt, mail
}

func doJSON(
	t *testing.T, b *Broker, method, target, secret string, body string,
) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if secret != "" {
		req.Header.Set("Authorization", "Bearer "+secret)
	}
	rec := httptest.NewRecorder()
	b.Handler().ServeHTTP(rec, req)
	return rec
}

func TestRegisterThenVerifyReturnsToApp(t *testing.T) {
	b, rt, mail := newAccountsTestBroker(t)

	rec := doJSON(t, b, http.MethodPost,
		"https://broker.test/t/acme/register", "s3cret",
		`{"email":"Alice@App.test","password":"long-enough-pass",
		  "name":"Alice","continueUrl":"https://app.test/"}`)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("register = %d: %s", rec.Code, rec.Body.String())
	}
	if mail.to != "alice@app.test" {
		t.Fatalf("email sent to %q", mail.to)
	}
	if !strings.HasPrefix(mail.link, "https://broker.test/t/acme/verify-email?") {
		t.Fatalf("link = %q", mail.link)
	}

	// The account exists, unverified, with the default role.
	u, err := b.accounts.GetUserByEmail(
		context.Background(), "acme", "alice@app.test")
	if err != nil {
		t.Fatal(err)
	}
	if u.EmailVerified {
		t.Fatal("account verified before the link")
	}
	if len(u.Roles) != 1 || u.Roles[0] != "user" {
		t.Fatalf("roles = %v", u.Roles)
	}

	// Click the link: verified + redirect to the app.
	req := httptest.NewRequest(http.MethodGet, mail.link, nil)
	rec = httptest.NewRecorder()
	b.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("verify = %d: %s", rec.Code, rec.Body.String())
	}
	if loc := rec.Header().Get("Location"); loc != "https://app.test/?verified=1" {
		t.Fatalf("verify redirect = %q", loc)
	}
	u, err = b.accounts.GetUserByEmail(
		context.Background(), "acme", "alice@app.test")
	if err != nil {
		t.Fatal(err)
	}
	if !u.EmailVerified {
		t.Fatal("account not verified")
	}

	// Replay: the token is single-use.
	req = httptest.NewRequest(http.MethodGet, mail.link, nil)
	rec = httptest.NewRecorder()
	b.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("replayed token = %d, want 400", rec.Code)
	}

	// A verified account cannot be registered again.
	rec = doJSON(t, b, http.MethodPost,
		"https://broker.test/t/acme/register", "s3cret",
		`{"email":"alice@app.test","password":"long-enough-pass",
		  "continueUrl":"https://app.test/"}`)
	if rec.Code != http.StatusConflict {
		t.Fatalf("duplicate register = %d, want 409", rec.Code)
	}

	// The registration secret is enforced.
	rec = doJSON(t, b, http.MethodPost,
		"https://broker.test/t/acme/register", "wrong",
		`{"email":"bob@app.test","password":"long-enough-pass",
		  "continueUrl":"https://app.test/"}`)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("bad secret = %d, want 401", rec.Code)
	}

	// continueUrl outside the tenant allowlist is refused.
	rec = doJSON(t, b, http.MethodPost,
		"https://broker.test/t/acme/register", "s3cret",
		`{"email":"bob@app.test","password":"long-enough-pass",
		  "continueUrl":"https://evil.test/"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad continueUrl = %d, want 400", rec.Code)
	}

	// Local accounts disabled on another tenant.
	rt.cfg.LocalAccounts = false
	rec = doJSON(t, b, http.MethodPost,
		"https://broker.test/t/acme/register", "s3cret", `{}`)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("disabled register = %d, want 404", rec.Code)
	}
}

func TestRegisterValidation(t *testing.T) {
	b, _, _ := newAccountsTestBroker(t)
	cases := []struct {
		name string
		body string
	}{
		{"short password", `{"email":"a@app.test","password":"short","continueUrl":"https://app.test/"}`},
		{"bad email", `{"email":"not-an-email","password":"long-enough-pass","continueUrl":"https://app.test/"}`},
		{"missing continueUrl", `{"email":"a@app.test","password":"long-enough-pass"}`},
		{"invalid json", `{`},
	}
	for _, c := range cases {
		rec := doJSON(t, b, http.MethodPost,
			"https://broker.test/t/acme/register", "s3cret", c.body)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s = %d, want 400", c.name, rec.Code)
		}
	}
}

func TestRegisterMailerFailure(t *testing.T) {
	b, _, mail := newAccountsTestBroker(t)
	mail.err = context.DeadlineExceeded
	rec := doJSON(t, b, http.MethodPost,
		"https://broker.test/t/acme/register", "s3cret",
		`{"email":"a@app.test","password":"long-enough-pass",
		  "continueUrl":"https://app.test/"}`)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("mailer failure = %d, want 502", rec.Code)
	}
	var body map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body["error"] == "" {
		t.Fatalf("no error in body: %s", rec.Body.String())
	}
}
