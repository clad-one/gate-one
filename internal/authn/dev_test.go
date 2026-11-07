package authn

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func newTestDev(t *testing.T) *Dev {
	t.Helper()
	d, err := NewDev(DevConfig{
		LoginBaseURL: "http://login.demo.localhost:3000",
		CookieDomain: "demo.localhost",
		AllowedHosts: []string{"app.demo.localhost", "app2.demo.localhost"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func csrfFrom(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	for _, c := range rec.Result().Cookies() {
		if c.Name == devCSRFCookie {
			return c.Value
		}
	}
	t.Fatal("csrf cookie not set")
	return ""
}

func sessionFrom(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	for _, c := range rec.Result().Cookies() {
		if c.Name == devSessionCookie {
			return c.Value
		}
	}
	t.Fatal("session cookie not set")
	return ""
}

func TestDevLoginFormAndSession(t *testing.T) {
	d := newTestDev(t)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(
		http.MethodGet,
		"http://login.demo.localhost:3000/login?returnTo=http://app.demo.localhost/",
		nil,
	)
	d.ServeLogin(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /login = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Development sign-in") {
		t.Errorf("login page missing its title: %s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "alice") ||
		!strings.Contains(rec.Body.String(), "bob") {
		t.Error("login page does not advertise the demo accounts")
	}

	csrf := csrfFrom(t, rec)
	form := url.Values{
		"username": {"bob"},
		"password": {"bob"},
		"csrf":     {csrf},
		"returnTo": {"http://app.demo.localhost/"},
	}
	req = httptest.NewRequest(
		http.MethodPost, "http://login.demo.localhost:3000/login",
		strings.NewReader(form.Encode()),
	)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: devCSRFCookie, Value: csrf})
	rec = httptest.NewRecorder()
	d.ServeLogin(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("POST /login = %d, want 302: %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Location"); got != "http://app.demo.localhost/" {
		t.Errorf("redirect = %q, want the returnTo", got)
	}
	session := sessionFrom(t, rec)

	// The session authenticates a request on an application host.
	req = httptest.NewRequest(http.MethodGet, "http://app.demo.localhost/", nil)
	req.AddCookie(&http.Cookie{Name: devSessionCookie, Value: session})
	res, err := d.Verify(context.Background(), req)
	if err != nil {
		t.Fatalf("Verify(session) = %v", err)
	}
	if res.Username != "bob" || res.Email != "bob@example.com" {
		t.Errorf("identity = %+v, want bob", res.Identity)
	}
	if !contains(res.Roles, "admin") {
		t.Errorf("roles = %v, want admin", res.Roles)
	}
	if !contains(res.Scopes, "mcp-tools") {
		t.Errorf("scopes = %v, want mcp-tools", res.Scopes)
	}
	if res.Claims["preferred_username"] != "bob" {
		t.Errorf("claims = %v, want preferred_username=bob", res.Claims)
	}
}

func TestDevRejectsBadPasswordAndCSRF(t *testing.T) {
	d := newTestDev(t)

	login := func(password, csrf string, withCookie bool) *httptest.ResponseRecorder {
		form := url.Values{
			"username": {"bob"}, "password": {password},
			"csrf": {csrf}, "returnTo": {"/"},
		}
		req := httptest.NewRequest(
			http.MethodPost, "http://login.demo.localhost:3000/login",
			strings.NewReader(form.Encode()),
		)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if withCookie {
			req.AddCookie(&http.Cookie{Name: devCSRFCookie, Value: "token"})
		}
		rec := httptest.NewRecorder()
		d.ServeLogin(rec, req)
		return rec
	}

	if rec := login("nope", "token", true); rec.Code != http.StatusUnauthorized {
		t.Errorf("bad password = %d, want 401", rec.Code)
	}
	if rec := login("bob", "token", false); rec.Code != http.StatusForbidden {
		t.Errorf("missing csrf cookie = %d, want 403", rec.Code)
	}
	if rec := login("bob", "wrong", true); rec.Code != http.StatusForbidden {
		t.Errorf("wrong csrf = %d, want 403", rec.Code)
	}
}

func TestDevMCPTokenAndScope(t *testing.T) {
	d := newTestDev(t)

	req := httptest.NewRequest(http.MethodPost, "http://mcp.demo.localhost/mcp", nil)
	req.Header.Set("Authorization", "Bearer dev-bob")
	res, err := d.VerifyMCP(context.Background(), req, "mcp-tools", "")
	if err != nil {
		t.Fatalf("VerifyMCP(dev-bob) = %v", err)
	}
	if res.Username != "bob" {
		t.Errorf("user = %q, want bob", res.Username)
	}

	req.Header.Set("Authorization", "Bearer dev-alice")
	if _, err := d.VerifyMCP(
		context.Background(), req, "mcp-admin", "",
	); !errors.Is(err, ErrInsufficientScope) {
		t.Errorf("alice + mcp-admin = %v, want ErrInsufficientScope", err)
	}

	req.Header.Set("Authorization", "Bearer nope")
	if _, err := d.VerifyMCP(
		context.Background(), req, "mcp-tools", "",
	); !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("bad token = %v, want ErrUnauthenticated", err)
	}
}

func TestDevLogoutAndPopupDone(t *testing.T) {
	d := newTestDev(t)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(
		http.MethodGet,
		"http://login.demo.localhost:3000/logout?returnTo=/",
		nil,
	)
	d.ServeLogin(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("logout = %d, want 302", rec.Code)
	}
	var cleared bool
	for _, c := range rec.Result().Cookies() {
		if c.Name == devSessionCookie && c.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Error("logout did not clear the session cookie")
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(
		http.MethodGet,
		"http://login.demo.localhost:3000/auth/popup-done?origin=http://app.demo.localhost",
		nil,
	)
	d.ServeLogin(rec, req)
	body := rec.Body.String()
	if !strings.Contains(body, "postMessage") ||
		!strings.Contains(body, "app.demo.localhost") {
		t.Errorf("popup-done page incomplete: %s", body)
	}
}

func TestDevSafeReturnTo(t *testing.T) {
	d := newTestDev(t)
	cases := map[string]string{
		"":                               "/",
		"http://app.demo.localhost/page": "http://app.demo.localhost/page",
		"http://app2.demo.localhost/":    "http://app2.demo.localhost/",
		"http://evil.example/":           "/",
		"//evil.example/":                "/",
		"javascript:alert(1)":            "/",
		"/local/path":                    "/local/path",
	}
	for in, want := range cases {
		if got := d.safeReturnTo(in); got != want {
			t.Errorf("safeReturnTo(%q) = %q, want %q", in, got, want)
		}
	}
}
