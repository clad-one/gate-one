package iam

import (
	"context"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func newLogoutTestBroker(t *testing.T) *IAM {
	t.Helper()
	b := &IAM{
		cfg: &Config{
			PublicURL:         "https://iam.test",
			SessionCookieName: "iam_sid",
		},
		tenants:  map[string]*tenantRuntime{},
		store:    newMemoryStore(),
		accounts: newMemoryAccounts(),
		now:      time.Now,
		rand:     rand.Reader,
	}
	rt := &tenantRuntime{cfg: Tenant{
		ID:                     "mycompany",
		PostLogoutRedirectURIs: []string{"https://app.test/*"},
		AppOrigins:             []string{"https://app.test/"},
	}}
	b.tenants["mycompany"] = rt
	t.Cleanup(func() { _ = b.Close() })
	return b
}

func doLogout(t *testing.T, b *IAM, browserID string) *httptest.ResponseRecorder {
	t.Helper()
	target := "https://iam.test/t/mycompany/logout?post_logout_redirect_uri=" +
		url.QueryEscape("https://app.test/")
	req := httptest.NewRequest(http.MethodGet, target, nil)
	if browserID != "" {
		req.AddCookie(&http.Cookie{Name: "iam_sid", Value: browserID})
	}
	rec := httptest.NewRecorder()
	b.Handler().ServeHTTP(rec, req)
	return rec
}

func TestLogoutUpstreamRPInitiated(t *testing.T) {
	b := newLogoutTestBroker(t)
	ctx := context.Background()
	const bid = "browser-1"
	if err := b.store.PutUpstream(ctx, "mycompany", bid, &upstreamSession{
		AdapterID:  "auth0",
		IDToken:    "upstream-id-token",
		EndSession: "https://idp.test/oidc/logout",
		ClientID:   "upstream-client",
	}, time.Hour); err != nil {
		t.Fatal(err)
	}

	rec := doLogout(t, b, bid)
	if rec.Code != http.StatusFound {
		t.Fatalf("logout = %d: %s", rec.Code, rec.Body.String())
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if loc.Scheme != "https" || loc.Host != "idp.test" ||
		loc.Path != "/oidc/logout" {
		t.Fatalf("upstream logout = %s", loc)
	}
	q := loc.Query()
	if q.Get("id_token_hint") != "upstream-id-token" {
		t.Fatalf("id_token_hint = %q", q.Get("id_token_hint"))
	}
	if q.Get("client_id") != "upstream-client" {
		t.Fatalf("client_id = %q", q.Get("client_id"))
	}
	if q.Get("post_logout_redirect_uri") !=
		"https://iam.test/t/mycompany/logout/done" {
		t.Fatalf("post_logout_redirect_uri = %q",
			q.Get("post_logout_redirect_uri"))
	}

	// The app target rides in the short-lived cookie; /logout/done
	// validates it and redirects.
	var logoutCookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == "iam_logout_to" {
			logoutCookie = c
		}
	}
	if logoutCookie == nil || logoutCookie.Value == "" {
		t.Fatal("iam_logout_to cookie missing")
	}
	req := httptest.NewRequest(http.MethodGet,
		"https://iam.test/t/mycompany/logout/done", nil)
	req.AddCookie(logoutCookie)
	done := httptest.NewRecorder()
	b.Handler().ServeHTTP(done, req)
	if done.Code != http.StatusFound {
		t.Fatalf("logout/done = %d", done.Code)
	}
	if got := done.Header().Get("Location"); got != "https://app.test/" {
		t.Fatalf("logout/done redirect = %q", got)
	}

	if up, err := b.store.GetUpstream(ctx, "mycompany", bid); err != nil || up != nil {
		t.Fatalf("upstream session not deleted: %+v %v", up, err)
	}
}

func TestLogoutWithoutUpstreamEndSessionFallsBack(t *testing.T) {
	b := newLogoutTestBroker(t)
	ctx := context.Background()
	const bid = "browser-2"
	if err := b.store.PutUpstream(ctx, "mycompany", bid, &upstreamSession{
		AdapterID: "google",
		IDToken:   "google-token",
	}, time.Hour); err != nil {
		t.Fatal(err)
	}

	rec := doLogout(t, b, bid)
	if rec.Code != http.StatusFound {
		t.Fatalf("logout = %d", rec.Code)
	}
	if got := rec.Header().Get("Location"); got != "https://app.test/" {
		t.Fatalf("fallback redirect = %q", got)
	}
}

func TestLogoutWithoutUpstreamSession(t *testing.T) {
	b := newLogoutTestBroker(t)
	rec := doLogout(t, b, "")
	if rec.Code != http.StatusFound {
		t.Fatalf("logout = %d", rec.Code)
	}
	if got := rec.Header().Get("Location"); got != "https://app.test/" {
		t.Fatalf("redirect = %q", got)
	}
}
