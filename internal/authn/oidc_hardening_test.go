package authn

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestAC_AUTH_SidRevocationIsTimestamped covers the fix for a locked-out
// re-login: an IdP that reuses the same sid after an RP-initiated
// logout must not keep the user out forever.
func TestAC_AUTH_SidRevocationIsTimestamped(t *testing.T) {
	ctx := context.Background()
	const iss = "https://issuer.test"

	for _, tc := range []struct {
		name  string
		store RevocationStore
	}{
		{"memory", NewMemoryStore()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := tc.store
			defer s.Close()
			before := time.Now().Add(-time.Minute)
			if err := s.Revoke(ctx, iss, "sid-x", "", time.Now().Add(time.Hour)); err != nil {
				t.Fatal(err)
			}
			if r, _ := s.CheckRevoked(ctx, iss, "sid-x", "", before); !r {
				t.Fatal("old session on revoked sid not revoked")
			}
			if r, _ := s.CheckRevoked(
				ctx, iss, "sid-x", "", time.Now().Add(time.Minute)); r {
				t.Fatal("new session on reused sid wrongly revoked")
			}
		})
	}
}

// TestOIDCConcurrentFlowsKeepSeparateTxCookies is the D regression:
// two /login flows in one browser must not overwrite each other's
// transaction cookie (the losing callback landed on "session expired").
func TestOIDCConcurrentFlowsKeepSeparateTxCookies(t *testing.T) {
	m := newMockOIDC(t)
	now := time.Now()
	o := newTestOIDC(t, m, &now)

	names := map[string]bool{}
	for i := 0; i < 2; i++ {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet,
			"http://login.test:3000/login?returnTo=http://app.test/", nil)
		o.ServeLogin(rec, req)
		var tx *http.Cookie
		for _, c := range rec.Result().Cookies() {
			if strings.HasPrefix(c.Name, oidcTxCookie+"_") {
				tx = c
			}
		}
		if tx == nil {
			t.Fatalf("flow %d: per-flow tx cookie missing", i)
		}
		names[tx.Name] = true
	}
	if len(names) != 2 {
		t.Fatalf("two flows shared a tx cookie name: %v", names)
	}
}

// TestOIDCTxExpiredKeepsReturnTo is the C regression: with the
// transaction gone, the recovery page still points back at the app.
func TestOIDCTxExpiredKeepsReturnTo(t *testing.T) {
	m := newMockOIDC(t)
	now := time.Now()
	o := newTestOIDC(t, m, &now)

	// A /login sets the returnTo cookie.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet,
		"http://login.test:3000/login?returnTo=http://app.test/page", nil)
	o.ServeLogin(rec, req)
	rt := findCookie(rec, oidcRtCookie)
	if rt == nil {
		t.Fatal("returnTo cookie missing at /login")
	}

	// A callback with no transaction cookie but the returnTo cookie.
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet,
		"http://login.test:3000/auth/callback?state=deadbeef", nil)
	req.AddCookie(rt)
	o.ServeLogin(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expired callback = %d, want 400", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "returnTo=") ||
		!strings.Contains(body, "app.test") {
		t.Fatalf("expired page lost the return target:\n%s", body)
	}
}
