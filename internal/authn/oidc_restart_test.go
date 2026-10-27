package authn

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

func newOIDCWithStore(
	t *testing.T,
	m *mockOIDC,
	now *time.Time,
	store RevocationStore,
) *OIDC {
	t.Helper()
	o, err := NewOIDC(context.Background(), OIDCConfig{
		Issuer:       m.srv.URL,
		ClientID:     "gate-one",
		ClientSecret: "secret",
		LoginBaseURL: "http://login.test:3000",
		CookieDomain: "test",
		AllowedHosts: []string{"app.test"},
		RedirectURL:  "http://login.test:3000/auth/callback",
		HTTPClient:   m.srv.Client(),
		SessionTTL:   time.Hour,
		Store:        store,
		Now:          func() time.Time { return *now },
	})
	if err != nil {
		t.Fatal(err)
	}
	return o
}

// A bbolt restart must keep both the session and the revocations: this
// is the regression that auth-bridge's in-memory sid list had.
func TestOIDCRestartPersistence(t *testing.T) {
	m := newMockOIDC(t)
	now := time.Now()
	path := filepath.Join(t.TempDir(), "state.db")

	store, err := OpenBoltStore(path, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	o := newOIDCWithStore(t, m, &now, store)
	session := performLogin(t, m, o)

	// Session works before the restart.
	req := httptest.NewRequest(http.MethodGet, "http://app.test/", nil)
	req.AddCookie(session)
	if _, err := o.Verify(context.Background(), req); err != nil {
		t.Fatalf("Verify before restart = %v", err)
	}

	// Restart: close the file and reopen it with a new provider.
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store2, err := OpenBoltStore(path, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store2.Close() })
	o2 := newOIDCWithStore(t, m, &now, store2)

	// The session survives the restart (same persisted key/store id).
	if _, err := o2.Verify(context.Background(), req); err != nil {
		t.Fatalf("Verify after restart = %v", err)
	}

	// Revoke it, then restart again: the revocation must persist.
	token := m.logoutToken("sid-123", "user-123", "jti-persist", now)
	rec := backchannelRequest(t, o2, token)
	if rec.Code != http.StatusOK {
		t.Fatalf("backchannel = %d: %s", rec.Code, rec.Body.String())
	}
	if _, err := o2.Verify(context.Background(), req); !errors.Is(
		err, ErrUnauthenticated,
	) {
		t.Fatalf("Verify after logout = %v, want ErrUnauthenticated", err)
	}

	if err := store2.Close(); err != nil {
		t.Fatal(err)
	}
	store3, err := OpenBoltStore(path, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store3.Close() })
	o3 := newOIDCWithStore(t, m, &now, store3)

	if _, err := o3.Verify(
		context.Background(), req,
	); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("Verify after second restart = %v, want ErrUnauthenticated", err)
	}
}
