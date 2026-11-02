package authn

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

var errAuditFull = errors.New("audit full")

func TestOIDCLoginLogoutEmitAuthEvents(t *testing.T) {
	m := newMockOIDC(t)
	now := time.Now()
	var mu sync.Mutex
	var events []AuthEvent
	o := newTestOIDCWith(t, m, &now, func(cfg *OIDCConfig) {
		cfg.EventSink = func(ev AuthEvent) error {
			mu.Lock()
			events = append(events, ev)
			mu.Unlock()
			return nil
		}
	})
	snapshot := func() []AuthEvent {
		mu.Lock()
		defer mu.Unlock()
		return append([]AuthEvent(nil), events...)
	}

	session := performLogin(t, m, o)
	login := snapshot()
	if len(login) != 1 || login[0].Action != "login" ||
		login[0].Result != "ok" {
		t.Fatalf("login events = %+v", login)
	}
	if login[0].UserID == "" || login[0].SessionID == "" {
		t.Fatalf("login identity = %+v", login[0])
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(
		http.MethodGet, "http://login.test:3000/logout", nil)
	req.AddCookie(session)
	o.ServeLogin(rec, req)

	all := snapshot()
	if len(all) != 2 {
		t.Fatalf("events = %+v, want login+logout", all)
	}
	logout := all[1]
	if logout.Action != "logout" || logout.Result != "ok" {
		t.Fatalf("logout event = %+v", logout)
	}
	if logout.UserID != login[0].UserID ||
		logout.SessionID != login[0].SessionID {
		t.Fatalf("logout identity = %+v", logout)
	}
}

func TestOIDCLoginAuditFailClosed(t *testing.T) {
	m := newMockOIDC(t)
	now := time.Now()
	o := newTestOIDCWith(t, m, &now, func(cfg *OIDCConfig) {
		cfg.EventSink = func(AuthEvent) error {
			return errAuditFull
		}
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(
		http.MethodGet,
		"http://login.test:3000/login?returnTo=http://app.test/", nil)
	o.ServeLogin(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("login = %d", rec.Code)
	}
	tx := findCookie(rec, oidcTxCookie)
	// Follow the mock IdP authorize and replay the callback.
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
	cb := httptest.NewRequest(http.MethodGet, resp.Header.Get("Location"), nil)
	cb.AddCookie(tx)
	rec2 := httptest.NewRecorder()
	o.ServeLogin(rec2, cb)
	if rec2.Code != http.StatusServiceUnavailable {
		t.Fatalf("callback = %d, want 503 (no session without audit)",
			rec2.Code)
	}
	if findCookie(rec2, oidcSessionCookie) != nil {
		t.Fatal("session created despite audit failure")
	}
}
