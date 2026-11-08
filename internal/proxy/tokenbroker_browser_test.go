package proxy

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

type tbCapture struct {
	mu     sync.Mutex
	secret string
	user   string
	path   string
}

func (c *tbCapture) snapshot() (secret, user, path string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.secret, c.user, c.path
}

// fakeTokenBroker answers /providers (startup validation) and the
// browser routes, recording the identity headers it received.
func fakeTokenBroker(t *testing.T) (*httptest.Server, *tbCapture) {
	t.Helper()
	cap := &tbCapture{}
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			cap.mu.Lock()
			cap.secret = r.Header.Get("X-Broker-Secret")
			cap.user = r.Header.Get("X-User-Id")
			cap.path = r.URL.Path
			cap.mu.Unlock()
			if r.URL.Path == "/providers" {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(
					`{"providers":[{"name":"github","display_name":"GitHub"}]}`))
				return
			}
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte("<html>services</html>"))
		}))
	t.Cleanup(srv.Close)
	return srv, cap
}

// unauthBridge is a bridge that answers /health but refuses /auth.
func unauthBridge(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/health" {
				w.WriteHeader(http.StatusOK)
				return
			}
			w.WriteHeader(http.StatusUnauthorized)
		}))
	t.Cleanup(srv.Close)
	return srv
}

func browserConfig(t *testing.T, brokerURL, browserHost string) string {
	t.Helper()
	host := ""
	if browserHost != "" {
		host = fmt.Sprintf(`"browserHost": %q,`, browserHost)
	}
	return fmt.Sprintf(`{
		"tokenBroker": {"url": %q, "secretEnv": "DELEGATED_TEST_SECRET", %s
			"links": {"services": {"url": "https://login.test/connections"}}},
		"routes": [{
			"host": "api.test", "path": "/*", "backend": "http://backend",
			"auth": {},
			"upstream": {"tokenBroker": {"provider": "github"}}
		}]
	}`, brokerURL, host)
}

func newBrowserGateway(t *testing.T, brokerURL, bridgeURL, browserHost string) *Gateway {
	t.Helper()
	t.Setenv("DELEGATED_TEST_SECRET", "delegated-secret")
	clearAuthCache()
	t.Cleanup(clearAuthCache)
	cfg := loadForTest(t, browserConfig(t, brokerURL, browserHost))
	gw, err := New(cfg, WithAuthBridgeURL(bridgeURL))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = gw.Close() })
	return gw
}

func TestTokenBrokerBrowserRoute(t *testing.T) {
	cases := []struct {
		path   string
		authed bool
		ok     bool
	}{
		{"/connections", true, true},
		{"/connect/github", true, true},
		{"/connections/github/disconnect", true, true},
		{"/oauth/github/callback", false, true},
		{"/connectionsx", false, false},
		{"/other", false, false},
	}
	for _, c := range cases {
		authed, ok := tokenBrokerBrowserRoute(c.path)
		if ok != c.ok || (ok && authed != c.authed) {
			t.Errorf("route(%q) = (%v,%v), want (%v,%v)",
				c.path, authed, ok, c.authed, c.ok)
		}
	}
}

func TestTokenBrokerBrowserAuthenticated(t *testing.T) {
	broker, cap := fakeTokenBroker(t)
	bridge := delegatedBridge(t)
	gw := newBrowserGateway(t, broker.URL, bridge.URL, "login.test")

	resp := doRequestWithHeaders(t, gw, "login.test", "/connections",
		map[string]string{"Cookie": "access_token=u1"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	secret, user, path := cap.snapshot()
	if secret != "delegated-secret" {
		t.Fatalf("secret = %q", secret)
	}
	if user != "user-1" {
		t.Fatalf("X-User-Id = %q, want user-1", user)
	}
	if path != "/connections" {
		t.Fatalf("path = %q", path)
	}
}

func TestTokenBrokerBrowserOverwritesSpoofedHeaders(t *testing.T) {
	broker, cap := fakeTokenBroker(t)
	bridge := delegatedBridge(t)
	gw := newBrowserGateway(t, broker.URL, bridge.URL, "login.test")

	resp := doRequestWithHeaders(t, gw, "login.test", "/connect/github",
		map[string]string{
			"Cookie":          "access_token=u1",
			"X-Broker-Secret": "evil",
			"X-User-Id":       "evil",
		})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	secret, user, _ := cap.snapshot()
	if secret != "delegated-secret" || user != "user-1" {
		t.Fatalf("spoofed headers survived: secret=%q user=%q", secret, user)
	}
}

func TestTokenBrokerBrowserCallbackIsSessionless(t *testing.T) {
	broker, cap := fakeTokenBroker(t)
	bridge := delegatedBridge(t)
	gw := newBrowserGateway(t, broker.URL, bridge.URL, "login.test")

	// No session cookie: the callback must still be proxied (the token
	// broker's one-shot state binds the user).
	resp := doRequestWithHeaders(t, gw, "login.test",
		"/oauth/github/callback?state=s&code=c", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	secret, user, path := cap.snapshot()
	if secret != "delegated-secret" {
		t.Fatalf("secret = %q", secret)
	}
	if user != "" {
		t.Fatalf("X-User-Id = %q, want empty on the sessionless callback", user)
	}
	if path != "/oauth/github/callback" {
		t.Fatalf("path = %q", path)
	}
}

func TestTokenBrokerBrowserUnauthenticatedRedirects(t *testing.T) {
	broker, _ := fakeTokenBroker(t)
	bridge := unauthBridge(t)
	gw := newBrowserGateway(t, broker.URL, bridge.URL, "login.test")

	req := httptest.NewRequest(http.MethodGet,
		"http://login.test/connections", nil)
	req.Host = "login.test"
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Accept", "text/html")
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	if loc := rec.Header().Get("Location"); !strings.Contains(loc, "returnTo=") {
		t.Fatalf("Location = %q", loc)
	}
}

func TestTokenBrokerBrowserHostDerivedFromLink(t *testing.T) {
	broker, cap := fakeTokenBroker(t)
	bridge := delegatedBridge(t)
	// browserHost empty: it is derived from links.services.url
	// (https://login.test/connections).
	gw := newBrowserGateway(t, broker.URL, bridge.URL, "")

	resp := doRequestWithHeaders(t, gw, "login.test", "/connections",
		map[string]string{"Cookie": "access_token=u1"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	_, user, _ := cap.snapshot()
	if user != "user-1" {
		t.Fatalf("X-User-Id = %q, want user-1 (host derived)", user)
	}
}

func TestTokenBrokerBrowserOtherHostFallsThrough(t *testing.T) {
	broker, _ := fakeTokenBroker(t)
	bridge := delegatedBridge(t)
	gw := newBrowserGateway(t, broker.URL, bridge.URL, "")

	// browserHost is derived from links.services.url (login.test), so
	// the routes are served there; another host must fall through.
	resp := doRequestWithHeaders(t, gw, "other.test", "/connections",
		map[string]string{"Cookie": "access_token=u1"})
	if resp.StatusCode == http.StatusOK {
		t.Fatalf("browser route served on a non-matching host")
	}
}
