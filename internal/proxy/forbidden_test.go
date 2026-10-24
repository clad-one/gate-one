package proxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// identityForbiddenGateway: a frontend route whose identity conditions
// the authenticated user fails (bridge grants offline_access, the
// route requires admin) — every authenticated request is a gateway
// rights refusal. extraAuthGuard is appended inside the route object
// (e.g. a authGuard.forbidden policy).
func identityForbiddenGateway(
	t *testing.T,
	extraRoute string,
) (*Gateway, string) {
	t.Helper()

	bridge := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-User-Id", "u1")
			w.Header().Set("X-Username", "alice")
			w.Header().Set("X-Roles", "offline_access") // not admin
			w.WriteHeader(http.StatusOK)
		},
	))
	t.Cleanup(bridge.Close)

	gw, hosts := testGatewayWithAuthBridge(t, `{
		"routes": [{
			"host": "app.test",
			"path": "/*",
			"frontend": true,
			"backend": "BACKEND",
			"auth": {
				"when": { "method": "GET" },
				"identity": { "roles": ["admin"] }
			}`+extraRoute+`
		}]
	}`, bridge.URL)

	return gw, hosts["app.test"]
}

func doIdentityProbe(
	t *testing.T,
	gw http.Handler,
	host, accept string,
) *http.Response {
	t.Helper()

	req := httptest.NewRequest(http.MethodGet, "http://"+host+"/page", nil)
	req.Host = host
	req.Header.Set("Authorization", "Bearer token")
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)
	return rec.Result()
}

// TestIdentityForbiddenNavigationServesHTML: a browser NAVIGATION
// refused on identity gets a readable HTML page (not the historical
// raw JSON body), still marked with the gateway header.
func TestIdentityForbiddenNavigationServesHTML(t *testing.T) {
	gw, host := identityForbiddenGateway(t, "")

	resp := doIdentityProbe(t, gw, host, "text/html,application/xhtml+xml")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}
	if got := resp.Header.Get(GatewayForbiddenHeader); got != gatewayForbiddenValue {
		t.Errorf("%s = %q, want %q", GatewayForbiddenHeader, got, gatewayForbiddenValue)
	}

	html := body(t, resp)
	if !strings.Contains(html, "Access denied") {
		t.Errorf("forbidden page missing its heading:\n%s", html)
	}
	if strings.Contains(html, `"error":"forbidden"`) {
		t.Error("navigation must serve the HTML page, not the JSON body")
	}
}

// TestIdentityForbiddenFetchIsJSONAndMarked: a fetch()/API client
// (no text/html Accept) keeps the JSON 403, with the gateway marker so
// the injected guard can show its opt-in banner.
func TestIdentityForbiddenFetchIsJSONAndMarked(t *testing.T) {
	gw, host := identityForbiddenGateway(t, "")

	resp := doIdentityProbe(t, gw, host, "application/json")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	if got := resp.Header.Get(GatewayForbiddenHeader); got != gatewayForbiddenValue {
		t.Errorf("%s = %q, want %q", GatewayForbiddenHeader, got, gatewayForbiddenValue)
	}

	b := body(t, resp)
	if !strings.Contains(b, `"error":"forbidden"`) ||
		!strings.Contains(b, "identity conditions not met") {
		t.Errorf("JSON 403 body = %q", b)
	}
}

// TestIdentityForbiddenPageURLRedirect: authGuard.forbidden.pageUrl
// turns the navigation refusal into a 302 toward the operator's page.
func TestIdentityForbiddenPageURLRedirect(t *testing.T) {
	gw, host := identityForbiddenGateway(t,
		`, "authGuard": { "forbidden": { "pageUrl": "https://denied.test/no" } }`)

	resp := doIdentityProbe(t, gw, host, "text/html")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want 302", resp.StatusCode)
	}
	if got := resp.Header.Get("Location"); got != "https://denied.test/no" {
		t.Errorf("Location = %q, want https://denied.test/no", got)
	}
}

// TestIdentityForbiddenCustomMessage: authGuard.forbidden.message
// overrides the built-in page's text (HTML-escaped).
func TestIdentityForbiddenCustomMessage(t *testing.T) {
	gw, host := identityForbiddenGateway(t,
		`, "authGuard": { "forbidden": { "message": "Nope & <stop>" } }`)

	resp := doIdentityProbe(t, gw, host, "text/html")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
	html := body(t, resp)
	if !strings.Contains(html, "Nope &amp; &lt;stop&gt;") {
		t.Errorf("custom message not escaped/served:\n%s", html)
	}
}

// TestBackendForbiddenNotMarked: a 403 coming FROM the backend (here
// it even attempts to forge the marker) must never carry the gateway
// marker — the guard banner must not fire on a backend refusal, and
// the forged header is stripped.
func TestBackendForbiddenNotMarked(t *testing.T) {
	gw, _ := upstreamGateway(t, `{
		"routes": [{
			"host": "public.test", "path": "/*", "frontend": true,
			"backend": "BACKEND"
		}]
	}`)

	resp := doGet(t, gw, "public.test", "/forbidden")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
	if got := resp.Header.Get(GatewayForbiddenHeader); got != "" {
		t.Errorf("%s = %q, want empty (backend marker must be stripped)",
			GatewayForbiddenHeader, got)
	}
	if b := body(t, resp); !strings.Contains(b, "backend_forbidden") {
		t.Errorf("backend 403 body altered: %q", b)
	}
}
