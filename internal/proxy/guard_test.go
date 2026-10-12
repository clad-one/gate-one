package proxy

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cladone/gateway/internal/core"
)

// testGateway builds a Gateway from a routes JSON (same schema as
// api-routes.json) and starts a backend answering htmlBody on /,
// jsBody on /js/app.js and 401 JSON on /api/x. Returns the gateway
// handler plus the host names used by the test routes.
func testGateway(
	t *testing.T,
	routesJSON string,
) (http.Handler, map[string]string) {
	t.Helper()

	htmlBody := `<!DOCTYPE html>
<html>
<head><title>Test</title></head>
<body>hello</body>
</html>`

	backend := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/api/x":
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"error":"authentication_required"}`))
			case "/js/app.js":
				w.Header().Set("Content-Type", "application/javascript")
				_, _ = w.Write([]byte("console.log('app');"))
			case "/missing":
				http.NotFound(w, r)
			default:
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				_, _ = w.Write([]byte(htmlBody))
			}
		},
	))
	t.Cleanup(backend.Close)

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "routes.json")
	routesJSON = strings.ReplaceAll(routesJSON, "BACKEND", backend.URL)
	if err := os.WriteFile(cfgPath, []byte(routesJSON), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := core.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}

	gw, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	hosts := map[string]string{}
	for _, r := range cfg.Routes {
		hosts[r.Host] = r.Host
	}
	return gw, hosts
}

func doGet(
	t *testing.T,
	gw http.Handler,
	host, path string,
) *http.Response {
	t.Helper()

	req := httptest.NewRequest(http.MethodGet, "http://"+host+path, nil)
	req.Host = host
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)
	return rec.Result()
}

func body(t *testing.T, resp *http.Response) string {
	t.Helper()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestGuardInjectedOnFrontendHTML(t *testing.T) {
	gw, _ := testGateway(t, `{
		"routes": [{
			"host": "front.test",
			"path": "/*",
			"frontend": true,
			"backend": "BACKEND"
		}]
	}`)

	resp := doGet(t, gw, "front.test", "/")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	b := body(t, resp)
	if !strings.Contains(b, "__cladoneAuthGuard") {
		t.Error("guard script missing from HTML response")
	}
	if !strings.Contains(
		b,
		"https://login.cladone.com/login",
	) {
		t.Error("guard script does not reference the login page")
	}
	// injected right after <head>
	if !strings.Contains(b, "<head><script>") {
		t.Errorf("script not injected after <head>: %q", b)
	}
	// page content intact
	if !strings.Contains(b, "<body>hello</body>") {
		t.Errorf("page body altered: %q", b)
	}
	// Content-Length matches the new body
	declared := resp.ContentLength
	if declared != int64(len(b)) {
		t.Errorf("Content-Length = %d, body = %d bytes", declared, len(b))
	}
}

func TestGuardNotInjectedOnNonHTML(t *testing.T) {
	gw, _ := testGateway(t, `{
		"routes": [{
			"host": "front.test",
			"path": "/*",
			"frontend": true,
			"backend": "BACKEND"
		}]
	}`)

	resp := doGet(t, gw, "front.test", "/js/app.js")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if b := body(t, resp); strings.Contains(b, "__cladoneAuthGuard") {
		t.Error("guard script injected into a JS asset")
	}
}

func TestGuardOptOut(t *testing.T) {
	gw, _ := testGateway(t, `{
		"routes": [{
			"host": "front.test",
			"path": "/*",
			"frontend": true,
			"backend": "BACKEND",
			"authGuard": { "enabled": false }
		}]
	}`)

	resp := doGet(t, gw, "front.test", "/")
	if b := body(t, resp); strings.Contains(b, "__cladoneAuthGuard") {
		t.Error("guard injected despite authGuard.enabled = false")
	}
}

func TestGuardCustomLoginURL(t *testing.T) {
	gw, _ := testGateway(t, `{
		"routes": [{
			"host": "front.test",
			"path": "/*",
			"frontend": true,
			"backend": "BACKEND",
			"authGuard": { "loginUrl": "https://example.com/login" }
		}]
	}`)

	resp := doGet(t, gw, "front.test", "/")
	if b := body(t, resp); !strings.Contains(
		b,
		"https://example.com/login",
	) {
		t.Error("guard script does not use the configured loginUrl")
	}
}

func TestGuardNotInjectedOnNonFrontendRoute(t *testing.T) {
	gw, _ := testGateway(t, `{
		"routes": [{
			"host": "api.test",
			"path": "/*",
			"backend": "BACKEND"
		}]
	}`)

	resp := doGet(t, gw, "api.test", "/")
	if b := body(t, resp); strings.Contains(b, "__cladoneAuthGuard") {
		t.Error("guard injected on a non-frontend route")
	}
}

func TestAPI401Unchanged(t *testing.T) {
	gw, _ := testGateway(t, `{
		"routes": [{
			"host": "front.test",
			"path": "/*",
			"frontend": true,
			"backend": "BACKEND"
		}]
	}`)

	resp := doGet(t, gw, "front.test", "/api/x")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}

	var payload map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	if payload["error"] != "authentication_required" {
		t.Errorf("error = %v, want authentication_required", payload["error"])
	}
}

func TestHeadFallbackNotInjected(t *testing.T) {
	gw, _ := testGateway(t, `{
		"routes": [{
			"host": "front.test",
			"path": "/*",
			"frontend": true,
			"backend": "BACKEND",
			"headFallback": true
		}]
	}`)

	req := httptest.NewRequest(http.MethodHead, "http://front.test/", nil)
	req.Host = "front.test"
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)
	resp := rec.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if b := body(t, resp); b != "" {
		t.Errorf("HEAD must not return a body, got %q", b)
	}
}

func TestBackendErrorForwardedUnmodified(t *testing.T) {
	// a 404 from the backend must pass through untouched (no guard)
	gw, _ := testGateway(t, `{
		"routes": [{
			"host": "front.test",
			"path": "/*",
			"frontend": true,
			"backend": "BACKEND"
		}]
	}`)

	resp := doGet(t, gw, "front.test", "/missing")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
}

func TestLoginPageURLConstantSharedWithRedirect(t *testing.T) {
	// page-route auth redirect must use the same constant as the guard
	if !strings.HasPrefix(LoginPageURL, "https://") {
		t.Errorf("LoginPageURL = %q, want https URL", LoginPageURL)
	}
	if !strings.HasSuffix(LoginPageURL, "/login") {
		t.Errorf("LoginPageURL = %q, want .../login", LoginPageURL)
	}
	// and must be URL-parseable
	if _, err := url.Parse(LoginPageURL); err != nil {
		t.Errorf("LoginPageURL not parseable: %v", err)
	}
}