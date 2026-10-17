package proxy

import (
	"encoding/base64"
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
// plus the host names used by the test routes.
func testGateway(
	t *testing.T,
	routesJSON string,
) (*Gateway, map[string]string) {
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
			"autoHead": true
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

// testGatewayWithAuthBridge is testGateway with the Gateway pointed
// at a mock auth-bridge base URL (checkAuth target).
func testGatewayWithAuthBridge(
	t *testing.T,
	routesJSON string,
	authBridgeURL string,
) (*Gateway, map[string]string) {
	t.Helper()

	gw, hosts := testGateway(t, routesJSON)
	gw.authBridgeBaseURL = authBridgeURL
	return gw, hosts
}

func TestAuthStateEndpointAuthenticated(t *testing.T) {
	// mock auth-bridge: accepts any token, exposes roles/scopes/claims
	bridge := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-User-Id", "u1")
			w.Header().Set("X-Username", "alice")
			w.Header().Set("X-Roles", "offline_access")
			w.Header().Set("X-Scopes", "openid,profile")
			w.Header().Set("X-Claims", base64.StdEncoding.EncodeToString(
				[]byte(`{"email":"a@b.c","email_verified":false}`)))
			w.WriteHeader(http.StatusOK)
		},
	))
	t.Cleanup(bridge.Close)

	gw, hosts := testGatewayWithAuthBridge(t, `{
		"routes": [{
			"host": "front.test",
			"path": "/*",
			"frontend": true,
			"backend": "BACKEND"
		}]
	}`, bridge.URL)
	host := hosts["front.test"]

	resp := doGet(t, gw, host, "/__gateway/auth")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	var payload struct {
		Roles  []string       `json:"roles"`
		Scopes []string       `json:"scopes"`
		Claims map[string]any `json:"claims"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("JSON invalide: %v", err)
	}
	if !contains(payload.Roles, "offline_access") {
		t.Errorf("roles = %v, want offline_access", payload.Roles)
	}
	if !contains(payload.Scopes, "profile") {
		t.Errorf("scopes = %v, want profile", payload.Scopes)
	}
	if payload.Claims["email"] != "a@b.c" || payload.Claims["email_verified"] != false {
		t.Errorf("claims = %v", payload.Claims)
	}
}

func contains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

// TestWhenIdentityConditions vérifie le modèle deux-étapes : les
// conditions d'identité (roles/scopes/claims) sont évaluées APRÈS
// authentification — anonyme → 401, authentifié insuffisant → 403,
// authentifié conforme → proxifié (200).
func TestWhenIdentityConditions(t *testing.T) {
	bridge := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "Bearer ok" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.Header().Set("X-User-Id", "u1")
			w.Header().Set("X-Username", "alice")
			w.Header().Set("X-Roles", "offline_access")
			w.Header().Set("X-Scopes", "openid,profile")
			w.Header().Set("X-Claims", base64.StdEncoding.EncodeToString(
				[]byte(`{"email":"a@b.c","email_verified":false}`)))
			w.WriteHeader(http.StatusOK)
		},
	))
	t.Cleanup(bridge.Close)

	gw, hosts := testGatewayWithAuthBridge(t, `{
		"routes": [{
			"host": "api.test",
			"path": "/api/y",
			"backend": "BACKEND",
			"auth": {
				"when": {
					"method": "GET",
					"roles": ["offline_access"],
					"scopes": ["profile"],
					"claims": { "email": "*" }
				}
			}
		}]
	}`, bridge.URL)
	host := hosts["api.test"]

	do := func(auth string) *http.Response {
		req := httptest.NewRequest(http.MethodGet, "http://"+host+"/api/y", nil)
		req.Host = host
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		rec := httptest.NewRecorder()
		gw.ServeHTTP(rec, req)
		return rec.Result()
	}

	// anonyme → 401
	if resp := do(""); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("anonyme: status = %d, want 401", resp.StatusCode)
	} else {
		resp.Body.Close()
	}

	// authentifié conforme → 200 (proxifié)
	if resp := do("Bearer ok"); resp.StatusCode != http.StatusOK {
		t.Errorf("conforme: status = %d, want 200", resp.StatusCode)
	} else {
		resp.Body.Close()
	}

	// authentifié mais rôles insuffisants → 403 (pas 401 : pas de
	// boucle de login possible)
	bridgeNoRoles := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-User-Id", "u2")
			w.Header().Set("X-Username", "bob")
			w.WriteHeader(http.StatusOK)
		},
	))
	t.Cleanup(bridgeNoRoles.Close)
	gw.authBridgeBaseURL = bridgeNoRoles.URL
	if resp := do("Bearer ok"); resp.StatusCode != http.StatusForbidden {
		t.Errorf("insuffisant: status = %d, want 403", resp.StatusCode)
	} else {
		resp.Body.Close()
	}
}

// TestWhenClaimsPresenceAndValue vérifie la sémantique du matcher
// claims : "*" = présence, sinon comparaison stringifiée (booléen
// JSON → "true"/"false", nombre → format Go).
func TestWhenClaimsPresenceAndValue(t *testing.T) {
	bridge := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-User-Id", "u1")
			w.Header().Set("X-Username", "alice")
			w.Header().Set("X-Claims", base64.StdEncoding.EncodeToString(
				[]byte(`{"email":"a@b.c","email_verified":false,"n":42}`)))
			w.WriteHeader(http.StatusOK)
		},
	))
	t.Cleanup(bridge.Close)

	probe := func(claimsJSON string) int {
		gw, _ := testGatewayWithAuthBridge(t, `{
			"routes": [{
				"host": "api.test",
				"path": "/api/y",
				"backend": "BACKEND",
				"auth": { "when": { "claims": `+claimsJSON+` } }
			}]
		}`, bridge.URL)

		req := httptest.NewRequest(http.MethodGet, "http://api.test/api/y", nil)
		req.Host = "api.test"
		req.Header.Set("Authorization", "Bearer x")
		rec := httptest.NewRecorder()
		gw.ServeHTTP(rec, req)
		return rec.Result().StatusCode
	}

	if got := probe(`{"email":"*"}`); got != http.StatusOK {
		t.Errorf(`{"email":"*"}: status = %d, want 200 (présence)`, got)
	}
	if got := probe(`{"email_verified":"false"}`); got != http.StatusOK {
		t.Errorf(`{"email_verified":"false"}: status = %d, want 200 (booléen stringifié)`, got)
	}
	if got := probe(`{"email_verified":"true"}`); got != http.StatusForbidden {
		t.Errorf(`{"email_verified":"true"}: status = %d, want 403 (claim faux = authentifié mais insuffisant)`, got)
	}
	if got := probe(`{"n":"42"}`); got != http.StatusOK {
		t.Errorf(`{"n":"42"}: status = %d, want 200 (nombre stringifié)`, got)
	}
	if got := probe(`{"absent":"*"}`); got != http.StatusForbidden {
		t.Errorf(`{"absent":"*"}: status = %d, want 403 (claim absent = insuffisant)`, got)
	}
}

func TestAuthStateEndpointAnonymous(t *testing.T) {
	// mock auth-bridge: rejects every token
	bridge := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
		},
	))
	t.Cleanup(bridge.Close)

	gw, hosts := testGatewayWithAuthBridge(t, `{
		"routes": [{
			"host": "front.test",
			"path": "/*",
			"frontend": true,
			"backend": "BACKEND"
		}]
	}`, bridge.URL)
	host := hosts["front.test"]

	resp := doGet(t, gw, host, "/__gateway/auth")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
	if b := body(t, resp); !strings.Contains(b, "authentication_required") {
		t.Errorf("body = %q, want authentication_required error", b)
	}
}

func TestAuthStateEndpointAbsentWithoutGuard(t *testing.T) {
	// on a host without a guard-enabled frontend route, the probe
	// path is NOT claimed by the gateway: it is proxied to the
	// backend like any other path (here: 200 HTML default handler).
	gw, hosts := testGateway(t, `{
		"routes": [
			{
				"host": "api.test",
				"path": "/*",
				"backend": "BACKEND"
			},
			{
				"host": "noguard.test",
				"path": "/*",
				"frontend": true,
				"backend": "BACKEND",
				"authGuard": { "enabled": false }
			}
		]
	}`)

	for _, host := range []string{hosts["api.test"], hosts["noguard.test"]} {
		resp := doGet(t, gw, host, "/__gateway/auth")
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("host %s: status = %d, want 200 (proxied)", host, resp.StatusCode)
		}
	}
}
