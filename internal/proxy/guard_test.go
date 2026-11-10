package proxy

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cladone/gate-one/internal/core"
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
	clearAuthCache() // global cache: every test starts neutral

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

	routesJSON = strings.ReplaceAll(routesJSON, "BACKEND", backend.URL)
	cfg := loadForTest(t, routesJSON)

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
	// simulates the production ingress: TLS terminated upstream,
	// X-Forwarded-Proto set by Traefik (the direct-HTTP demo variant
	// tests go through doRequestWithHeaders without XFP)
	req.Header.Set("X-Forwarded-Proto", "https")
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
	// the login URL comes from the CONFIG (test oidc block) — never
	// a hardcoded URL
	if !strings.Contains(
		b,
		testLoginURL,
	) {
		t.Errorf("guard script does not reference the login page (%s)", testLoginURL)
	}
	// injected right after <head>
	if !strings.Contains(b, "<head><script>") {
		t.Errorf("script not injected after <head>: %q", b)
	}
	// page content intact
	if !strings.Contains(b, "<body>hello</body>") {
		t.Errorf("page body altered: %q", b)
	}
	// The injection is STREAMING: Content-Length removed (the size
	// changes on the fly) — the response is served chunked, the
	// flush lands write by write (TTFB == the origin's).
	if resp.Header.Get("Content-Length") != "" || resp.ContentLength >= 0 {
		t.Errorf("Content-Length %d/%q: an injected page must be served chunked",
			resp.ContentLength, resp.Header.Get("Content-Length"))
	}
}

// Lazy images are not fetch()es: a resource error is the first sign of
// a session that died mid-read. The guard must re-probe at once
// (throttled) instead of waiting for the periodic timer — otherwise the
// login banner only appears after up to 60 s (2026-10-26).
func TestGuardProbesOnResourceError(t *testing.T) {
	gw, _ := testGateway(t, `{
		"routes": [{
			"host": "front.test",
			"path": "/*",
			"frontend": true,
			"backend": "BACKEND",
			"userBadge": {"claims": ["preferred_username"]}
		}]
	}`)

	b := body(t, doGet(t, gw, "front.test", "/"))

	for _, want := range []string{
		`document.addEventListener("error"`,
		"lastResourceProbe",
		`t.tagName !== "IMG"`,
		"probeSession();",
		"}, true);",
	} {
		if !strings.Contains(b, want) {
			t.Errorf("guard missing resource-error probe hook %q", want)
		}
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

// Login resolution: authGuard.loginUrl (route) wins over the
// platform provider; an AUTHENTICATED route with no login REFUSES to
// start, while a purely public route starts with no oidc block (the
// onboarding "static site" case).
func TestLoginURLResolution(t *testing.T) {
	t.Run("route priority > platform", func(t *testing.T) {
		cfg := loadForTest(t, `{
			"oidc": {"loginUrl": "https://login.plateforme.test/login"},
			"routes": [{
				"host": "front.test", "path": "/*", "frontend": true,
				"backend": "http://127.0.0.1:1",
				"authGuard": {"loginUrl": "https://login.route.test/login"}
			}]
		}`)
		if got := cfg.LoginURLFor(&cfg.Routes[0]); got != "https://login.route.test/login" {
			t.Errorf("login = %q, want the route's URL", got)
		}
	})

	t.Run("platform default", func(t *testing.T) {
		cfg := loadForTest(t, `{
			"oidc": {"loginUrl": "https://login.plateforme.test/login"},
			"routes": [{
				"host": "front.test", "path": "/*", "frontend": true,
				"backend": "http://127.0.0.1:1"
			}]
		}`)
		if got := cfg.LoginURLFor(&cfg.Routes[0]); got != "https://login.plateforme.test/login" {
			t.Errorf("login = %q, want the platform's URL", got)
		}
	})

	t.Run("public route without login: starts", func(t *testing.T) {
		dir := t.TempDir()
		cfgPath := filepath.Join(dir, "routes.json")
		cfgJSON := `{"routes": [{
			"host": "front.test", "path": "/*", "frontend": true,
			"backend": "http://127.0.0.1:1"
		}]}`
		if err := os.WriteFile(cfgPath, []byte(cfgJSON), 0o600); err != nil {
			t.Fatal(err)
		}
		cfg, err := core.Load(cfgPath)
		if err != nil {
			t.Fatalf("public route refused: %v", err)
		}
		if got := cfg.LoginURLFor(&cfg.Routes[0]); got != "" {
			t.Errorf("login = %q, want empty (no auth on this route)", got)
		}
	})

	t.Run("authenticated route without login: refuses to start", func(t *testing.T) {
		dir := t.TempDir()
		cfgPath := filepath.Join(dir, "routes.json")
		cfgJSON := `{"routes": [{
			"host": "front.test", "path": "/*", "frontend": true,
			"backend": "http://127.0.0.1:1",
			"auth": {}
		}]}`
		if err := os.WriteFile(cfgPath, []byte(cfgJSON), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := core.Load(cfgPath); err == nil ||
			!strings.Contains(err.Error(), "no login URL") {
			t.Errorf("err = %v, want refusal \"no login URL\"", err)
		}
	})

	t.Run("MCP without issuer: refuses to start", func(t *testing.T) {
		dir := t.TempDir()
		cfgPath := filepath.Join(dir, "routes.json")
		cfgJSON := `{"routes": [{
			"host": "mcp.test", "path": "/mcp",
			"backend": "http://127.0.0.1:1",
			"mcp": {"enabled": true, "path": "/mcp", "scope": "mcp-tools"}
		}]}`
		if err := os.WriteFile(cfgPath, []byte(cfgJSON), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := core.Load(cfgPath); err == nil ||
			!strings.Contains(err.Error(), "issuer") {
			t.Errorf("err = %v, want refusal mentioning the issuer", err)
		}
	})
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
	gw.setAuthBridgeForTest(authBridgeURL)
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

	resp := doGet(t, gw, host, "/__gate-one/auth")
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
		t.Fatalf("invalid JSON: %v", err)
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

// TestIdentityConditions checks the two-step model: identity
// conditions (roles/scopes/claims) are evaluated AFTER
// authentication — anonymous → 401, authenticated insufficient → 403,
// authenticated conforming → proxified (200).
func TestIdentityConditions(t *testing.T) {
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
				"when": { "method": "GET" },
				"identity": {
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

	// anonymous → 401
	if resp := do(""); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("anonymous: status = %d, want 401", resp.StatusCode)
	} else {
		resp.Body.Close()
	}

	// authenticated conforming → 200 (proxified)
	if resp := do("Bearer ok"); resp.StatusCode != http.StatusOK {
		t.Errorf("conforming: status = %d, want 200", resp.StatusCode)
	} else {
		resp.Body.Close()
	}

	// authenticated but insufficient roles → 403 (not 401: no
	// possible login loop). DIFFERENT token: the gateway's identity
	// cache keys on the client's credentials — same token = same
	// identity (the cache is right); a new "session" is needed to
	// consult the bridge again.
	bridgeNoRoles := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-User-Id", "u2")
			w.Header().Set("X-Username", "bob")
			w.WriteHeader(http.StatusOK)
		},
	))
	t.Cleanup(bridgeNoRoles.Close)
	gw.setAuthBridgeForTest(bridgeNoRoles.URL)
	if resp := do("Bearer ok2"); resp.StatusCode != http.StatusForbidden {
		t.Errorf("insufficient: status = %d, want 403", resp.StatusCode)
	} else {
		resp.Body.Close()
	}
}

// TestWhenListOrSemantics: auth.when as an array is an OR of ANDs —
// authentication is required as soon as ONE element matches; a request
// matching no element stays public (and identity is then not
// evaluated: there is no token).
func TestWhenListOrSemantics(t *testing.T) {
	bridge := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "Bearer ok" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.Header().Set("X-User-Id", "u1")
			w.Header().Set("X-Username", "alice")
			w.Header().Set("X-Roles", "offline_access")
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
				"when": [ { "method": "GET" }, { "method": "DELETE" } ],
				"identity": { "roles": ["offline_access"] }
			}
		}]
	}`, bridge.URL)
	host := hosts["api.test"]

	do := func(method, auth string) int {
		req := httptest.NewRequest(method, "http://"+host+"/api/y", nil)
		req.Host = host
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		rec := httptest.NewRecorder()
		gw.ServeHTTP(rec, req)
		return rec.Result().StatusCode
	}

	// GET matches the first element → auth required.
	if got := do(http.MethodGet, ""); got != http.StatusUnauthorized {
		t.Errorf("GET anonymous: status = %d, want 401", got)
	}
	if got := do(http.MethodGet, "Bearer ok"); got != http.StatusOK {
		t.Errorf("GET authenticated: status = %d, want 200", got)
	}

	// DELETE matches the second element → auth required.
	if got := do(http.MethodDelete, ""); got != http.StatusUnauthorized {
		t.Errorf("DELETE anonymous: status = %d, want 401", got)
	}

	// POST matches NO element → public: no auth, no identity.
	if got := do(http.MethodPost, ""); got != http.StatusOK {
		t.Errorf("POST anonymous: status = %d, want 200 (public, no when match)", got)
	}
}

// TestIdentityClaimsPresenceAndValue checks the claims matcher
// semantics: "*" = presence, otherwise stringified comparison
// (JSON boolean → "true"/"false", number → Go format).
func TestIdentityClaimsPresenceAndValue(t *testing.T) {
	bridge := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-User-Id", "u1")
			w.Header().Set("X-Username", "alice")
			w.Header().Set("X-Claims", base64.StdEncoding.EncodeToString(
				[]byte(`{"email":"a@b.c","email_verified":false,"n":42,`+
					`"groups":["admin","user"]}`)))
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
				"auth": { "identity": { "claims": `+claimsJSON+` } }
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
		t.Errorf(`{"email":"*"}: status = %d, want 200 (presence)`, got)
	}
	if got := probe(`{"email_verified":"false"}`); got != http.StatusOK {
		t.Errorf(`{"email_verified":"false"}: status = %d, want 200 (stringified boolean)`, got)
	}
	if got := probe(`{"email_verified":"true"}`); got != http.StatusForbidden {
		t.Errorf(`{"email_verified":"true"}: status = %d, want 403 (false claim = authenticated but insufficient)`, got)
	}
	if got := probe(`{"n":"42"}`); got != http.StatusOK {
		t.Errorf(`{"n":"42"}: status = %d, want 200 (stringified number)`, got)
	}
	if got := probe(`{"absent":"*"}`); got != http.StatusForbidden {
		t.Errorf(`{"absent":"*"}: status = %d, want 403 (absent claim = insufficient)`, got)
	}

	// A list of accepted values = OR (anyOf) on the same claim.
	if got := probe(`{"email":["a@b.c","x@y.z"]}`); got != http.StatusOK {
		t.Errorf(`{"email":["a@b.c","x@y.z"]}: status = %d, want 200 (one match)`, got)
	}
	if got := probe(`{"email":["x@y.z","z@w.v"]}`); got != http.StatusForbidden {
		t.Errorf(`{"email":["x@y.z","z@w.v"]}: status = %d, want 403 (no match)`, got)
	}
	if got := probe(`{"email":["*"]}`); got != http.StatusOK {
		t.Errorf(`{"email":["*"]}: status = %d, want 200 (presence in a list)`, got)
	}

	// An array-valued token claim matches when one element matches.
	if got := probe(`{"groups":"admin"}`); got != http.StatusOK {
		t.Errorf(`{"groups":"admin"}: status = %d, want 200 (array claim)`, got)
	}
	if got := probe(`{"groups":["x","user"]}`); got != http.StatusOK {
		t.Errorf(`{"groups":["x","user"]}: status = %d, want 200 (one element)`, got)
	}
	if got := probe(`{"groups":"x"}`); got != http.StatusForbidden {
		t.Errorf(`{"groups":"x"}: status = %d, want 403 (no element matches)`, got)
	}
	if got := probe(`{"groups":["*"]}`); got != http.StatusOK {
		t.Errorf(`{"groups":["*"]}: status = %d, want 200 (presence)`, got)
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

	resp := doGet(t, gw, host, "/__gate-one/auth")
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
		resp := doGet(t, gw, host, "/__gate-one/auth")
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("host %s: status = %d, want 200 (proxied)", host, resp.StatusCode)
		}
	}
}
