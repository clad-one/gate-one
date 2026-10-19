package proxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestMCPE2EOnLine reproduces the smoke.sh scenario (POST /mcp JSON
// without Authorization against an mcp + auth route) as a Go test:
// stubbed auth-bridge, checks the bridge receives X-MCP-Scope and
// the client sees a 401 challenge — instead of the unauthenticated
// 200 wrongly observed in a previous diagnostic version.
func TestMCPE2EOnLine(t *testing.T) {
	// fake backend: answers an empty 200 on everything
	backend := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		},
	))
	t.Cleanup(backend.Close)

	var seenScopes []string
	bridge := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			seenScopes = append(seenScopes, r.Header.Get("X-MCP-Scope"))
			w.WriteHeader(http.StatusUnauthorized)
		},
	))
	t.Cleanup(bridge.Close)

	routesJSON := `{
		"routes": [{
			"host": "mcp.smoke.local",
			"path": "/mcp",
			"backend": "` + backend.URL + `",
			"auth": {},
			"mcp": {"enabled": true, "path": "/mcp", "scope": "smoke-scope", "operations": []}
		}]
	}`

	gw := loadGatewayForTest(t, routesJSON)
	gw.authBridgeBaseURL = bridge.URL

	// GET /mcp without Authorization → checkMCPAuth must be called
	req := httptest.NewRequest(http.MethodGet, "http://mcp.smoke.local/mcp", nil)
	req.Host = "mcp.smoke.local"
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (challenge)", rec.Code)
	}
	if www := rec.Header().Get("WWW-Authenticate"); !strings.Contains(
		www,
		`scope="smoke-scope"`,
	) {
		t.Errorf("WWW-Authenticate = %q, want scope=smoke-scope", www)
	}
	if len(seenScopes) != 1 || seenScopes[0] != "smoke-scope" {
		t.Errorf("X-MCP-Scope received by auth-bridge = %v, want [smoke-scope]", seenScopes)
	}
}

// TestMCPBridgeUnreachable checks that a transport error toward
// auth-bridge (DNS/dead service) does not produce an empty 200
// response: the gateway answers an explicit 502 (the old code did a
// bare return, Go then emitted an empty 200).
func TestMCPBridgeUnreachable(t *testing.T) {
	routesJSON := `{
		"routes": [{
			"host": "mcp.smoke.local",
			"path": "/mcp",
			"backend": "http://127.0.0.1:1",
			"auth": {},
			"mcp": {"enabled": true, "path": "/mcp", "scope": "smoke-scope", "operations": []}
		}]
	}`

	gw := loadGatewayForTest(t, routesJSON)
	// unreachable fake auth-bridge: port 1, connection refused.
	// Short-timeout client: the test must not suffer the production
	// client's system timeout (30 s).
	gw.authBridgeBaseURL = "http://127.0.0.1:1"
	gw.client = &http.Client{Timeout: 2 * time.Second}

	req := httptest.NewRequest(http.MethodGet, "http://mcp.smoke.local/mcp", nil)
	req.Host = "mcp.smoke.local"
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502 (the old code let Go emit an empty 200)", rec.Code)
	}
}

// loadGatewayForTest loads a JSON config and builds the gateway.
func loadGatewayForTest(t *testing.T, routesJSON string) *Gateway {
	t.Helper()

	cfg := loadForTest(t, routesJSON)

	gw, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return gw
}
