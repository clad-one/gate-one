package proxy

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"cladone/gateway/internal/core"
)

// TestMCPE2EOnLine reproduit le scénario du smoke.sh (POST /mcp JSON
// sans Authorization contre une route mcp + auth) en test Go :
// auth-bridge stubbé, vérifie que le bridge reçoit X-MCP-Scope et que
// le client voit un challenge 401 — au lieu du 200 sans auth observé
// à tort dans une version précédente du diagnostic.
func TestMCPE2EOnLine(t *testing.T) {
	// backend factice : répond 200 vide sur tout
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

	// GET /mcp sans Authorization → checkMCPAuth doit être appelé
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
		t.Errorf("X-MCP-Scope reçu par auth-bridge = %v, want [smoke-scope]", seenScopes)
	}
}

// TestMCPBridgeUnreachable vérifie qu'une erreur transport vers
// auth-bridge (DNS/service mort) ne produit pas de réponse 200 vide :
// la gateway répond 502 explicite (l'ancien code faisait un return nu,
// Go émettait alors un 200 vide).
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
	// auth-bridge factice injoignable : port 1, connection refused.
	// Client à timeout court : le test ne doit pas subir le timeout
	// système (30 s) du client de production.
	gw.authBridgeBaseURL = "http://127.0.0.1:1"
	gw.client = &http.Client{Timeout: 2 * time.Second}

	req := httptest.NewRequest(http.MethodGet, "http://mcp.smoke.local/mcp", nil)
	req.Host = "mcp.smoke.local"
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502 (l'ancien code laissait Go émettre un 200 vide)", rec.Code)
	}
}

// loadGatewayForTest charge une config JSON et construit la gateway.
func loadGatewayForTest(t *testing.T, routesJSON string) *Gateway {
	t.Helper()

	cfgPath := filepath.Join(t.TempDir(), "routes.json")
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
	return gw
}
