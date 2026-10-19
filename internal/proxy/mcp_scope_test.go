package proxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// newMCPTestGateway builds a Gateway with one MCP route (scope
// configurable) whose auth checks go to a stubbed auth-bridge. The
// stub records the X-MCP-Scope header it received and answers with a
// status chosen per request (default 401 to trigger the challenge).
func newMCPTestGateway(
	t *testing.T,
	scope string,
) (http.Handler, *[]string) {
	return newMCPTestGatewayWithBridgeStatus(t, scope, http.StatusUnauthorized)
}

// newMCPTestGatewayWithBridgeStatus est la variante paramétrable :
// le stub auth-bridge répond toujours bridgeStatus, ce qui permet de
// tester le relais du 401 (challenge) comme du 403 (insufficient
// scope).
func newMCPTestGatewayWithBridgeStatus(
	t *testing.T,
	scope string,
	bridgeStatus int,
) (http.Handler, *[]string) {
	t.Helper()

	var seen []string

	bridge := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			seen = append(seen, r.Header.Get("X-MCP-Scope"))
			w.WriteHeader(bridgeStatus)
		},
	))
	t.Cleanup(bridge.Close)

	routeScope := ""
	if scope != "" {
		routeScope = `, "scope": "` + scope + `"`
	}

	routesJSON := `{
		"routes": [{
			"host": "gram.test",
			"path": "/mcp",
			"backend": "http://backend.test",
			"auth": {},
			"mcp": {"enabled": true, "path": "/mcp"` + routeScope + `}
		}]
	}`

	cfg := loadForTest(t, routesJSON)

	gw, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	gw.authBridgeBaseURL = bridge.URL

	return gw, &seen
}

func TestMCPChallengeUsesConfiguredScope(t *testing.T) {
	gw, _ := newMCPTestGateway(t, "custom-scope")

	resp := doGet(t, gw, "gram.test", "/mcp")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}

	wwwAuth := resp.Header.Get("WWW-Authenticate")
	if !strings.Contains(wwwAuth, `scope="custom-scope"`) {
		t.Errorf("challenge = %q, want scope=custom-scope", wwwAuth)
	}
	if !strings.Contains(
		wwwAuth,
		`resource_metadata="https://gram.test/.well-known/oauth-protected-resource"`,
	) {
		t.Errorf("challenge = %q, missing resource_metadata", wwwAuth)
	}
}

func TestMCPChallengeDefaultsToMcpTools(t *testing.T) {
	gw, seen := newMCPTestGateway(t, "")

	resp := doGet(t, gw, "gram.test", "/mcp")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}

	if wwwAuth := resp.Header.Get("WWW-Authenticate"); !strings.Contains(
		wwwAuth,
		`scope="`+defaultMCPScope+`"`,
	) {
		t.Errorf("challenge = %q, want default scope", wwwAuth)
	}

	// the scope sent to auth-bridge must match the default too
	if len(*seen) != 1 {
		t.Fatalf("auth-bridge stub called %d times, want 1", len(*seen))
	}
	if (*seen)[0] != defaultMCPScope {
		t.Errorf("X-MCP-Scope = %q, want %q", (*seen)[0], defaultMCPScope)
	}
}

// TestMCPInsufficientScopeChallenge vérifie le relais du 403
// auth-bridge (token valide mais scope manquant) : la gateway doit
// renvoyer error="insufficient_scope", le scope exigé et
// resource_metadata (MCP 2026-07-28, cohérence avec le 401).
func TestMCPInsufficientScopeChallenge(t *testing.T) {
	gw, _ := newMCPTestGatewayWithBridgeStatus(t, "custom-scope", http.StatusForbidden)

	resp := doGet(t, gw, "gram.test", "/mcp")
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}

	wwwAuth := resp.Header.Get("WWW-Authenticate")
	if !strings.Contains(wwwAuth, `error="insufficient_scope"`) {
		t.Errorf("challenge = %q, want error=insufficient_scope", wwwAuth)
	}
	if !strings.Contains(wwwAuth, `scope="custom-scope"`) {
		t.Errorf("challenge = %q, want scope=custom-scope", wwwAuth)
	}
	if !strings.Contains(
		wwwAuth,
		`resource_metadata="https://gram.test/.well-known/oauth-protected-resource"`,
	) {
		t.Errorf("challenge = %q, missing resource_metadata", wwwAuth)
	}
}

func TestMCPProtectedResourceAnnouncesConfiguredScope(t *testing.T) {
	gw, _ := newMCPTestGateway(t, "custom-scope")

	resp := doGet(t, gw, "gram.test", "/.well-known/oauth-protected-resource")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	var payload map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}

	scopes, ok := payload["scopes_supported"].([]any)
	if !ok || len(scopes) != 1 {
		t.Fatalf("scopes_supported = %v, want one entry", payload["scopes_supported"])
	}
	if scopes[0] != "custom-scope" {
		t.Errorf("scopes_supported[0] = %v, want custom-scope", scopes[0])
	}
}
