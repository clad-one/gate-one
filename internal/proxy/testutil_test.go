package proxy

// Common base of the proxy tests: the test config carries the oidc
// block (load-time validation requires a login for every active-guard
// route and an issuer for every MCP route — NO URL is hardcoded in
// the code).

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"cladone/gate-one/internal/authn"
	"cladone/gate-one/internal/core"
)

// testLoginURL: the login page of the test configs (the UI harness
// and the redirect assertions refer to it).
const testLoginURL = "https://login.test/login"

// withTestOIDC: injects the test oidc block into a JSON config if
// not already declared (a test wanting another IdP declares it
// itself).
func withTestOIDC(routesJSON string) string {
	var m map[string]any
	if err := json.Unmarshal([]byte(routesJSON), &m); err != nil {
		panic(fmt.Sprintf("invalid test config: %v", err))
	}
	if _, ok := m["oidc"]; !ok {
		m["oidc"] = map[string]any{
			"loginUrl": testLoginURL,
			"issuer":   "https://auth.test/realms/test",
		}
	}
	b, err := json.Marshal(m)
	if err != nil {
		panic(err)
	}
	return string(b)
}

// loadForTestIn: same, but in the provided directory (tests that
// co-locate bundle + config).
func loadForTestIn(
	t *testing.T,
	dir, routesJSON string,
) *core.Config {
	t.Helper()

	cfgPath := filepath.Join(dir, "routes.json")
	if err := os.WriteFile(
		cfgPath, []byte(withTestOIDC(routesJSON)), 0o600,
	); err != nil {
		t.Fatal(err)
	}

	cfg, err := core.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

// loadForTest: writes the config (with the test oidc block) into a
// temporary directory and loads it through the strict grammar.
func loadForTest(t *testing.T, routesJSON string) *core.Config {
	t.Helper()
	return loadForTestIn(t, t.TempDir(), routesJSON)
}

// setAuthBridgeForTest swaps the gateway's provider for a stub after
// construction. Tests used to assign authBridgeBaseURL directly; the
// provider is now built at New time, so the assignment must rebuild
// it (and drop the identity cache, which is global).
func (g *Gateway) setAuthBridgeForTest(rawURL string) {
	g.authBridgeBaseURL = rawURL
	login, issuer := "", ""
	if g.config.AuthProvider != nil {
		login = g.config.AuthProvider.LoginURL
		issuer = g.config.AuthProvider.Issuer
	}
	p, err := authn.NewHTTP(authn.HTTPConfig{
		BaseURL:       rawURL,
		LoginURLValue: login,
		IssuerValue:   issuer,
		Client:        g.client,
	})
	if err != nil {
		panic(err)
	}
	g.auth = p
	clearAuthCache()
}
