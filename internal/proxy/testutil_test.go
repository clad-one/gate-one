package proxy

// Socle commun des tests du proxy : la config de test porte le bloc
// oidc (la validation au load exige un login pour toute route à garde
// active et un issuer pour toute route MCP — AUCUNE URL n'est codée
// en dur dans le code).

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"cladone/gateway/internal/core"
)

// testLoginURL : la page de login des configs de test (le harnais UI
// et les assertions de redirect s'y réfèrent).
const testLoginURL = "https://login.test/login"

// withTestOIDC : injecte le bloc oidc de test dans une config JSON
// s'il n'est pas déjà déclaré (un test qui veut un autre IdP le
// déclare lui-même).
func withTestOIDC(routesJSON string) string {
	var m map[string]any
	if err := json.Unmarshal([]byte(routesJSON), &m); err != nil {
		panic(fmt.Sprintf("config de test invalide : %v", err))
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

// loadForTestIn : idem, mais dans le répertoire fourni (les tests
// qui co-localisent bundle + config).
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

// loadForTest : écrit la config (avec bloc oidc de test) dans un
// répertoire temporaire et la charge via la grammaire stricte.
func loadForTest(t *testing.T, routesJSON string) *core.Config {
	t.Helper()
	return loadForTestIn(t, t.TempDir(), routesJSON)
}
