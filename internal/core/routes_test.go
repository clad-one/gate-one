package core

import (
	"os"
	"path/filepath"
	"testing"
)

// La config réelle utilise "autoHead" : le tag Go doit le lire. Régression
// pour le bug où le tag était "headFallback" et le flag était ignoré (HEAD
// partait natif au backend).
func TestAutoHeadDeserialization(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "routes.json")
	cfg := `{
		"routes": [
			{"host": "a.local", "path": "/*", "backend": "http://x", "autoHead": true},
			{"host": "b.local", "path": "/*", "backend": "http://x"}
		]
	}`
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !c.Routes[0].AutoHead {
		t.Error(`"autoHead": true not deserialized into Route.AutoHead`)
	}
	if c.Routes[1].AutoHead {
		t.Error("absent autoHead should default to false")
	}
}

// Le scope MCP exigé doit venir du champ "mcp.scope" de la config
// (valeur aussi déclarée dans le realm Keycloak : le client scope
// optionnel du même nom).
func TestMCPScopeDeserialization(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "routes.json")
	cfg := `{
		"routes": [
			{"host": "a.local", "path": "/mcp", "backend": "http://x",
			 "mcp": {"enabled": true, "scope": "custom-scope"}},
			{"host": "b.local", "path": "/*", "backend": "http://x",
			 "mcp": {"enabled": true}}
		]
	}`
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := c.Routes[0].MCP.Scope; got != "custom-scope" {
		t.Errorf(`"mcp": {"scope": "custom-scope"} deserialized as %q`, got)
	}
	if got := c.Routes[1].MCP.Scope; got != "" {
		t.Errorf("absent mcp.scope should default to empty, got %q", got)
	}
}

// La grammaire est STRICTE : tout champ inconnu (faute de frappe dans
// un nom de policy, champ prévu mais non implémenté) doit casser le
// load — jamais de policy ignorée en silence (régression du type
// autoHead/"headFallback"). NB : le décodage Go est insensible à la
// casse sur les tags ("autohead" matche "autoHead") — la stricte ne
// rejette que les noms réellement inconnus.
func TestLoadRejectsUnknownFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "routes.json")
	cfg := `{
		"routes": [
			{"host": "a.local", "path": "/*", "backend": "http://x",
			 "headFallback": true}
		]
	}`
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Error("headFallback (nom inconnu) doit être rejeté, load accepté")
	}
}

func TestLoadAllowsSchemaKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "routes.json")
	cfg := `{
		"$schema": "./api-routes.schema.json",
		"routes": [
			{"host": "a.local", "path": "/*", "backend": "http://x"}
		]
	}`
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatalf("$schema doit être accepté: %v", err)
	}
	if len(c.Routes) != 1 {
		t.Errorf("routes = %d, want 1", len(c.Routes))
	}
}

// La config RÉELLE de production doit passer la grammaire stricte.
func TestLoadRealConfigStrict(t *testing.T) {
	c, err := Load("../../api-routes.json")
	if err != nil {
		t.Fatalf("api-routes.json réel invalide: %v", err)
	}
	if len(c.Routes) == 0 {
		t.Error("aucune route chargée")
	}
}
