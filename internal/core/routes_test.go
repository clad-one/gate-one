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
