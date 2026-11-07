package core

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// usageConfigWithPluginsDir builds a minimal usage config whose plugins
// come from pluginsDir (inline list empty).
func usageConfigWithPluginsDir(walDir, pluginsDir string, requireSigned bool) string {
	flag := ""
	if requireSigned {
		flag = `"requireSigned": true, `
	}
	raw := usageConfigJSON(walDir,
		`{"error": {"shareBytes": 500000, "fsync": "none"}}`, `[]`)
	raw = strings.Replace(raw, `"usage": {`, `"usage": { `+flag, 1)
	return strings.Replace(raw,
		`"plugins":`, `"pluginsDir": "`+pluginsDir+`", "plugins":`, 1)
}

func writePluginFile(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestUsagePluginsDirScan: the directory reader sorts *.json descriptors,
// skips dotfiles/subdirectories/other extensions, and resolves manifest
// and artifact paths relative to the descriptor.
func TestUsagePluginsDirScan(t *testing.T) {
	dir := t.TempDir()
	writePluginFile(t, dir, "b.json",
		`{"name":"b","url":"http://127.0.0.1:9201","types":["error"]}`)
	writePluginFile(t, dir, "a.json",
		`{"name":"a","url":"http://127.0.0.1:9200","types":["error"],`+
			`"manifest":"m.json","artifact":"plugin.bin"}`)
	writePluginFile(t, dir, ".hidden.json", "not json")
	writePluginFile(t, dir, "notes.txt", "x")
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}

	got, err := loadPluginsDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d plugins, want 2: %+v", len(got), got)
	}
	if got[0].Name != "a" || got[1].Name != "b" {
		t.Fatalf("order/names = %q, %q; want a, b", got[0].Name, got[1].Name)
	}
	if got[0].Manifest != filepath.Join(dir, "m.json") ||
		got[0].Artifact != filepath.Join(dir, "plugin.bin") {
		t.Fatalf("paths not resolved against the dir: %+v", got[0])
	}
}

// TestUsagePluginsDirMerged: descriptors from pluginsDir are merged with
// the inline list (inline first).
func TestUsagePluginsDirMerged(t *testing.T) {
	t.Setenv("TEST_SUBJECT_SECRET", "subject-secret")
	t.Setenv("TEST_PLUGIN_SECRET", "plugin-secret")

	dir := t.TempDir()
	writePluginFile(t, dir, "p.json",
		`{"name":"dir-plugin","url":"http://127.0.0.1:9200","types":["error"]}`)

	cfg, err := loadAuthTest(t, strings.Replace(
		usageConfigWithPluginsDir("usage-wal", dir, false),
		`"plugins": []`,
		`"plugins": [{"name":"inline","url":"http://127.0.0.1:9100","types":["error"]}]`,
		1))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Usage.Plugins) != 2 ||
		cfg.Usage.Plugins[0].Name != "inline" ||
		cfg.Usage.Plugins[1].Name != "dir-plugin" {
		t.Fatalf("plugins = %+v", cfg.Usage.Plugins)
	}
}

// TestUsagePluginsDirDuplicate: a name repeated between the inline list
// and the directory is refused.
func TestUsagePluginsDirDuplicate(t *testing.T) {
	t.Setenv("TEST_SUBJECT_SECRET", "subject-secret")
	t.Setenv("TEST_PLUGIN_SECRET", "plugin-secret")

	dir := t.TempDir()
	writePluginFile(t, dir, "p.json",
		`{"name":"dup","url":"http://127.0.0.1:9200","types":["error"]}`)

	raw := strings.Replace(
		usageConfigWithPluginsDir("usage-wal", dir, false),
		`"plugins": []`,
		`"plugins": [{"name":"dup","url":"http://127.0.0.1:9100","types":["error"]}]`,
		1)
	if _, err := loadAuthTest(t, raw); err == nil ||
		!strings.Contains(err.Error(), "duplicate name") {
		t.Fatalf("err = %v, want duplicate name", err)
	}
}

// TestUsagePluginsDirRequireSigned: an unsigned descriptor in the
// directory is refused when requireSigned is set.
func TestUsagePluginsDirRequireSigned(t *testing.T) {
	t.Setenv("TEST_SUBJECT_SECRET", "subject-secret")
	t.Setenv("TEST_PLUGIN_SECRET", "plugin-secret")

	dir := t.TempDir()
	writePluginFile(t, dir, "p.json",
		`{"name":"unsigned","url":"http://127.0.0.1:9200","types":["error"]}`)

	if _, err := loadAuthTest(t,
		usageConfigWithPluginsDir("usage-wal", dir, true)); err == nil ||
		!strings.Contains(err.Error(), "unsigned plugin refused") {
		t.Fatalf("err = %v, want unsigned plugin refused", err)
	}
}
