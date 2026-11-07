package core

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func usageConfigJSON(dir, types, plugins string) string {
	return `{
		"authProvider": {
			"type": "dev",
			"loginBaseUrl": "http://login.dev.test:3000",
			"cookieDomain": "dev.test"
		},
		"usage": {
			"dir": "` + dir + `",
			"nodeId": "gw-1",
			"subjectSecretEnv": "TEST_SUBJECT_SECRET",
			"pluginSecretEnv": "TEST_PLUGIN_SECRET",
			"budgetBytes": 1000000,
			"types": ` + types + `,
			"plugins": ` + plugins + `
		},
		"routes": [{
			"host": "app.dev.test", "path": "/*", "frontend": true,
			"backend": "http://127.0.0.1:1", "auth": {}
		}]
	}`
}

// usageConfigJSONRequireSigned injects usage.requireSigned into the
// shared fixture.
func usageConfigJSONRequireSigned(dir, types, plugins string, requireSigned bool) string {
	raw := usageConfigJSON(dir, types, plugins)
	flag := ""
	if requireSigned {
		flag = `"requireSigned": true, `
	}
	return strings.Replace(raw, `"usage": {`, `"usage": { `+flag, 1)
}

func TestUsageConfigValid(t *testing.T) {
	t.Setenv("TEST_SUBJECT_SECRET", "subject-secret")
	t.Setenv("TEST_PLUGIN_SECRET", "plugin-secret")
	cfg, err := loadAuthTest(t, usageConfigJSON(
		"usage-wal",
		`{"error": {"shareBytes": 500000, "fsync": "window_ms", "windowMs": 100}}`,
		`[{"name": "audit", "url": "http://127.0.0.1:9100", "types": ["error"], "filters": {"tenants": ["mycompany"]}}]`,
	))
	if err != nil {
		t.Fatal(err)
	}
	u := cfg.Usage
	if u == nil {
		t.Fatal("usage not resolved")
	}
	if string(u.SubjectSecret) != "subject-secret" ||
		string(u.PluginSecret) != "plugin-secret" {
		t.Fatal("secrets not resolved")
	}
	if !strings.HasSuffix(u.Dir, "usage-wal") {
		t.Errorf("dir = %q", u.Dir)
	}
	if u.Plugins[0].OnMaxLag != "block" {
		t.Errorf("onMaxLag = %q", u.Plugins[0].OnMaxLag)
	}
}

func TestUsageConfigRejects(t *testing.T) {
	t.Setenv("TEST_SUBJECT_SECRET", "s")
	t.Setenv("TEST_PLUGIN_SECRET", "p")
	cases := []struct {
		name    string
		types   string
		plugins string
		want    string
	}{
		{
			"sum_over_budget",
			`{"error": {"shareBytes": 2000000}}`,
			`[{"name": "a", "url": "http://127.0.0.1:1", "types": ["error"]}]`,
			"exceeds budgetBytes",
		},
		{
			"unknown_type",
			`{"nope": {"shareBytes": 1000}}`,
			`[{"name": "a", "url": "http://127.0.0.1:1", "types": ["nope"]}]`,
			"unknown event type",
		},
		{
			"plugin_type_not_configured",
			`{"error": {"shareBytes": 1000}}`,
			`[{"name": "a", "url": "http://127.0.0.1:1", "types": ["audit"]}]`,
			"not configured in usage.types",
		},
		{
			"error_zero_loss",
			`{"error": {"shareBytes": 1000, "fsync": "always"}}`,
			`[{"name": "a", "url": "http://127.0.0.1:1", "types": ["error"]}]`,
			"zero_loss",
		},
		{
			"duplicate_plugin",
			`{"error": {"shareBytes": 1000}}`,
			`[{"name": "a", "url": "http://127.0.0.1:1", "types": ["error"]}, {"name": "a", "url": "http://127.0.0.1:2", "types": ["error"]}]`,
			"duplicate name",
		},
		{
			"bad_url",
			`{"error": {"shareBytes": 1000}}`,
			`[{"name": "a", "url": "not-a-url", "types": ["error"]}]`,
			"absolute http",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := loadAuthTest(t, usageConfigJSON("u", c.types, c.plugins))
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want %q", err, c.want)
			}
		})
	}
}

func TestUsageConfigUnsignedAllowedByDefault(t *testing.T) {
	t.Setenv("TEST_SUBJECT_SECRET", "s")
	t.Setenv("TEST_PLUGIN_SECRET", "p")
	cfg, err := loadAuthTest(t, usageConfigJSON(
		"u", `{"error": {"shareBytes": 1000}}`,
		`[{"name": "a", "url": "http://127.0.0.1:1", "types": ["error"]}]`,
	))
	if err != nil {
		t.Fatalf("unsigned plugin should be allowed by default: %v", err)
	}
	if cfg.Usage.RequireSigned {
		t.Fatal("requireSigned default should be false")
	}
}

func TestUsageConfigRequireSignedRejectsUnsigned(t *testing.T) {
	t.Setenv("TEST_SUBJECT_SECRET", "s")
	t.Setenv("TEST_PLUGIN_SECRET", "p")
	_, err := loadAuthTest(t, usageConfigJSONRequireSigned(
		"u", `{"error": {"shareBytes": 1000}}`,
		`[{"name": "a", "url": "http://127.0.0.1:1", "types": ["error"]}]`,
		true,
	))
	if err == nil || !strings.Contains(err.Error(), "unsigned plugin refused") {
		t.Fatalf("err = %v, want unsigned refused", err)
	}
}

func TestUsageConfigMissingSecret(t *testing.T) {
	t.Setenv("TEST_SUBJECT_SECRET", "")
	t.Setenv("TEST_PLUGIN_SECRET", "p")
	_, err := loadAuthTest(t, usageConfigJSON(
		"u", `{"error": {"shareBytes": 1000}}`,
		`[{"name": "a", "url": "http://127.0.0.1:1", "types": ["error"]}]`,
	))
	if err == nil || !strings.Contains(err.Error(), "TEST_SUBJECT_SECRET") {
		t.Fatalf("err = %v, want missing secret", err)
	}
}

func TestUsageConfigSignedManifest(t *testing.T) {
	t.Setenv("TEST_SUBJECT_SECRET", "s")
	t.Setenv("TEST_PLUGIN_SECRET", "p")
	dir := t.TempDir()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	trustPath := filepath.Join(dir, "trust.json")
	trust := `{"keys":{"k1":"` +
		base64.RawURLEncoding.EncodeToString(pub) +
		`"},"allowedNames":["com.cladone.*"],"coreVersion":"1.5.0"}`
	if err := os.WriteFile(trustPath, []byte(trust), 0o600); err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(dir, "audit.json")
	artifactPath := filepath.Join(dir, "audit")
	if err := os.WriteFile(manifestPath, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(artifactPath, []byte("bin"), 0o700); err != nil {
		t.Fatal(err)
	}
	raw := fmt.Sprintf(`{
		"authProvider": {
			"type": "dev",
			"loginBaseUrl": "http://login.dev.test:3000",
			"cookieDomain": "dev.test"
		},
		"usage": {
			"dir": "u",
			"subjectSecretEnv": "TEST_SUBJECT_SECRET",
			"pluginSecretEnv": "TEST_PLUGIN_SECRET",
			"trustStore": %q,
			"types": {"auth": {"shareBytes": 1000}},
			"plugins": [{
				"name": "com.cladone.audit",
				"url": "http://127.0.0.1:9100",
				"manifest": %q,
				"artifact": %q
			}]
		},
		"routes": [{
			"host": "app.dev.test", "path": "/*", "frontend": true,
			"backend": "http://127.0.0.1:1", "auth": {}
		}]
	}`, trustPath, manifestPath, artifactPath)
	cfg, err := loadAuthTest(t, raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Usage.Trust.Keys) != 1 {
		t.Fatalf("trust keys = %d", len(cfg.Usage.Trust.Keys))
	}
	if !filepath.IsAbs(cfg.Usage.Plugins[0].Manifest) ||
		!filepath.IsAbs(cfg.Usage.Plugins[0].Artifact) {
		t.Fatal("manifest/artifact paths not resolved")
	}
}

func TestUsageConfigManifestRequiresTrustStore(t *testing.T) {
	t.Setenv("TEST_SUBJECT_SECRET", "s")
	t.Setenv("TEST_PLUGIN_SECRET", "p")
	raw := usageConfigJSON(
		"u",
		`{"auth": {"shareBytes": 1000}}`,
		`[{"name": "com.cladone.audit", "url": "http://127.0.0.1:9100", "manifest": "/tmp/m.json", "artifact": "/tmp/a"}]`,
	)
	_, err := loadAuthTest(t, raw)
	if err == nil || !strings.Contains(err.Error(), "trustStore") {
		t.Fatalf("err = %v, want trustStore", err)
	}
}

func TestRouteUsageOptOut(t *testing.T) {
	cfg, err := loadAuthTest(t, `{
		"authProvider": {"type":"dev","loginBaseUrl":"http://login.dev.test:3000","cookieDomain":"dev.test"},
		"routes": [
			{"host":"a.test","path":"/*","backend":"http://b","auth":{},"usage":false},
			{"host":"b.test","path":"/*","backend":"http://b","auth":{}}
		]
	}`)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Routes[0].UsageEnabled() {
		t.Fatal(`"usage": false must opt the route out`)
	}
	if !cfg.Routes[1].UsageEnabled() {
		t.Fatal("usage must default to enabled")
	}
}
