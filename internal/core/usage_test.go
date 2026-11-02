package core

import (
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

func TestUsageConfigValid(t *testing.T) {
	t.Setenv("TEST_SUBJECT_SECRET", "subject-secret")
	t.Setenv("TEST_PLUGIN_SECRET", "plugin-secret")
	cfg, err := loadAuthTest(t, usageConfigJSON(
		"usage-wal",
		`{"error": {"shareBytes": 500000, "fsync": "window_ms", "windowMs": 100}}`,
		`[{"name": "audit", "url": "http://127.0.0.1:9100", "types": ["error"], "filters": {"tenants": ["acme"]}}]`,
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
