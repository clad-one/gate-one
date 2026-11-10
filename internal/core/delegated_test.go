package core

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func loadDelegated(t *testing.T, config string) (*Config, error) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "routes.json")
	if err := os.WriteFile(path, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	return Load(path)
}

func TestDelegatedConfigResolvesSecret(t *testing.T) {
	t.Setenv("DELEGATED_CORE_SECRET", "s3cret")

	cfg, err := loadDelegated(t, `{
		"tokenBroker": {"url": "http://broker:4000", "secretEnv": "DELEGATED_CORE_SECRET"},
		"routes": [{
			"host": "api.test", "path": "/*", "backend": "http://backend",
			"auth": {},
			"upstream": {"tokenBroker": {"provider": "github"}}
		}]
	}`)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.TokenBroker.SecretValue != "s3cret" {
		t.Fatalf("secret = %q", cfg.TokenBroker.SecretValue)
	}
	d := cfg.Routes[0].UpstreamTokenBroker()
	if d.HeaderValue() != "Authorization" {
		t.Fatalf("header = %q", d.HeaderValue())
	}
	if d.PrefixValue() != "Bearer " {
		t.Fatalf("prefix = %q", d.PrefixValue())
	}
	if cfg.Routes[0].Upstream.TokenBroker.Provider != "github" {
		t.Fatalf("provider = %q", cfg.Routes[0].Upstream.TokenBroker.Provider)
	}
}

func TestDelegatedConfigExplicitRawPrefix(t *testing.T) {
	t.Setenv("DELEGATED_CORE_SECRET", "s3cret")

	cfg, err := loadDelegated(t, `{
		"tokenBroker": {"secretEnv": "DELEGATED_CORE_SECRET"},
		"routes": [{
			"host": "api.test", "path": "/*", "backend": "http://backend",
			"auth": {},
			"upstream": {"tokenBroker": {"provider": "github", "prefix": ""}}
		}]
	}`)
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.Routes[0].UpstreamTokenBroker().PrefixValue(); got != "" {
		t.Fatalf("prefix = %q, want explicit empty", got)
	}
	if cfg.TokenBroker.URL != "http://token-broker:4000" {
		t.Fatalf("default URL = %q", cfg.TokenBroker.URL)
	}
}

func TestDelegatedConfigRejects(t *testing.T) {
	t.Setenv("DELEGATED_CORE_SECRET", "s3cret")

	cases := []struct {
		name string
		cfg  string
		want string
	}{
		{
			name: "no auth",
			cfg: `{
				"tokenBroker": {"secretEnv": "DELEGATED_CORE_SECRET"},
				"routes": [{"host":"api.test","path":"/*","backend":"http://backend",
					"upstream":{"tokenBroker":{"provider":"github"}}}]
			}`,
			want: "requires auth",
		},
		{
			name: "no tokenBroker",
			cfg: `{
				"routes": [{"host":"api.test","path":"/*","backend":"http://backend",
					"auth":{},
					"upstream":{"tokenBroker":{"provider":"github"}}}]
			}`,
			want: "requires the top-level tokenBroker block",
		},
		{
			name: "bad provider",
			cfg: `{
				"tokenBroker": {"secretEnv": "DELEGATED_CORE_SECRET"},
				"routes": [{"host":"api.test","path":"/*","backend":"http://backend",
					"auth":{},"upstream":{"tokenBroker":{"provider":"GitHub"}}}]
			}`,
			want: "provider",
		},
		{
			name: "reserved header",
			cfg: `{
				"tokenBroker": {"secretEnv": "DELEGATED_CORE_SECRET"},
				"routes": [{"host":"api.test","path":"/*","backend":"http://backend",
					"auth":{},"upstream":{"tokenBroker":{"provider":"github","header":"X-User-Id"}}}]
			}`,
			want: "reserved",
		},
		{
			name: "invalid header",
			cfg: `{
				"tokenBroker": {"secretEnv": "DELEGATED_CORE_SECRET"},
				"routes": [{"host":"api.test","path":"/*","backend":"http://backend",
					"auth":{},"upstream":{"tokenBroker":{"provider":"github","header":"Bad Header"}}}]
			}`,
			want: "invalid header",
		},
		{
			name: "header conflict",
			cfg: `{
				"tokenBroker": {"secretEnv": "DELEGATED_CORE_SECRET"},
				"routes": [{"host":"api.test","path":"/*","backend":"http://backend",
					"auth":{},
					"upstream":{"headers":{"Authorization":"Basic x"},
						"tokenBroker":{"provider":"github"}}}]
			}`,
			want: "conflicts",
		},
		{
			name: "missing secret env",
			cfg: `{
				"tokenBroker": {"secretEnv": "MISSING_DELEGATED_SECRET"},
				"routes": [{"host":"api.test","path":"/*","backend":"http://backend",
					"auth":{},"upstream":{"tokenBroker":{"provider":"github"}}}]
			}`,
			want: "MISSING_DELEGATED_SECRET",
		},
		{
			name: "bad URL",
			cfg: `{
				"tokenBroker": {"url":"ftp://broker","secretEnv":"DELEGATED_CORE_SECRET"},
				"routes": [{"host":"api.test","path":"/*","backend":"http://backend",
					"auth":{},"upstream":{"tokenBroker":{"provider":"github"}}}]
			}`,
			want: "scheme",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := loadDelegated(t, tc.cfg)
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want substring %q", err, tc.want)
			}
		})
	}
}

func TestDelegatedResolvedWithoutRoutes(t *testing.T) {
	// The Services page (pause/resume/erase) must stay available after
	// every route stops delegating: a configured broker block is
	// resolved even with no delegated route.
	t.Setenv("DELEGATED_CORE_SECRET", "s3cret")
	cfg, err := loadDelegated(t, `{
		"tokenBroker": {
			"secretEnv": "DELEGATED_CORE_SECRET",
			"links": {"services": {"url": "https://login.test/connections"}}
		},
		"routes": [{"host":"a.test","path":"/*","backend":"http://backend"}]
	}`)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.TokenBroker.SecretValue != "s3cret" {
		t.Fatalf("secret not resolved without a delegated route")
	}
	if cfg.TokenBroker.BrowserHost != "login.test" {
		t.Fatalf("browserHost = %q", cfg.TokenBroker.BrowserHost)
	}
}
