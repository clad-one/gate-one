package core

// Validation of upstream.headers when they now reach MCP tool calls.

import "testing"

func TestValidateMCPStaticHeaders(t *testing.T) {
	base := func() *Config {
		return &Config{
			OIDC: &OIDCConfig{Issuer: "https://auth.test/realms/t"},
			Routes: []Route{{
				Host: "m.test", Path: "/mcp", Backend: "http://b.test",
				Auth: &AuthPolicy{},
				Upstream: &UpstreamPolicy{
					Headers: map[string]string{"X-Api-Key": "k"},
				},
				MCP: &MCPPolicy{Enabled: true, Path: "/mcp"},
			}},
		}
	}

	if err := base().validate(); err != nil {
		t.Fatalf("valid static header refused: %v", err)
	}

	cases := map[string]func(*Config){
		"identity header": func(c *Config) {
			c.Routes[0].Upstream.Headers["X-User-Id"] = "x"
		},
		"transport header": func(c *Config) {
			c.Routes[0].Upstream.Headers["Accept"] = "x"
		},
		"control character": func(c *Config) {
			c.Routes[0].Upstream.Headers["X-Api-Key"] = "a\nb"
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			c := base()
			mutate(c)
			if err := c.validate(); err == nil {
				t.Fatal("expected an error")
			}
		})
	}

	// A plain REST route may legitimately use transport headers.
	rest := &Config{
		OIDC: &OIDCConfig{Issuer: "https://auth.test/realms/t"},
		Routes: []Route{{
			Host: "r.test", Path: "/*", Backend: "http://b.test",
			Upstream: &UpstreamPolicy{
				Headers: map[string]string{"Accept": "application/json"},
			},
		}},
	}
	if err := rest.validate(); err != nil {
		t.Fatalf("plain REST route refused: %v", err)
	}
}
