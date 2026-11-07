package core

import (
	"strings"
	"testing"
)

func TestMCPToolFilter(t *testing.T) {
	f := &MCPToolFilter{
		Include: []string{"list_*", "get_*"},
		Exclude: []string{"*_secret"},
	}
	cases := map[string]bool{
		"list_issues": true,
		"get_repo":    true,
		"get_secret":  false,
		"delete_repo": false,
		"list_secret": false,
		"get_public":  true,
		"unrelated":   false,
	}
	for name, want := range cases {
		if got := f.Allows(name); got != want {
			t.Errorf("Allows(%q) = %v, want %v", name, got, want)
		}
	}

	var nilFilter *MCPToolFilter
	if !nilFilter.Allows("anything") {
		t.Error("nil filter must allow all")
	}
}

func TestMCPUpstreamValidation(t *testing.T) {
	cases := []struct {
		name string
		cfg  string
		want string
	}{
		{
			name: "operations and upstream",
			cfg: `{"oidc":{"issuer":"https://auth.test/realms/test"}, "routes":[{"host":"m.test","path":"/mcp","backend":"http://up",
				"mcp":{"enabled":true,"operations":[{"name":"x","operationId":"x"}],
				"upstream":{"tools":{"exclude":["x"]}}}}]}`,
			want: "mutually exclusive",
		},
		{
			name: "bad upstream URL",
			cfg: `{"oidc":{"issuer":"https://auth.test/realms/test"}, "routes":[{"host":"m.test","path":"/mcp","backend":"http://up",
				"mcp":{"enabled":true,"upstream":{"url":"ftp://up"}}}]}`,
			want: "scheme",
		},
		{
			name: "bad filter",
			cfg: `{"oidc":{"issuer":"https://auth.test/realms/test"}, "routes":[{"host":"m.test","path":"/mcp","backend":"http://up",
				"mcp":{"enabled":true,"upstream":{"tools":{"exclude":["["]}}}}]}`,
			want: "invalid pattern",
		},
		{
			name: "reserved static header",
			cfg: `{"oidc":{"issuer":"https://auth.test/realms/test"}, "routes":[{"host":"m.test","path":"/mcp","backend":"http://up",
				"upstream":{"headers":{"Mcp-Session-Id":"x"}},
				"mcp":{"enabled":true,"upstream":{}}}]}`,
			want: "reserved",
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

func TestMCPUpstreamWithDelegatedLoads(t *testing.T) {
	t.Setenv("DELEGATED_CORE_SECRET", "s3cret")

	cfg, err := loadDelegated(t, `{
		"oidc": {"issuer": "https://auth.test/realms/test"},
		"tokenBroker": {"secretEnv": "DELEGATED_CORE_SECRET"},
		"routes": [{
			"host": "mcp.test", "path": "/mcp", "backend": "https://up.example/mcp",
			"auth": {},
			"mcp": {"enabled": true, "upstream": {"tools": {"exclude": ["delete_*"]}}},
			"upstream": {"tokenBroker": {"provider": "github"}}
		}]
	}`)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Routes[0].MCP.Upstream == nil {
		t.Fatal("mcp.upstream not decoded")
	}
	if !cfg.Routes[0].MCP.Upstream.Tools.Allows("list_issues") {
		t.Error("list_issues should be allowed")
	}
	if cfg.Routes[0].MCP.Upstream.Tools.Allows("delete_repo") {
		t.Error("delete_repo should be hidden")
	}
}
