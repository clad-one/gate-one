package core

// Tests de validation du modèle services + ensembles.

import (
	"strings"
	"testing"
)

func boolPtr(b bool) *bool { return &b }

func validMCPSetConfig() *Config {
	return &Config{
		OIDC: &OIDCConfig{Issuer: "https://auth.test/realms/t"},
		Routes: []Route{
			{
				Host: "svc.test", Path: "/github",
				Backend: "http://b.test",
				Auth:    &AuthPolicy{},
				MCP: &MCPPolicy{
					Enabled: true, Name: "github",
					Resource: "https://svc.test/github",
					Scope:    "svc-scope",
				},
			},
			{
				Host: "svc.test", Path: "/gitlab",
				Backend: "http://b.test",
				MCP: &MCPPolicy{
					Enabled: true, Name: "gitlab",
					Standalone: boolPtr(false),
				},
			},
		},
		MCPSets: map[string]*MCPSet{
			"git": {
				Host: "mcp.test", Endpoint: "/git",
				Resource: "https://mcp.test/git",
				Scope:    "set-scope",
				Members: []MCPSetMember{
					{Service: "github", Path: "/github"},
					{Service: "gitlab", Path: "/gitlab"},
				},
			},
		},
	}
}

func TestValidateMCPSetsAcceptsValid(t *testing.T) {
	if err := validMCPSetConfig().validate(); err != nil {
		t.Fatalf("valid config refused: %v", err)
	}
}

func TestValidateMCPSetsRejects(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{
			"unknown service",
			func(c *Config) {
				c.MCPSets["git"].Members[0].Service = "nope"
			},
			"unknown service",
		},
		{
			"duplicate service name",
			func(c *Config) { c.Routes[1].MCP.Name = "github" },
			"declared twice",
		},
		{
			"non-standalone service without a set",
			func(c *Config) {
				c.MCPSets["git"].Members =
					c.MCPSets["git"].Members[:1]
			},
			"belongs to no mcpSet",
		},
		{
			"access-unit resource collision",
			func(c *Config) {
				c.MCPSets["git"].Resource = "https://svc.test/github"
			},
			"already used",
		},
		{
			"standalone service without auth",
			func(c *Config) { c.Routes[0].Auth = nil },
			"requires auth",
		},
		{
			"invalid member tool pattern",
			func(c *Config) {
				c.MCPSets["git"].Members[0].Tools = []string{"["}
			},
			"invalid tool pattern",
		},
		{
			"relative member path",
			func(c *Config) {
				c.MCPSets["git"].Members[0].Path = "github"
			},
			"path must start with /",
		},
		{
			"duplicate member path",
			func(c *Config) {
				c.MCPSets["git"].Members[1].Path = "/github"
			},
			"duplicate member path",
		},
		{
			"set without members",
			func(c *Config) { c.MCPSets["git"].Members = nil },
			"at least one member",
		},
		{
			"set identity with a technical condition",
			func(c *Config) {
				c.MCPSets["git"].Identity = &Match{Method: "GET"}
			},
			"technical conditions belong",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := validMCPSetConfig()
			tc.mutate(c)
			err := c.validate()
			if err == nil {
				t.Fatalf("expected an error containing %q", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestValidateMCPSetsDisabledSetIsSkipped(t *testing.T) {
	c := validMCPSetConfig()
	c.MCPSets["git"].Enabled = boolPtr(false)

	// The set is skipped entirely: its non-standalone service is now
	// unreferenced, and the error carries an actionable hint.
	err := c.validate()
	if err == nil || !strings.Contains(err.Error(), "belongs to no mcpSet") {
		t.Fatalf("err = %v, want the service to be unreferenced", err)
	}
	if !strings.Contains(err.Error(), "hint:") {
		t.Errorf("error lacks an actionable hint: %v", err)
	}
}

func TestValidateMCPSetsErrorsCarryHints(t *testing.T) {
	c := validMCPSetConfig()
	c.MCPSets["git"].Members[0].Service = "nope"

	err := c.validate()
	if err == nil {
		t.Fatal("expected an error")
	}
	for _, want := range []string{
		"unknown service", "hint:", `mcpSets["git"].enabled=false`,
	} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error = %v, want it to contain %q", err, want)
		}
	}
}
