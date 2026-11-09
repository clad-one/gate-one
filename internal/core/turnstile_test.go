package core

import (
	"strings"
	"testing"
)

func turnstileConfigJSON(block string) string {
	return `{
		"turnstile": ` + block + `,
		"authProvider": {
			"type": "dev",
			"loginBaseUrl": "http://login.dev.test:3000",
			"cookieDomain": "dev.test"
		},
		"routes": [{
			"host": "app.dev.test", "path": "/*", "frontend": true,
			"backend": "http://127.0.0.1:1", "auth": {}
		}]
	}`
}

func TestTurnstileConfigDefaults(t *testing.T) {
	t.Setenv("TEST_TURNSTILE_SECRET", "secret")
	cfg, err := loadAuthTest(t, turnstileConfigJSON(`{
		"siteKey": "0x4AAAA",
		"secretEnv": "TEST_TURNSTILE_SECRET"
	}`))
	if err != nil {
		t.Fatal(err)
	}
	ts := cfg.Turnstile
	if ts == nil || !ts.Active() {
		t.Fatal("turnstile block not resolved")
	}
	if ts.Secret != "secret" {
		t.Fatalf("secret not read from env")
	}
	if len(ts.Methods) != 1 || ts.Methods[0] != "POST" {
		t.Fatalf("methods = %v, want [POST]", ts.Methods)
	}
	if ts.TokenHeader != DefaultTurnstileTokenHeader {
		t.Fatalf("tokenHeader = %q", ts.TokenHeader)
	}
	if got := cfg.TurnstileFor("app.dev.test", "/contact"); got == nil {
		t.Fatal("empty hosts/paths must match everything")
	}
	if !ts.MatchesMethod("post") {
		t.Fatal("method matching must be case-insensitive")
	}
}

func TestTurnstileOnlyConfiguredScope(t *testing.T) {
	t.Setenv("TEST_TURNSTILE_SECRET", "secret")
	cfg, err := loadAuthTest(t, turnstileConfigJSON(`{
		"siteKey": "0x4AAAA",
		"secretEnv": "TEST_TURNSTILE_SECRET",
		"hosts": ["App.Example.com", "*.dev.test"],
		"paths": ["/contact/*", "/register"],
		"methods": ["post", "PATCH"]
	}`))
	if err != nil {
		t.Fatal(err)
	}
	ts := cfg.Turnstile
	if len(ts.Hosts) != 2 || ts.Hosts[0] != "app.example.com" {
		t.Fatalf("hosts = %v", ts.Hosts)
	}
	if len(ts.Methods) != 2 || ts.Methods[0] != "POST" ||
		ts.Methods[1] != "PATCH" {
		t.Fatalf("methods = %v", ts.Methods)
	}

	cases := []struct {
		host, path, method string
		want               bool
	}{
		{"app.example.com", "/contact", "POST", true},
		{"app.example.com", "/contact/send", "POST", true},
		{"app.example.com", "/register", "PATCH", true},
		{"app.dev.test", "/register", "POST", true},
		{"app.example.com", "/", "POST", false},
		{"app.example.com", "/contact", "GET", false},
		{"other.test", "/contact", "POST", false},
	}
	for _, c := range cases {
		got := cfg.TurnstileFor(c.host, c.path)
		ok := got != nil && got.MatchesMethod(c.method)
		if ok != c.want {
			t.Errorf("%s%s %s: got %v, want %v",
				c.host, c.path, c.method, ok, c.want)
		}
	}
}

func TestTurnstileDisabledIsNil(t *testing.T) {
	cfg, err := loadAuthTest(t, turnstileConfigJSON(`{
		"enabled": false,
		"siteKey": "0x4AAAA",
		"secretEnv": "MISSING_ON_PURPOSE"
	}`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Turnstile != nil {
		t.Fatal("an explicitly disabled block must be dropped")
	}
}

func TestTurnstileConfigRejects(t *testing.T) {
	t.Setenv("TEST_TURNSTILE_SECRET", "secret")
	cases := []struct {
		name  string
		block string
		want  string
	}{
		{"no_sitekey", `{"secretEnv":"TEST_TURNSTILE_SECRET"}`, "siteKey"},
		{"no_secretenv", `{"siteKey":"k"}`, "secretEnv"},
		{"empty_env", `{"siteKey":"k","secretEnv":"NOPE_MISSING"}`, "is empty"},
		{"bad_action",
			`{"siteKey":"k","secretEnv":"TEST_TURNSTILE_SECRET","action":"bad action"}`,
			"turnstile.action"},
		{"bad_method",
			`{"siteKey":"k","secretEnv":"TEST_TURNSTILE_SECRET","methods":["GET"]}`,
			"turnstile.methods"},
		{"bad_path",
			`{"siteKey":"k","secretEnv":"TEST_TURNSTILE_SECRET","paths":["contact"]}`,
			"turnstile.paths"},
		{"bad_host",
			`{"siteKey":"k","secretEnv":"TEST_TURNSTILE_SECRET","hosts":["a.*.b"]}`,
			"turnstile.hosts"},
		{"empty_wildcard",
			`{"siteKey":"k","secretEnv":"TEST_TURNSTILE_SECRET","hosts":["*."]}`,
			"turnstile.hosts"},
		{"bad_path_wildcard",
			`{"siteKey":"k","secretEnv":"TEST_TURNSTILE_SECRET","paths":["/con*"]}`,
			"turnstile.paths"},
		{"bad_header",
			`{"siteKey":"k","secretEnv":"TEST_TURNSTILE_SECRET","tokenHeader":"Bad Header"}`,
			"turnstile.tokenHeader"},
		{"unknown_field",
			`{"siteKey":"k","secretEnv":"TEST_TURNSTILE_SECRET","nope":true}`,
			"unknown field"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := loadAuthTest(t, turnstileConfigJSON(c.block))
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want %q", err, c.want)
			}
		})
	}
}

func TestPathMatches(t *testing.T) {
	cases := []struct {
		pattern, path string
		want          bool
	}{
		{"/*", "/", true},
		{"/*", "/contact", true},
		{"/contact/*", "/contact", true},
		{"/contact/*", "/contact/send", true},
		{"/contact/*", "/contacts", false},
		{"/contact", "/contact", true},
		{"/contact", "/contact/send", false},
		{"", "/contact", false},
	}
	for _, c := range cases {
		if got := PathMatches(c.pattern, c.path); got != c.want {
			t.Errorf("PathMatches(%q, %q) = %v", c.pattern, c.path, got)
		}
	}
}

func TestHostMatches(t *testing.T) {
	cases := []struct {
		pattern, host string
		want          bool
	}{
		{"", "app.example.com", true},
		{"app.example.com", "APP.Example.com:8443", true},
		{"app.example.com", "other.example.com", false},
		{"*.example.com", "app.example.com", true},
		{"*.example.com", "a.b.example.com", true},
		{"*.example.com", "example.com", false},
		{"*.example.com", "notexample.com", false},
	}
	for _, c := range cases {
		if got := HostMatches(c.pattern, c.host); got != c.want {
			t.Errorf("HostMatches(%q, %q) = %v", c.pattern, c.host, got)
		}
	}
}

func TestPathsOverlap(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"/*", "/contact/*", true},
		{"/contact/*", "/*", true},
		{"/contact/*", "/contact/send", true},
		{"/contact/*", "/contact", true},
		{"/contact/*", "/other/*", false},
		{"/a/*", "/a/b/*", true},
		{"/contact", "/contact", true},
		{"/contact", "/contact/send", false},
		{"/other/*", "/contact", false},
	}
	for _, c := range cases {
		if got := PathsOverlap(c.a, c.b); got != c.want {
			t.Errorf("PathsOverlap(%q, %q) = %v", c.a, c.b, got)
		}
	}
}
