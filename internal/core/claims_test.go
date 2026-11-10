package core

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestClaimValuesUnmarshal(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []string
		err  string
	}{
		{"string", `"*"`, []string{"*"}, ""},
		{"one", `"alice@example.com"`, []string{"alice@example.com"}, ""},
		{"list", `["a@x","b@x"]`, []string{"a@x", "b@x"}, ""},
		{"null", `null`, nil, "string or an array"},
		{"empty_list", `[]`, nil, "empty"},
		{"empty_value", `""`, nil, "empty value"},
		{"empty_in_list", `["a",""]`, nil, "empty value"},
		{"number", `42`, nil, "string or an array"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var v ClaimValues
			err := json.Unmarshal([]byte(c.in), &v)
			if c.err != "" {
				if err == nil || !strings.Contains(err.Error(), c.err) {
					t.Fatalf("err = %v, want %q", err, c.err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(v) != len(c.want) {
				t.Fatalf("got %v, want %v", v, c.want)
			}
			for i := range c.want {
				if v[i] != c.want[i] {
					t.Fatalf("got %v, want %v", v, c.want)
				}
			}
		})
	}
}

func TestClaimValuesMarshal(t *testing.T) {
	one, _ := json.Marshal(ClaimValues{"a"})
	if string(one) != `"a"` {
		t.Fatalf("single value = %s, want a string (backward compatible)", one)
	}
	many, _ := json.Marshal(ClaimValues{"a", "b"})
	if string(many) != `["a","b"]` {
		t.Fatalf("list = %s", many)
	}
}

func TestMatchClaimsArrayLoad(t *testing.T) {
	cfg, err := loadAuthTest(t, `{
		"authProvider": {
			"type": "dev",
			"loginBaseUrl": "http://login.dev.test:3000",
			"cookieDomain": "dev.test"
		},
		"routes": [{
			"host": "app.dev.test", "path": "/*", "frontend": true,
			"backend": "http://127.0.0.1:1",
			"auth": {
				"identity": {
					"claims": {
						"email": ["alice@example.com", "a.rolland@example.com"],
						"email_verified": "true"
					}
				}
			}
		}]
	}`)
	if err != nil {
		t.Fatal(err)
	}
	id := cfg.Routes[0].Auth.Identity
	if id == nil {
		t.Fatal("identity missing")
	}
	if got := id.Claims["email"]; len(got) != 2 ||
		got[0] != "alice@example.com" || got[1] != "a.rolland@example.com" {
		t.Fatalf("email = %v", got)
	}
	if got := id.Claims["email_verified"]; len(got) != 1 ||
		got[0] != "true" {
		t.Fatalf("email_verified = %v", got)
	}
}

func TestMatchClaimsRejectsInvalid(t *testing.T) {
	cases := []struct{ name, claims, want string }{
		{"empty_list", `{"email": []}`, "empty"},
		{"null", `{"email": null}`, "string or an array"},
		{"number", `{"email": 42}`, "string or an array"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := loadAuthTest(t, `{
				"routes": [{
					"host": "app.dev.test", "path": "/*",
					"backend": "http://127.0.0.1:1",
					"auth": { "identity": { "claims": `+c.claims+` } }
				}]
			}`)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want %q", err, c.want)
			}
		})
	}
}

func TestUIGateClaimsArrayLoad(t *testing.T) {
	cfg, err := loadAuthTest(t, `{
		"routes": [{
			"host": "app.dev.test", "path": "/*", "frontend": true,
			"backend": "http://127.0.0.1:1",
			"uiGate": [{
				"selector": ".x",
				"claims": {"email": ["a@x", "b@x"]}
			}]
		}]
	}`)
	if err != nil {
		t.Fatal(err)
	}
	rule := cfg.Routes[0].UIGate[0]
	if got := rule.Claims["email"]; len(got) != 2 || got[1] != "b@x" {
		t.Fatalf("uiGate claims = %v", got)
	}
}
