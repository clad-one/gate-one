package iam

import (
	"encoding/json"
	"reflect"
	"testing"
)

func rtWithRules(rules ...Rule) *tenantRuntime {
	return &tenantRuntime{cfg: Tenant{Rules: rules}}
}

func TestRuleMatchOperators(t *testing.T) {
	cases := []struct {
		op, got, want string
		ok            bool
	}{
		{"", "admins", "admins", true},
		{"exact", "admins", "admins", true},
		{"exact", "Admins", "admins", false},
		{"prefix", "team-support", "team-", true},
		{"suffix", "alice@example.com", "@example.com", true},
		{"domain", "alice@example.com", "example.com", true},
		{"domain", "alice@example.com", "@example.com", true},
		{"domain", "alice@other.com", "example.com", false},
		{"glob", "team-support", "team-*", true},
		{"glob", "team-support", "*-support", true},
		{"glob", "team-support", "team-?", false},
	}
	for _, c := range cases {
		if got := matchValue(c.got, c.want, c.op); got != c.ok {
			t.Errorf("matchValue(%q,%q,%q) = %v, want %v",
				c.got, c.want, c.op, got, c.ok)
		}
	}
}

func TestRuleDomainAndRolesFrom(t *testing.T) {
	rt := rtWithRules(Rule{
		When: []Condition{{Claim: "email", Match: "domain", Values: []string{"example.com"}}},
		Then: Then{
			Roles:     []string{"employee"},
			RolesFrom: []RolesFrom{{Claim: "groups", Transforms: []string{"keep:-:-1", "lower"}}},
		},
	})
	got := rt.ruleRights(map[string]any{
		"email":  "Alice@Example.com",
		"groups": []any{"team-Support", "team-Ops"},
	})
	want := []string{"employee", "support", "ops"}
	if !reflect.DeepEqual(got.Roles, want) {
		t.Fatalf("roles = %v, want %v", got.Roles, want)
	}
}

func TestRuleCopyClaims(t *testing.T) {
	rt := rtWithRules(Rule{
		When: []Condition{{Claim: "sub", Values: []string{"google-1"}}},
		Then: Then{CopyClaims: []CopyClaim{
			{From: "email", To: "email_domain", Transforms: []string{"keep:@:-1", "lower"}},
			{From: "groups"}, // same name, raw value preserved
		}},
	})
	got := rt.ruleRights(map[string]any{
		"sub":    "google-1",
		"email":  "Alice@Example.com",
		"groups": []any{"a", "b"},
	})
	if got.Claims["email_domain"] != "example.com" {
		t.Fatalf("email_domain = %v", got.Claims["email_domain"])
	}
	if !reflect.DeepEqual(got.Claims["groups"], []any{"a", "b"}) {
		t.Fatalf("groups = %v", got.Claims["groups"])
	}
}

func TestRuleAND(t *testing.T) {
	rt := rtWithRules(Rule{
		When: []Condition{
			{Claim: "email", Match: "domain", Values: []string{"example.com"}},
			{Claim: "groups", Values: []string{"support"}},
		},
		Then: Then{Roles: []string{"support-agent"}},
	})
	// Both conditions hold.
	got := rt.ruleRights(map[string]any{
		"email": "a@example.com", "groups": []any{"support", "x"},
	})
	if !reflect.DeepEqual(got.Roles, []string{"support-agent"}) {
		t.Fatalf("both: roles = %v", got.Roles)
	}
	// Only one holds -> no match.
	got = rt.ruleRights(map[string]any{
		"email": "a@other.com", "groups": []any{"support"},
	})
	if len(got.Roles) != 0 {
		t.Fatalf("one: roles = %v, want none", got.Roles)
	}
}

func TestKeepTransform(t *testing.T) {
	cases := []struct{ in, spec, want string }{
		{"a@b@c", "keep:@:0", "a"},
		{"a@b@c", "keep:@:1", "b"},
		{"a@b@c", "keep:@:-1", "c"},
		{"a@b@c", "keep:@:0:-2", "a@b"},
		{"a@b@c", "keep:@:1:", "b@c"},
		{"a@b@c", "keep:@:0:-1", "a@b@c"},
		{"a@b@c", "keep:@:0:9", "a@b@c"}, // to clamped
		{"a@b@c", "keep:@:5", ""},        // from out of range
		{"team-support", "keep:-:-1", "support"},
		{"alice@example.com", "keep:@:-1", "example.com"},
	}
	for _, c := range cases {
		if got := applyTransform(c.in, c.spec); got != c.want {
			t.Errorf("applyTransform(%q,%q) = %q, want %q",
				c.in, c.spec, got, c.want)
		}
	}
}

func TestRuleWhenParsesArray(t *testing.T) {
	var r Rule
	if err := json.Unmarshal([]byte(
		`{"when":[{"claim":"email","values":["x"]},{"claim":"sub","values":["y"]}],`+
			`"then":{"roles":["a"]}}`), &r); err != nil {
		t.Fatal(err)
	}
	if len(r.When) != 2 {
		t.Fatalf("conditions = %d, want 2", len(r.When))
	}
}

func TestRuleValidation(t *testing.T) {
	bad := []Rule{
		{Then: Then{Roles: []string{"a"}}}, // no when
		{When: []Condition{{Claim: "x", Match: "regex"}}, Then: Then{Roles: []string{"a"}}},
		{When: []Condition{{Claim: "x"}}, Then: Then{}}, // no grant
		{When: []Condition{{Claim: "x"}}, Then: Then{RolesFrom: []RolesFrom{{}}}},
		{When: []Condition{{Claim: "x"}}, Then: Then{
			CopyClaims: []CopyClaim{{From: "a", To: "sub"}}}}, // reserved target
		{When: []Condition{{Claim: "x"}}, Then: Then{
			RolesFrom: []RolesFrom{{Claim: "g", Transforms: []string{"nope"}}}}},
	}
	for i, r := range bad {
		if err := validateRules([]Rule{r}); err == nil {
			t.Errorf("case %d: expected an error", i)
		}
	}
	good := Rule{
		When: []Condition{{Claim: "email", Match: "domain", Values: []string{"x.com"}}},
		Then: Then{
			Roles:     []string{"employee"},
			RolesFrom: []RolesFrom{{Claim: "groups", Transforms: []string{"keep:-:-1", "lower"}}},
			CopyClaims: []CopyClaim{
				{From: "email", To: "email_domain", Transforms: []string{"keep:@:-1"}},
			},
		},
	}
	if err := validateRules([]Rule{good}); err != nil {
		t.Fatalf("valid rule rejected: %v", err)
	}
}
