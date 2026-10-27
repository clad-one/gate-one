package core

import (
	"os"
	"path/filepath"
	"testing"
)

// csp policy: directives accept the string and the array form, and the
// accessors resolve the defaults.
func TestCSPDeserialization(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "routes.json")
	cfg := `{
		"oidc": {"loginUrl": "http://login.test/login"},
		"routes": [{
			"host": "a.local", "path": "/*", "frontend": true,
			"backend": "http://app",
			"csp": {
				"mode": "nonce",
				"reportOnly": true,
				"stampScripts": "all",
				"directives": {
					"default-src": "'self'",
					"script-src": ["'self'", "'strict-dynamic'"],
					"connect-src": "'self' https://auth.cladone.com"
				}
			}
		}]
	}`
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}

	csp := c.Routes[0].CSP
	if csp == nil {
		t.Fatal("csp absent")
	}
	if csp.Mode != "nonce" || !csp.ReportOnly || !csp.Nonce() || !csp.StampsAll() {
		t.Errorf("policy = %+v", csp)
	}
	if !csp.Emits() {
		t.Error("nonce mode must emit a policy")
	}
	if csp.Header() != "Content-Security-Policy-Report-Only" {
		t.Errorf("header = %q", csp.Header())
	}
	if got := csp.Directives["script-src"]; len(got) != 2 || got[1] != "'strict-dynamic'" {
		t.Errorf("array form = %#v", got)
	}
	if got := csp.Directives["default-src"]; len(got) != 1 || got[0] != "'self'" {
		t.Errorf("string form = %#v", got)
	}
	if got := csp.Directives["connect-src"]; len(got) != 1 ||
		got[0] != "'self' https://auth.cladone.com" {
		t.Errorf("multi-source string = %#v", got)
	}
	if csp.Path() != DefaultCSPReportPath {
		t.Errorf("default report path = %q", csp.Path())
	}
}

// A mode typo must refuse the load, never silently disable the policy.
func TestCSPValidationMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "routes.json")

	for _, mode := range []string{"", "Nonce", "report", "enforce"} {
		cfg := `{"routes":[{"host":"a.local","path":"/*","backend":"http://app",` +
			`"csp":{"mode":"` + mode + `"}}]}`
		if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err == nil {
			t.Errorf("mode %q: acceptance expected to be refused", mode)
		}
	}
}

// reportOnly only makes sense when we emit a policy; stampScripts only
// in nonce mode; reportTo must be a local path.
func TestCSPValidationCombinations(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "routes.json")

	bad := []string{
		`{"mode":"merge","reportOnly":true}`,
		`{"mode":"hash","stampScripts":"all"}`,
		`{"mode":"nonce","reportTo":"https://evil.example/report"}`,
		`{"mode":"nonce","reportTo":"/a b"}`,
		`{"mode":"nonce","directives":{"bad name":"'self'"}}`,
		`{"mode":"nonce","directives":{"script-src":[]}}`,
		`{"mode":"nonce","directives":{"script-src":[""]}}`,
		`{"mode":"nonce","directives":{"script-src":["'self'\r\nX: y"]}}`,
	}

	for _, csp := range bad {
		cfg := `{"routes":[{"host":"a.local","path":"/*","backend":"http://app",` +
			`"csp":` + csp + `}]}`
		if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err == nil {
			t.Errorf("csp %s: acceptance expected to be refused", csp)
		}
	}
}

// off/merge/hash are valid without extra fields; merge emits nothing of
// its own.
func TestCSPMergeMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "routes.json")
	cfg := `{"routes":[{"host":"a.local","path":"/*","backend":"http://app",
		"csp":{"mode":"merge"}}]}`
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	csp := c.Routes[0].CSP
	if csp.Nonce() || csp.Emits() {
		t.Errorf("merge must not emit a policy of its own: %+v", csp)
	}
}

func TestCSPOwnValidation(t *testing.T) {
	for _, c := range []*CSPPolicy{
		{Mode: "off", Own: true},
		{Mode: "merge", Own: true},
		{Mode: "nonce", Own: true, ReportOnly: true},
	} {
		if err := validateCSP(c); err == nil {
			t.Errorf("policy %+v accepted, want refusal", c)
		}
	}
	if err := validateCSP(&CSPPolicy{Mode: "nonce", Own: true}); err != nil {
		t.Errorf("valid own policy refused: %v", err)
	}
}
