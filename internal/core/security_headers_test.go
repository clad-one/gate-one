package core

import (
	"os"
	"path/filepath"
	"testing"
)

func loadSecurityHeaders(t *testing.T, block string) (*Config, error) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "routes.json")
	cfg := `{"securityHeaders":` + block + `,
		"routes":[{"host":"a.local","path":"/*","backend":"http://app"}]}`
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	return Load(path)
}

// A declared block applies the secure defaults.
func TestSecurityHeadersDefaults(t *testing.T) {
	c, err := loadSecurityHeaders(t, `{}`)
	if err != nil {
		t.Fatal(err)
	}
	p := c.SecurityHeaders
	if p == nil {
		t.Fatal("block absent")
	}
	if got := p.HSTS(); got != "max-age=15552000" {
		t.Errorf("HSTS = %q", got)
	}
	if !p.NoSniffEnabled() {
		t.Error("nosniff off by default")
	}
	if got := p.Referrer(); got != "strict-origin-when-cross-origin" {
		t.Errorf("referrer = %q", got)
	}
}

// Absent block = no header at all (an edge proxy may own it).
func TestSecurityHeadersAbsent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "routes.json")
	cfg := `{"routes":[{"host":"a.local","path":"/*","backend":"http://app"}]}`
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.SecurityHeaders != nil {
		t.Error("absent block should stay nil")
	}
}

// Explicit values: 0 disables HSTS, empty referrer disables the
// header, includeSubDomains/preload are formatted.
func TestSecurityHeadersExplicit(t *testing.T) {
	c, err := loadSecurityHeaders(t, `{
		"hstsMaxAge": 0, "nosniff": false, "referrerPolicy": ""
	}`)
	if err != nil {
		t.Fatal(err)
	}
	p := c.SecurityHeaders
	if got := p.HSTS(); got != "" {
		t.Errorf("HSTS = %q, want empty (max-age 0)", got)
	}
	if p.NoSniffEnabled() {
		t.Error("nosniff should be off")
	}
	if got := p.Referrer(); got != "" {
		t.Errorf("referrer = %q, want empty", got)
	}

	c, err = loadSecurityHeaders(t, `{
		"hstsMaxAge": 31536000,
		"hstsIncludeSubDomains": true,
		"hstsPreload": true,
		"referrerPolicy": "no-referrer"
	}`)
	if err != nil {
		t.Fatal(err)
	}
	p = c.SecurityHeaders
	want := "max-age=31536000; includeSubDomains; preload"
	if got := p.HSTS(); got != want {
		t.Errorf("HSTS = %q, want %q", got, want)
	}
	if got := p.Referrer(); got != "no-referrer" {
		t.Errorf("referrer = %q", got)
	}
}

// A declared-but-broken block must refuse the load.
func TestSecurityHeadersValidation(t *testing.T) {
	bad := []string{
		`{"hstsMaxAge": -1}`,
		`{"hstsMaxAge": 63072001}`,
		`{"hstsPreload": true}`,
		`{"referrerPolicy": "sometimes"}`,
		`{"referrerPolicy": "no-referrer\r\nX-Evil: 1"}`,
	}
	for _, block := range bad {
		if _, err := loadSecurityHeaders(t, block); err == nil {
			t.Errorf("securityHeaders %s: acceptance expected to be refused", block)
		}
	}
}
