package proxy

import (
	"testing"

	"cladone/gate-one/internal/core"
)

// TestMatchUsageFiltersHost: a subscription can be scoped to a host or
// host glob, independently of the path (which matches on every host).
func TestMatchUsageFiltersHost(t *testing.T) {
	f := &core.UsageFilters{
		Hosts:   []string{"app.test", "*.wiki.test"},
		Routes:  []string{"/api/*"},
		Methods: []string{"POST"},
	}
	cases := []struct {
		host, path, method string
		want               bool
	}{
		{"app.test", "/api/x", "POST", true},
		{"APP.TEST", "/api/x", "POST", true}, // case-insensitive
		{"fr.wiki.test", "/api/x", "POST", true},
		{"other.test", "/api/x", "POST", false}, // path matches, host does not
		{"app.test", "/web/x", "POST", false},   // host matches, path does not
		{"app.test", "/api/x", "GET", false},
	}
	for _, c := range cases {
		got := matchUsageFilters(f, c.host, "", c.path, c.method, 0)
		if got != c.want {
			t.Errorf("match(host=%q path=%q method=%q) = %v, want %v",
				c.host, c.path, c.method, got, c.want)
		}
	}
}
