package pwa

import (
	"strings"
	"testing"

	"cladone/gateway/internal/core"
)

// extractApiCacheName returns the generated apiCache cache name from a
// generated SW body.
func extractApiCacheName(sw string) string {
	marker := "caches.open('gateway-pwa-api-"
	i := strings.Index(sw, marker)
	if i < 0 {
		return ""
	}
	rest := sw[i+len(marker):]
	j := strings.Index(rest, "'")
	if j < 0 {
		return ""
	}
	return rest[:j]
}

// Reconfiguring ONE endpoint only invalidates its own cache: the
// other endpoint keeps its name (and therefore its content), the
// assets caches too.
func TestApiCacheVersioningPerEndpoint(t *testing.T) {
	pol1 := emptyPolicy()
	pol1.ApiCaches = []*core.PWAApiCache{
		{Path: "/api/process_stream"},
		{Path: "/api/other"},
	}
	n1 := extractApiCacheName(New(pol1).swJS())

	// config change on another endpoint: process_stream keeps its
	// cache name
	pol2 := emptyPolicy()
	pol2.ApiCaches = []*core.PWAApiCache{
		{Path: "/api/process_stream"},
		{Path: "/api/other", MaxEntries: 99},
	}
	n2 := extractApiCacheName(New(pol2).swJS())
	if n1 == "" || n2 == "" {
		t.Fatalf("empty names: %q / %q", n1, n2)
	}
	if n1 != n2 {
		t.Errorf("reconfiguring /api/other invalidated /api/process_stream: %q vs %q", n1, n2)
	}

	// reconfiguring the endpoint itself changes its cache name
	pol3 := emptyPolicy()
	pol3.ApiCaches = []*core.PWAApiCache{
		{Path: "/api/process_stream", MaxEntries: 99},
		{Path: "/api/other", MaxEntries: 99},
	}
	n3 := extractApiCacheName(New(pol3).swJS())
	if n3 == n1 {
		t.Errorf("reconfiguring /api/process_stream did not invalidate its cache: %q", n3)
	}
}

// The API cache name no longer depends on the SW hash: a comment
// added to the SW (without a policy change) preserves the API cache
// name => the offline replay survives innocuous deployments.
func TestApiCacheNameStableAcrossSWChanges(t *testing.T) {
	pol := emptyPolicy()
	pol.ApiCaches = []*core.PWAApiCache{{Path: "/api/process_stream"}}
	sw1 := New(pol).swJS()

	// unrelated change: explicit assets strategy (changes the SW
	// text, hence its global hash, but not the apiCache policy)
	pol.Assets = &core.PWAAssetsPolicy{Strategy: "networkFirst"}
	sw2 := New(pol).swJS()

	if extractCacheVersion(sw1) == extractCacheVersion(sw2) {
		t.Skip("the global hash did not change — non-discriminating test")
	}
	if extractApiCacheName(sw1) != extractApiCacheName(sw2) {
		t.Errorf("API cache invalidated by an unrelated change:\n%q\nvs\n%q",
			extractApiCacheName(sw1), extractApiCacheName(sw2))
	}
}
