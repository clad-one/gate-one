package pwa

import (
	"strings"
	"testing"

	"cladone/gate-one/internal/core"
)

// extractApiCacheName returns the generated apiCache cache name from a
// generated SW body.
func extractApiCacheName(sw string) string {
	marker := "caches.open('gate-one-pwa-api-"
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

// The "Cladone Gate One" rename changed the cache prefixes
// (gateway-pwa-* -> gate-one-pwa-*). Caches left in storage by a
// pre-rename service worker would never match the current-version
// filters: the activate handler must carry a delete-only legacy list
// and clear them unconditionally. Text-level regression: the
// generated SW must keep the LEGACY_PREFIXES constant and the
// unconditional filter clause (behavioral check: sw-sim).
func TestSWLegacyCachePurge(t *testing.T) {
	sw := New(emptyPolicy()).swJS()

	for _, want := range []string{
		// delete-only constant, pre-rename prefixes
		"const LEGACY_PREFIXES = ['gateway-pwa-'];",
		// unconditional deletion clause, evaluated FIRST
		"LEGACY_PREFIXES.some((p) => k.startsWith(p)) ||",
	} {
		if !strings.Contains(sw, want) {
			t.Errorf("legacy purge missing %s in:\n%s", want, sw)
		}
	}
	// sanity: the CURRENT prefixes replaced the old ones
	if strings.Contains(strings.ReplaceAll(sw, "LEGACY_PREFIXES = ['gateway-pwa-'];", ""),
		"'gateway-pwa-") {
		t.Error("a legacy prefix leaked outside LEGACY_PREFIXES (caches would be re-created)")
	}
}
