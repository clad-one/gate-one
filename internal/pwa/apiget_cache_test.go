package pwa

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"cladone/gate-one/internal/core"
)

// method:"GET" on a declared endpoint => SWR route (cache answers
// instantly, network refreshes in the background), not the
// network-first replay.
func TestSWApiCacheMethodGET(t *testing.T) {
	pol := emptyPolicy()
	pol.ApiCaches = []*core.PWAApiCache{{Path: "/openapi.json", Method: "GET"}}
	sw := New(pol).swJS()

	for _, want := range []string{
		"url.pathname === '/openapi.json'",
		"StaleWhileRevalidate-like SWR marker absent", // see below
	} {
		_ = want // nothing: assertions below use dedicated checks
	}
	if !strings.Contains(sw, "workbox.routing.registerRoute(\n    ({url}) => url.pathname === '/openapi.json'") {
		t.Fatalf("GET route not generated:\n%s", sw)
	}
	if !strings.Contains(sw, "cache.match(req)") {
		t.Error("GET: cache.match(req) (key = URL alone) expected")
	}
	if !strings.Contains(sw, "'GET'\n  );") {
		t.Error("GET: route registered with method 'GET' expected")
	}
	if strings.Contains(sw, "storeCompleteResponse(cache, 'gate-one-pwa-api-openapi.json") {
		t.Error("GET: no storeCompleteResponse (no SSE tee/idle)")
	}
}

// Default: empty method = POST, unchanged behavior (replay).
func TestSWApiCacheMethodDefaultPOST(t *testing.T) {
	pol := emptyPolicy()
	pol.ApiCaches = []*core.PWAApiCache{{Path: "/api/process_stream"}}
	sw := New(pol).swJS()
	if !strings.Contains(sw, "'POST'\n  );") {
		t.Error("POST: route registered with method 'POST' expected")
	}
	if !strings.Contains(sw, "storeCompleteResponse") {
		t.Error("POST: storeCompleteResponse (tee/idle) expected")
	}
}

// apiGETCache present => GET catch-all registered last, excluding
// the virtual prefix, the declared paths and the declared excludes.
func TestSWApiGETCatchAll(t *testing.T) {
	pol := emptyPolicy()
	pol.ApiCaches = []*core.PWAApiCache{{Path: "/api/process_stream"}}
	pol.ApiGETCache = &core.PWAApiGETCache{Excludes: []string{"/api/auth/"}}
	sw := New(pol).swJS()

	// catch-all registered after the explicit routes
	iExplicit := strings.Index(sw, "url.pathname === '/api/process_stream'")
	iAll := strings.Index(sw, "gate-one-pwa-api-all-v")
	if iExplicit < 0 || iAll < 0 {
		t.Fatalf("expected routes missing: explicit=%d all=%d", iExplicit, iAll)
	}
	if iAll < iExplicit {
		t.Error("catch-all registered BEFORE the explicit route")
	}

	for _, want := range []string{
		"!url.pathname.startsWith('" + PathPrefix + "')",
		"!url.pathname.startsWith('/api/process_stream')",
		"!url.pathname.startsWith('/api/auth/')",
		"maxEntries: 200",
		"maxAgeSeconds: 86400",
		"purgeOnQuotaError: true",
	} {
		if !strings.Contains(sw, want) {
			t.Errorf("expected catch-all %q:\n%s", want, sw[iAll-200:])
		}
	}
}

// apiGETCache absent => no regression: no catch-all generated.
func TestSWApiGETCatchAllAbsent(t *testing.T) {
	sw := New(emptyPolicy()).swJS()
	if strings.Contains(sw, "gate-one-pwa-api-all-v") {
		t.Error("catch-all generated without apiGETCache")
	}
}

// Reconfiguring the catch-all does not invalidate the explicit
// endpoints' caches, and vice versa (per-block hashing, see versioning).
func TestApiGETCatchAllVersioning(t *testing.T) {
	pol1 := emptyPolicy()
	pol1.ApiGETCache = &core.PWAApiGETCache{}
	name1 := extractCatchAllName(New(pol1).swJS())

	pol2 := emptyPolicy()
	pol2.ApiGETCache = &core.PWAApiGETCache{Excludes: []string{"/x/"}}
	name2 := extractCatchAllName(New(pol2).swJS())

	if name1 == "" || name2 == "" {
		t.Fatalf("empty names: %q / %q", name1, name2)
	}
	if name1 == name2 {
		t.Errorf("changing excludes did not invalidate the catch-all: %q", name1)
	}

	// declared endpoint reconfigured: the catch-all keeps its name
	pol3 := emptyPolicy()
	pol3.ApiGETCache = &core.PWAApiGETCache{}
	pol3.ApiCaches = []*core.PWAApiCache{{Path: "/api/a"}}
	nA := extractCatchAllName(New(pol3).swJS())
	pol4 := emptyPolicy()
	pol4.ApiGETCache = &core.PWAApiGETCache{}
	pol4.ApiCaches = []*core.PWAApiCache{{Path: "/api/a", MaxEntries: 9}}
	nB := extractCatchAllName(New(pol4).swJS())
	if nA != nB {
		t.Errorf("reconfiguring an endpoint invalidated the catch-all: %q vs %q", nA, nB)
	}
}

func extractCatchAllName(sw string) string {
	marker := "caches.open('gate-one-pwa-api-all-"
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

// method "none": the path opts out of caching — no route
// generated for it, the catch-all ignores it (declared path = master).
func TestSWApiCacheMethodNone(t *testing.T) {
	pol := emptyPolicy()
	pol.ApiCaches = []*core.PWAApiCache{
		{Path: "/api/live", Method: "none"},
		{Path: "/api/poems", Method: "GET"},
	}
	pol.ApiGETCache = &core.PWAApiGETCache{}
	sw := New(pol).swJS()

	// no route for /api/live
	if strings.Contains(sw, "url.pathname === '/api/live'") {
		t.Error("method none: no route must be generated for the path")
	}
	if strings.Contains(sw, "gate-one-pwa-api-api-live-") {
		t.Error("method none: no dedicated cache must be created")
	}
	// the catch-all still excludes it (defense in depth if one day
	// the declared paths' exclusion changes shape)
	if !strings.Contains(sw, "!url.pathname.startsWith('/api/live')") {
		t.Error("method none: the path must remain excluded from the catch-all")
	}
	// the other endpoint works normally
	if !strings.Contains(sw, "url.pathname === '/api/poems'") {
		t.Error("method none: the neighboring endpoint must still be generated")
	}
	// case-insensitive
	pol2 := emptyPolicy()
	pol2.ApiCaches = []*core.PWAApiCache{{Path: "/api/x", Method: "NONE"}}
	sw2 := New(pol2).swJS()
	if strings.Contains(sw2, "url.pathname === '/api/x'") {
		t.Error("method NONE (uppercase) must also opt out")
	}
}

// excludePatterns: RegExps tested against the complete URL (pathname +
// query) — a particular parameter disqualifies the request.
func TestSWApiGETExcludePatterns(t *testing.T) {
	pol := emptyPolicy()
	pol.ApiGETCache = &core.PWAApiGETCache{
		ExcludePatterns: []string{"^https://x\\.test/api/poems\\?.*user=admin"},
	}
	sw := New(pol).swJS()

	wantRE := "const EXCLUDE_RE_0 = new RegExp('" + pol.ApiGETCache.ExcludePatterns[0] + "');"
	for _, want := range []string{
		wantRE,
		".test(url.href)",
	} {
		if !strings.Contains(sw, want) {
			t.Errorf("expected excludePatterns %q in:\n%s", want, sw)
		}
	}
	// several patterns => incremented indexes
	pol2 := emptyPolicy()
	pol2.ApiGETCache = &core.PWAApiGETCache{
		ExcludePatterns: []string{"/a/", "/b/"},
	}
	sw2 := New(pol2).swJS()
	if !strings.Contains(sw2, "EXCLUDE_RE_0") || !strings.Contains(sw2, "EXCLUDE_RE_1") {
		t.Error("several patterns expected (EXCLUDE_RE_0, EXCLUDE_RE_1)")
	}
	// no pattern => no declaration, match unchanged
	sw3 := New(emptyPolicy()).swJS()
	if strings.Contains(sw3, "EXCLUDE_RE_") {
		t.Error("no RegExp expected without excludePatterns")
	}
}

// Config load: invalid pattern => rejected at load (fail fast),
// no SW that would cache what should have been excluded.
func TestConfigRejectsInvalidExcludePattern(t *testing.T) {
	tmp := t.TempDir() + "/routes.json"
	cfg := `{"routes":[{"host":"x.test","path":"/*","backend":"http://b","pwa":{"enabled":true,"apiGETCache":{"excludePatterns":["([bad"]}}}]}` + "\n"
	if err := os.WriteFile(tmp, []byte(cfg), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := core.Load(tmp); err == nil {
		t.Fatal("config with invalid RegExp must be rejected at load")
	}
	// valid pattern accepted
	cfg2 := `{"routes":[{"host":"x.test","path":"/*","backend":"http://b","pwa":{"enabled":true,"apiGETCache":{"excludePatterns":["^https://x\\.test/api/poems\\?"]}}}]}` + "\n"
	if err := os.WriteFile(tmp, []byte(cfg2), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := core.Load(tmp); err != nil {
		t.Fatalf("valid pattern rejected: %v", err)
	}
}

// pwa.networkOnly declarative: the NetworkOnly route is generated
// from the config's patterns (no hard-coded filter — the gateway
// supports any authentication server). The production-shape patterns
// are anchored: Keycloak endpoints on the IdP origin, and a defensive
// callback guard on the app origin (the auth-bridge callback page has
// no SW and redirects clean, so the app anchor is belt-and-braces —
// patterns must never be generic: tested against the FULL url.href,
// `/auth` would already match `/authors/42`).
func TestSWNetworkOnlyGenerated(t *testing.T) {
	pol := emptyPolicy()
	pol.NetworkOnly = &core.PWANetworkOnlyPolicy{
		ExcludePatterns: []string{
			"^https://idp\\.test/realms/[^/?#]+/protocol/openid-connect",
			"^https://app\\.test/\\?[^#]*\\bcode=",
		},
	}
	sw := New(pol).swJS()

	if !strings.Contains(sw, "new workbox.strategies.NetworkOnly()") {
		t.Error("NetworkOnly route expected when networkOnly is declared")
	}
	for i, pat := range pol.NetworkOnly.ExcludePatterns {
		want := fmt.Sprintf("const NO_CACHE_RE_%d = new RegExp('%s');", i, pat)
		if !strings.Contains(sw, want) {
			t.Errorf("expected NO_CACHE_RE_%d: %q", i, want)
		}
		wantTest := fmt.Sprintf("NO_CACHE_RE_%d.test(url.href)", i)
		if !strings.Contains(sw, wantTest) {
			t.Errorf("full URL test expected: %q", wantTest)
		}
	}
}

// networkOnly absent => no NetworkOnly route, no NO_CACHE_RE.
func TestSWNetworkOnlyAbsent(t *testing.T) {
	sw := New(emptyPolicy()).swJS()
	if strings.Contains(sw, "NetworkOnly") {
		t.Error("no NetworkOnly route without a declared pwa.networkOnly")
	}
	if strings.Contains(sw, "NO_CACHE_RE") {
		t.Error("no exclusion RegExp without a declared pwa.networkOnly")
	}
}

// The registration order is authoritative: the networkOnly route must
// be REGISTERED BEFORE the assets route — workbox stops at the first
// matching route, and the OIDC callback page is a document
// (destination 'document') that the assets route would cache if it
// were consulted first.
func TestSWNetworkOnlyBeforeAssets(t *testing.T) {
	pol := emptyPolicy()
	pol.NetworkOnly = &core.PWANetworkOnlyPolicy{
		ExcludePatterns: []string{"^https://app\\.test/\\?[^#]*\\bcode="}}
	sw := New(pol).swJS()

	iNo := strings.Index(sw, "NO_CACHE_RE_0.test(url.href)")
	iAssets := strings.Index(sw, "request.destination === 'document'")
	if iNo < 0 || iAssets < 0 {
		t.Fatalf("routes attendues absentes: networkOnly=%d assets=%d", iNo, iAssets)
	}
	if iNo > iAssets {
		t.Error("networkOnly registered AFTER assets: a callback document would be cached by assets before the exclusion")
	}
}
