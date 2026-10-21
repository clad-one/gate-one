package pwa

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"cladone/gate-one/internal/core"
)

func makePolicy() *core.PWAPolicy {
	return &core.PWAPolicy{
		Enabled:    true,
		Name:       "TestApp",
		ShortName:  "TA",
		ThemeColor: "#123456",
		Icons:      []string{"/icon-192.png", "/icon-512.png"},
	}
}

func emptyPolicy() *core.PWAPolicy {
	return &core.PWAPolicy{Enabled: true}
}

func TestManifest(t *testing.T) {
	h := New(makePolicy())

	req := httptest.NewRequest(http.MethodGet, "/__gate-one_pwa/manifest.json", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()

	for _, want := range []string{
		`"name": "TestApp"`,
		`"short_name": "TA"`,
		`"theme_color": "#123456"`,
		`"start_url": "/"`,
		`"src": "/icon-192.png"`,
		`"sizes": "192x192"`,
		`"src": "/icon-512.png"`,
		`"sizes": "512x512"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("manifest missing %s in:\n%s", want, body)
		}
	}
}

func TestManifestDefaults(t *testing.T) {
	h := New(emptyPolicy())

	req := httptest.NewRequest(http.MethodGet, "/__gate-one_pwa/manifest.json", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	body := rec.Body.String()
	if !strings.Contains(body, `"display": "standalone"`) {
		t.Errorf("manifest missing display standalone:\n%s", body)
	}
}

func TestServiceWorker(t *testing.T) {
	h := New(emptyPolicy())

	req := httptest.NewRequest(http.MethodGet, "/__gate-one_pwa/sw.js", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "text/javascript") {
		t.Errorf("content-type = %q", ct)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-cache" {
		t.Errorf("sw.js must not be cached, cache-control = %q", cc)
	}
	if swa := rec.Header().Get("Service-Worker-Allowed"); swa != "/" {
		t.Errorf("service-worker-allowed = %q, want /", swa)
	}

	body := rec.Body.String()
	if strings.Contains(body, "googleapis.com") {
		t.Error("sw.js must not reference googleapis.com (self-hosting required)")
	}
	if !strings.Contains(body, "modulePathPrefix: '/__gate-one_pwa/workbox/'") {
		t.Error("sw.js must use the self-hosted modulePathPrefix")
	}
	// No hard-coded auth exclusions: without a declared
	// pwa.networkOnly, the generated SW contains no NetworkOnly
	// route (the gateway supports any authentication server — the
	// choice is declarative).
	if strings.Contains(body, "NetworkOnly") {
		t.Error("sw.js must not hard-code auth exclusions (config-only)")
	}
}

func TestServiceWorkerRewriteTargets(t *testing.T) {
	h := New(nil, &RewriteSpec{
		Origins: []string{"origin.example"},
		Target:  "https://public.example",
		Targets: map[string]string{
			"fr.origin.example": "fr.public.example",
		},
	})

	body := h.swJS()
	if !strings.Contains(body, `"targets":{"fr.origin.example":"fr.public.example"}`) {
		t.Errorf("sw.js missing the targets map:\n%s", body)
	}
	if strings.Contains(body, `"siblings"`) {
		t.Error("sw.js still uses the old siblings key")
	}
	if !strings.Contains(body, "RW.targets") {
		t.Error("sw.js runtime does not read RW.targets")
	}
}

func TestServiceWorkerApiCache(t *testing.T) {
	pol := emptyPolicy()
	pol.ApiCache = &core.PWAApiCache{
		Path:          "/api/process_stream",
		MaxEntries:    42,
		MaxAgeSeconds: 3600,
	}
	h := New(pol)

	sw := h.swJS()

	for _, want := range []string{
		"url.pathname === '/api/process_stream'",
		// cache name suffixed by the SW version (hash)
		"caches.open('gate-one-pwa-api-api-process_stream-",
		"storeCompleteResponse",
		"body.tee()",
		"buildCacheKey",
		"cache.match(keyReq)",
		"ExpirationPlugin",
		"maxEntries: 42",
		"maxAgeSeconds: 3600",
		"maxEntrySizeBytes", // mention in the comment
		"1500",              // idleFinalizeMs default rendered in the SW
		"purgeOnQuotaError: true",
	} {
		if !strings.Contains(sw, want) {
			t.Errorf("sw.js apiCache missing %s in:\n%s", want, sw)
		}
	}
	// explicit values
	if !strings.Contains(sw, "42 entries max") || !strings.Contains(sw, "3600s") {
		t.Errorf("sw.js apiCache limits not rendered:\n%s", sw)
	}
}

func TestServiceWorkerApiCachesMultiple(t *testing.T) {
	pol := emptyPolicy()
	pol.ApiCaches = []*core.PWAApiCache{
		{Path: "/api/process_stream", MaxEntries: 10, MaxAgeSeconds: 600, MaxEntrySizeBytes: 1048576, IdleFinalizeMs: 3000},
		{Path: "/api/poems", MaxEntries: 200, MaxAgeSeconds: 604800},
	}
	sw := New(pol).swJS()

	for _, want := range []string{
		"url.pathname === '/api/process_stream'",
		"url.pathname === '/api/poems'",
		"maxEntries: 10",
		"maxEntries: 200",
		"maxAgeSeconds: 600",
		"3000", // idleFinalizeMs declared explicitly
		"1500", // default for the block that does not declare it
		"maxAgeSeconds: 604800",
		// default size per entry for the second block
		"2097152",
	} {
		if !strings.Contains(sw, want) {
			t.Errorf("sw.js multi-apiCache missing %s", want)
		}
	}
	// each endpoint its own cache (SW version suffix)
	if !strings.Contains(sw, "caches.open('gate-one-pwa-api-api-process_stream-") ||
		!strings.Contains(sw, "caches.open('gate-one-pwa-api-api-poems-") {
		t.Errorf("per-endpoint cache names missing:\n%s", sw)
	}
}

func TestServiceWorkerApiCacheDefaults(t *testing.T) {
	pol := emptyPolicy()
	pol.ApiCache = &core.PWAApiCache{Path: "/api/x"}
	sw := New(pol).swJS()

	if !strings.Contains(sw, "50 entries max") || !strings.Contains(sw, "86400s") {
		t.Errorf("apiCache defaults not applied:\n%s", sw)
	}
}

func TestServiceWorkerWithoutApiCache(t *testing.T) {
	sw := New(emptyPolicy()).swJS()
	// The activation purge filter mentions the api prefix, but
	// no API cache route must be generated.
	if strings.Contains(sw, "registerRoute(\n    ({url}) => url.pathname === '") {
		t.Errorf("apiCache route generated without policy:\n%s", sw)
	}
}

func TestServiceWorkerVersioning(t *testing.T) {
	sw := New(emptyPolicy()).swJS()

	for _, want := range []string{
		"const CACHE_VERSION = '", // injected hash
		"self.skipWaiting()",
		"addEventListener('activate'",
		"caches.delete(k)",
		// the placeholder must never survive generation
	} {
		if !strings.Contains(sw, want) {
			t.Errorf("sw.js versioning missing %s", want)
		}
	}
	if strings.Contains(sw, "@@CACHE_VERSION@@") {
		t.Error("CACHE_VERSION placeholder not substituted")
	}
}

// Any policy change (even a single field) must change the
// cache names => automatic purge at activation.
func TestServiceWorkerVersionChangesWithPolicy(t *testing.T) {
	sw1 := New(emptyPolicy()).swJS()

	pol := emptyPolicy()
	pol.ApiCaches = []*core.PWAApiCache{{Path: "/api/process_stream"}}
	sw2 := New(pol).swJS()

	v1 := extractCacheVersion(sw1)
	v2 := extractCacheVersion(sw2)
	if v1 == "" || v2 == "" {
		t.Fatalf("empty versions: %q / %q", v1, v2)
	}
	if v1 == v2 {
		t.Errorf("policy change did not change cache version: %q", v1)
	}

	// same policy => same version (cache preserved across deploys
	// without change)
	sw2b := New(pol).swJS()
	if extractCacheVersion(sw2b) != v2 {
		t.Errorf("identical policy changed cache version: %q vs %q", v2, extractCacheVersion(sw2b))
	}
}

// An apiCache's version field changes the endpoint's cache name
// AND the global version: the old entry is purged at activation.
func TestApiCacheVersionField(t *testing.T) {
	pol := emptyPolicy()
	pol.ApiCaches = []*core.PWAApiCache{{
		Path:    "/api/process_stream",
		Version: "morphalou",
	}}
	sw := New(pol).swJS()
	if !strings.Contains(sw, "gate-one-pwa-api-api-process_stream-morphalou-") {
		t.Errorf("apiCache version not in cache name:\n%s", sw)
	}

	pol2 := emptyPolicy()
	pol2.ApiCaches = []*core.PWAApiCache{{
		Path:    "/api/process_stream",
		Version: "morphalou-2",
	}}
	sw2 := New(pol2).swJS()
	if !strings.Contains(sw2, "gate-one-pwa-api-api-process_stream-morphalou-2-") {
		t.Errorf("bumped apiCache version missing:\n%s", sw2)
	}
	if extractCacheVersion(sw) == extractCacheVersion(sw2) {
		t.Error("apiCache version bump did not change global cache version")
	}
}

func extractCacheVersion(sw string) string {
	const marker = "const CACHE_VERSION = '"
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

func TestWorkboxEmbedded(t *testing.T) {
	h := New(emptyPolicy())

	req := httptest.NewRequest(http.MethodGet, "/__gate-one_pwa/workbox/workbox-sw.js", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "javascript") {
		t.Errorf("content-type = %q", ct)
	}
	if !strings.Contains(rec.Body.String(), "workbox") {
		t.Error("embedded workbox-sw.js looks empty")
	}
}

func TestWorkboxTraversalBlocked(t *testing.T) {
	h := New(emptyPolicy())

	req := httptest.NewRequest(http.MethodGet, "/__gate-one_pwa/workbox/../pwa.go", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestUnknownPathNotFound(t *testing.T) {
	h := New(emptyPolicy())

	req := httptest.NewRequest(http.MethodGet, "/__gate-one_pwa/whatever", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestInjectResponse(t *testing.T) {
	html := "<html><HEAD><title>t</title></HEAD><body>hi</body></html>"
	resp := &http.Response{
		StatusCode:    http.StatusOK,
		Header:        http.Header{"Content-Type": []string{"text/html; charset=utf-8"}},
		Body:          io.NopCloser(strings.NewReader(html)),
		ContentLength: int64(len(html)),
	}

	if err := InjectResponse(resp); err != nil {
		t.Fatalf("InjectResponse: %v", err)
	}

	got, _ := io.ReadAll(resp.Body)
	s := string(got)

	if !strings.Contains(s, `<link rel="manifest" href="/__gate-one_pwa/manifest.json">`) {
		t.Errorf("manifest link not injected:\n%s", s)
	}
	if !strings.Contains(s, "navigator.serviceWorker.register") {
		t.Errorf("SW registration not injected:\n%s", s)
	}
	// injection must land right after <HEAD> (case-insensitive)
	if !strings.Contains(s, "<HEAD><link") {
		t.Errorf("injection not right after <head>:\n%s", s)
	}
	if cl := resp.Header.Get("Content-Length"); cl != strconv.Itoa(len(s)) {
		t.Errorf("content-length = %q, want %d", cl, len(s))
	}
}

func TestInjectResponseSkipsNonHTML(t *testing.T) {
	html := "plain data"
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(html)),
	}

	if err := InjectResponse(resp); err != nil {
		t.Fatalf("InjectResponse: %v", err)
	}

	got, _ := io.ReadAll(resp.Body)
	if string(got) != html {
		t.Errorf("non-HTML body was modified: %q", string(got))
	}
}

func TestInjectResponseSkipsNon200(t *testing.T) {
	html := "<html><head></head></html>"
	resp := &http.Response{
		StatusCode: http.StatusNotFound,
		Header:     http.Header{"Content-Type": []string{"text/html"}},
		Body:       io.NopCloser(strings.NewReader(html)),
	}

	if err := InjectResponse(resp); err != nil {
		t.Fatalf("InjectResponse: %v", err)
	}

	got, _ := io.ReadAll(resp.Body)
	if string(got) != html {
		t.Errorf("non-200 body was modified: %q", string(got))
	}
}

func TestInjectResponseWithoutHead(t *testing.T) {
	html := "<p>no html structure</p>"
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"text/html"}},
		Body:       io.NopCloser(strings.NewReader(html)),
	}

	if err := InjectResponse(resp); err != nil {
		t.Fatalf("InjectResponse: %v", err)
	}

	got, _ := io.ReadAll(resp.Body)
	if string(got) != html {
		t.Errorf("body without <head> must be left untouched, got %q", string(got))
	}
}
