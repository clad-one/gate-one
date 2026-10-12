package pwa

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"cladone/gateway/internal/core"
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

	req := httptest.NewRequest(http.MethodGet, "/__gateway_pwa/manifest.json", nil)
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

	req := httptest.NewRequest(http.MethodGet, "/__gateway_pwa/manifest.json", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	body := rec.Body.String()
	if !strings.Contains(body, `"display": "standalone"`) {
		t.Errorf("manifest missing display standalone:\n%s", body)
	}
}

func TestServiceWorker(t *testing.T) {
	h := New(emptyPolicy())

	req := httptest.NewRequest(http.MethodGet, "/__gateway_pwa/sw.js", nil)
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
	if !strings.Contains(body, "modulePathPrefix: '/__gateway_pwa/workbox/'") {
		t.Error("sw.js must use the self-hosted modulePathPrefix")
	}
	if !strings.Contains(body, "NetworkOnly") {
		t.Error("sw.js must route auth traffic through NetworkOnly")
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
		"caches.open('gateway-pwa-api')",
		"storeCompleteResponse",
		"body.tee()",
		"cache.match(request)",
		"ExpirationPlugin",
		"maxEntries: 42",
		"maxAgeSeconds: 3600",
		"purgeOnQuotaError: true",
	} {
		if !strings.Contains(sw, want) {
			t.Errorf("sw.js apiCache missing %s in:\n%s", want, sw)
		}
	}
	// valeurs explicites
	if !strings.Contains(sw, "42 entrées max") || !strings.Contains(sw, "3600s") {
		t.Errorf("sw.js apiCache limits not rendered:\n%s", sw)
	}
}

func TestServiceWorkerApiCacheDefaults(t *testing.T) {
	pol := emptyPolicy()
	pol.ApiCache = &core.PWAApiCache{Path: "/api/x"}
	sw := New(pol).swJS()

	if !strings.Contains(sw, "50 entrées max") || !strings.Contains(sw, "86400s") {
		t.Errorf("apiCache defaults not applied:\n%s", sw)
	}
}

func TestServiceWorkerWithoutApiCache(t *testing.T) {
	sw := New(emptyPolicy()).swJS()
	if strings.Contains(sw, "gateway-pwa-api") {
		t.Errorf("apiCache route generated without policy:\n%s", sw)
	}
}

func TestWorkboxEmbedded(t *testing.T) {
	h := New(emptyPolicy())

	req := httptest.NewRequest(http.MethodGet, "/__gateway_pwa/workbox/workbox-sw.js", nil)
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

	req := httptest.NewRequest(http.MethodGet, "/__gateway_pwa/workbox/../pwa.go", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestUnknownPathNotFound(t *testing.T) {
	h := New(emptyPolicy())

	req := httptest.NewRequest(http.MethodGet, "/__gateway_pwa/whatever", nil)
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

	if !strings.Contains(s, `<link rel="manifest" href="/__gateway_pwa/manifest.json">`) {
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
