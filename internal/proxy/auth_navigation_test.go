package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// An unauthenticated fetch/XHR under a page route must receive the
// API 401 JSON, not the 302 to the login host: following the redirect
// cross-origin fails the CORS check and the application sees an opaque
// "Failed to fetch" instead of the guard's banner (which only reacts
// to 401).
func TestPageRouteFetchGets401NotRedirect(t *testing.T) {
	gw := devGateway(t, "http://127.0.0.1:1")

	req := httptest.NewRequest(
		http.MethodPost, "http://app.dev.test/api/process_stream",
		strings.NewReader("{}"))
	req.Host = "app.dev.test"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("fetch = %d, want 401", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "" {
		t.Fatalf("fetch got a redirect to %q", loc)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "json") {
		t.Errorf("Content-Type = %q, want JSON", ct)
	}
	body, _ := io.ReadAll(rec.Body)
	if !strings.Contains(string(body), "authentication_required") {
		t.Errorf("body = %q, want authentication_required", body)
	}
}

// A real navigation keeps the 302 to the login host.
func TestPageRouteNavigationRedirects(t *testing.T) {
	gw := devGateway(t, "http://127.0.0.1:1")

	req := httptest.NewRequest(http.MethodGet, "http://app.dev.test/", nil)
	req.Host = "app.dev.test"
	req.Header.Set("Accept", "text/html")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("navigation = %d, want 302", rec.Code)
	}
	if loc := rec.Header().Get("Location"); !strings.HasPrefix(
		loc, "http://login.dev.test:3000/login?returnTo=") {
		t.Fatalf("Location = %q", loc)
	}
}

// iframe/frame navigations are documents too.
func TestPageRouteIframeRedirects(t *testing.T) {
	gw := devGateway(t, "http://127.0.0.1:1")

	req := httptest.NewRequest(http.MethodGet, "http://app.dev.test/embed", nil)
	req.Host = "app.dev.test"
	req.Header.Set("Sec-Fetch-Dest", "iframe")
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("iframe = %d, want 302", rec.Code)
	}
}

// Legacy clients (curl, old browsers) send no Sec-Fetch-*: keep the
// historical redirect unless they explicitly ask for JSON/XHR.
func TestPageRouteLegacyClientRedirects(t *testing.T) {
	gw := devGateway(t, "http://127.0.0.1:1")

	req := httptest.NewRequest(http.MethodGet, "http://app.dev.test/", nil)
	req.Host = "app.dev.test"
	req.Header.Set("Accept", "*/*")
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("legacy = %d, want 302", rec.Code)
	}
}

func TestPageRouteXHRGets401(t *testing.T) {
	gw := devGateway(t, "http://127.0.0.1:1")

	req := httptest.NewRequest(
		http.MethodPost, "http://app.dev.test/api/process_stream",
		strings.NewReader("{}"))
	req.Host = "app.dev.test"
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("xhr = %d, want 401", rec.Code)
	}
}

func TestPageRouteJSONClientGets401(t *testing.T) {
	gw := devGateway(t, "http://127.0.0.1:1")

	req := httptest.NewRequest(http.MethodGet, "http://app.dev.test/api/state", nil)
	req.Host = "app.dev.test"
	req.Header.Set("Accept", "application/json")
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("json client = %d, want 401", rec.Code)
	}
}
