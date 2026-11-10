package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// A conditional request (If-None-Match) must still return the injected
// HTML: a 304 has no body, so the browser would reuse a cached copy
// without the guard/Turnstile script. The gateway asks for the full
// representation and drops the origin validators after injection.
func TestInjectionBypassesConditionalRequests(t *testing.T) {
	clearAuthCache()
	var sawConditional atomic.Bool

	backend := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("If-None-Match") != "" ||
				r.Header.Get("If-Modified-Since") != "" {
				sawConditional.Store(true)
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("ETag", `"v1"`)
			w.Header().Set("Last-Modified", "Wed, 21 Oct 2015 07:28:00 GMT")
			if r.Header.Get("If-None-Match") == `"v1"` {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			_, _ = io.WriteString(w, "<html><body>app</body></html>")
		}))
	t.Cleanup(backend.Close)

	cfg := loadForTest(t, `{
		"routes": [{
			"host": "app.test", "path": "/*", "frontend": true,
			"backend": "`+backend.URL+`"
		}]
	}`)
	gw, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = gw.Close() })

	req := httptest.NewRequest(http.MethodGet, "http://app.test/", nil)
	req.Host = "app.test"
	req.Header.Set("If-None-Match", `"v1"`)
	req.Header.Set("If-Modified-Since", "Wed, 21 Oct 2015 07:28:00 GMT")
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (304 would skip the injection)",
			rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "__cladoneAuthGuard") {
		t.Fatalf("guard not injected into the 200 body: %s", body)
	}
	if sawConditional.Load() {
		t.Fatal("the conditional headers reached the backend")
	}
	if got := rec.Header().Get("ETag"); got != "" {
		t.Fatalf("ETag = %q, want empty after body injection", got)
	}
	if got := rec.Header().Get("Last-Modified"); got != "" {
		t.Fatalf("Last-Modified = %q, want empty after body injection", got)
	}
}
