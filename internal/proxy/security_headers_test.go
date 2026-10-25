package proxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"cladone/gate-one/internal/core"
)

func intPtr(v int) *int       { return &v }
func boolPtr(v bool) *bool    { return &v }
func strPtr(v string) *string { return &v }

// The platform policy is applied to every response the gateway
// generates itself (health, stats, 404…).
func TestSecurityHeadersGeneratedResponses(t *testing.T) {
	gw, hosts := testGateway(t, `{
		"securityHeaders": {},
		"routes": [{
			"host": "sec.test", "path": "/*", "backend": "BACKEND"
		}]
	}`)

	for _, path := range []string{"/healthz", "/__gate-one/stats"} {
		resp := doGet(t, gw, hosts["sec.test"], path)
		if got := resp.Header.Get("X-Content-Type-Options"); got != "nosniff" {
			t.Errorf("%s: nosniff = %q", path, got)
		}
		if got := resp.Header.Get("Strict-Transport-Security"); got != "max-age=15552000" {
			t.Errorf("%s: HSTS = %q", path, got)
		}
		if got := resp.Header.Get("Referrer-Policy"); got != "strict-origin-when-cross-origin" {
			t.Errorf("%s: referrer = %q", path, got)
		}
	}
}

// …and to proxied responses, without duplicates.
func TestSecurityHeadersProxiedResponse(t *testing.T) {
	gw, hosts := testGateway(t, `{
		"securityHeaders": {"hstsMaxAge": 31536000},
		"routes": [{
			"host": "sec.test", "path": "/*", "frontend": true,
			"backend": "BACKEND"
		}]
	}`)

	resp := doGet(t, gw, hosts["sec.test"], "/")
	if got := resp.Header.Values("Strict-Transport-Security"); len(got) != 1 ||
		got[0] != "max-age=31536000" {
		t.Errorf("HSTS = %#v, want one max-age=31536000", got)
	}
	if got := resp.Header.Values("X-Content-Type-Options"); len(got) != 1 ||
		got[0] != "nosniff" {
		t.Errorf("nosniff = %#v", got)
	}
	if !strings.Contains(body(t, resp), "<html>") {
		t.Error("proxied body lost")
	}
}

// A proxified app's stricter Referrer-Policy wins; a conflicting
// backend copy of the other headers is overwritten (single value).
func TestSecurityWriterRespectsBackendReferrer(t *testing.T) {
	policy := &core.SecurityHeadersPolicy{}

	rec := httptest.NewRecorder()
	w := newSecurityWriter(rec, policy)

	// What ReverseProxy does before WriteHeader.
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "backend-value")
	w.WriteHeader(http.StatusOK)

	if got := rec.Header().Get("Referrer-Policy"); got != "no-referrer" {
		t.Errorf("backend referrer lost: %q", got)
	}
	if got := rec.Header().Values("X-Content-Type-Options"); len(got) != 1 ||
		got[0] != "nosniff" {
		t.Errorf("nosniff = %#v, want the platform value only", got)
	}
}

// Explicit disables: no header at all, and the writer is not even
// installed when the policy is empty.
func TestSecurityHeadersDisabled(t *testing.T) {
	p := &core.SecurityHeadersPolicy{
		HSTSMaxAge:     intPtr(0),
		NoSniff:        boolPtr(false),
		ReferrerPolicy: strPtr(""),
	}
	rec := httptest.NewRecorder()
	if w := newSecurityWriter(rec, p); w != http.ResponseWriter(rec) {
		t.Error("empty policy should not wrap the writer")
	}

	// nil policy: nothing.
	if w := newSecurityWriter(rec, nil); w != http.ResponseWriter(rec) {
		t.Error("nil policy should not wrap the writer")
	}
}

// Implicit WriteHeader (Write without WriteHeader) still finalizes the
// headers; a second WriteHeader is a no-op.
func TestSecurityWriterImplicitWriteHeader(t *testing.T) {
	w := newSecurityWriter(httptest.NewRecorder(), &core.SecurityHeadersPolicy{})
	if _, err := w.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	w.WriteHeader(http.StatusInternalServerError) // ignored, already written

	rec := w.(*securityWriter).ResponseWriter.(*httptest.ResponseRecorder)
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("nosniff = %q", got)
	}
}

// Flush finalizes the headers before forwarding (SSE responses keep
// working through the wrapper).
func TestSecurityWriterFlush(t *testing.T) {
	rec := httptest.NewRecorder()
	w := newSecurityWriter(rec, &core.SecurityHeadersPolicy{})

	f, ok := w.(http.Flusher)
	if !ok {
		t.Fatal("wrapper does not implement http.Flusher")
	}
	f.Flush()

	if !rec.Flushed {
		t.Error("underlying writer not flushed")
	}
	if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("headers not finalized before flush: %q", got)
	}
}
