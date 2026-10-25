package proxy

// Security headers (HSTS, X-Content-Type-Options, Referrer-Policy):
// applied at WriteHeader time, on EVERY response the gateway serves —
// proxied or generated (health, stats, 401/403, MCP metadata, PWA
// assets, CSP collector). Applying them at the writer level is what
// makes the ownership unambiguous:
//
//   - HSTS and X-Content-Type-Options are SET, so a backend copy can
//     never produce a duplicate or contradict the platform policy;
//   - Referrer-Policy is only set when the response does not already
//     carry one: a proxified application that answers a stricter
//     value (e.g. no-referrer) keeps it — never weaken.

import (
	"net/http"

	"cladone/gate-one/internal/core"
)

type securityWriter struct {
	http.ResponseWriter
	hsts     string
	nosniff  bool
	referrer string
	wrote    bool
}

// newSecurityWriter: returns w unchanged when the policy is absent or
// empty (zero overhead on an install that delegates hardening to its
// edge).
func newSecurityWriter(
	w http.ResponseWriter,
	p *core.SecurityHeadersPolicy,
) http.ResponseWriter {

	if p == nil {
		return w
	}

	hsts := p.HSTS()
	nosniff := p.NoSniffEnabled()
	referrer := p.Referrer()

	if hsts == "" && !nosniff && referrer == "" {
		return w
	}

	return &securityWriter{
		ResponseWriter: w,
		hsts:           hsts,
		nosniff:        nosniff,
		referrer:       referrer,
	}
}

func (s *securityWriter) WriteHeader(code int) {

	if s.wrote {
		return
	}
	s.wrote = true

	header := s.ResponseWriter.Header()

	if s.nosniff {
		header.Set("X-Content-Type-Options", "nosniff")
	}
	if s.hsts != "" {
		header.Set("Strict-Transport-Security", s.hsts)
	}
	// Backend headers are already copied into this map by ReverseProxy
	// (copyHeader happens before WriteHeader): an application-declared
	// policy wins.
	if s.referrer != "" && header.Get("Referrer-Policy") == "" {
		header.Set("Referrer-Policy", s.referrer)
	}

	s.ResponseWriter.WriteHeader(code)
}

func (s *securityWriter) Write(b []byte) (int, error) {
	if !s.wrote {
		s.WriteHeader(http.StatusOK)
	}
	return s.ResponseWriter.Write(b)
}

// Flush keeps SSE working through the wrapper (the gateway streams
// /api/process_stream): headers are finalized before the first flush.
func (s *securityWriter) Flush() {
	if !s.wrote {
		s.WriteHeader(http.StatusOK)
	}
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap lets http.ResponseController reach the underlying writer
// (deadlines, flushing) — required by Go's ReverseProxy.
func (s *securityWriter) Unwrap() http.ResponseWriter { return s.ResponseWriter }
