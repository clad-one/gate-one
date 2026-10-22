package proxy

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func pathRewriteBackend(t *testing.T) *httptest.Server {
	t.Helper()

	mux := http.NewServeMux()
	var srv *httptest.Server

	mux.HandleFunc("/v1/redirect", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "/v1/next?x=1")
		w.WriteHeader(http.StatusFound)
	})
	mux.HandleFunc("/v1/redirect-relative", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "next?x=1")
		w.WriteHeader(http.StatusFound)
	})
	mux.HandleFunc("/v1/redirect-outside", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "/other")
		w.WriteHeader(http.StatusFound)
	})
	mux.HandleFunc("/v1/redirect-encoded", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "/v1/a%2Fb")
		w.WriteHeader(http.StatusFound)
	})
	mux.HandleFunc("/v1/redirect-abs", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", srv.URL+"/v1/next?x=1")
		w.WriteHeader(http.StatusFound)
	})
	mux.HandleFunc("/v1/headers", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Location", "/v1/here")
		w.Header().Set("Refresh", "5; url=/v1/refreshed")
		w.Header().Set("Link", `</v1/style.css>; rel=preload, </other/x>; rel=alternate`)
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/v1/cookie", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "sid", Value: "abc", Path: "/v1/sub", HttpOnly: true})
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/v1/html", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, `<!doctype html>
<html><head>
<base href="/v1/">
<link rel="stylesheet" href="/v1/style.css">
<meta http-equiv="refresh" content="0; url=/v1/next">
<style>.hero{background:url("/v1/bg2.png")}</style>
</head><body>
<a href="/v1/next">next</a>
<a href="relative">relative</a>
<a href="/api/already">already public</a>
<a href="https://other.example/v1/x">other</a>
<img src="/v1/img.png" srcset="/v1/a.png 1x, /v1/b.png 2x">
<script src="/v1/app.js"></script>
<form action="/v1/submit"></form>
<div style="background:url('/v1/bg.png')"></div>
</body></html>`)
	})
	mux.HandleFunc("/v1/json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"href":"/v1/next"}`))
	})
	mux.HandleFunc("/v1/gzhtml", func(w http.ResponseWriter, r *http.Request) {
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		_, _ = zw.Write([]byte(`<a href="/v1/next">next</a>`))
		_ = zw.Close()
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Content-Encoding", "gzip")
		_, _ = w.Write(buf.Bytes())
	})
	mux.HandleFunc("/plain", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<a href="/next">next</a> <a href="/api/already">already</a>`))
	})
	mux.HandleFunc("/redirect-root", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "/next")
		w.WriteHeader(http.StatusFound)
	})
	mux.HandleFunc("/cookie-root", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "root", Value: "1", Path: "/foo"})
		http.SetCookie(w, &http.Cookie{Name: "wide", Value: "1", Path: "/"})
		w.WriteHeader(http.StatusNoContent)
	})

	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestResponsePathRewriteHeaders(t *testing.T) {
	srv := pathRewriteBackend(t)
	gw := mustStripPrefixGateway(t, fmt.Sprintf(`{
		"routes": [{
			"host": "public.test", "path": "/api/*",
			"backend": %q, "stripPrefix": "/api"
		}]
	}`, srv.URL+"/v1"))

	cases := []struct {
		path string
		want string
	}{
		{"/api/redirect", "/api/next?x=1"},
		{"/api/redirect-relative", "next?x=1"},
		{"/api/redirect-outside", "/other"},
		{"/api/redirect-encoded", "/api/a%2Fb"},
		{"/api/redirect-abs", srv.URL + "/api/next?x=1"},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			resp := doGet(t, gw, "public.test", tc.path)
			if got := resp.Header.Get("Location"); got != tc.want {
				t.Errorf("Location = %q, want %q", got, tc.want)
			}
		})
	}

	resp := doGet(t, gw, "public.test", "/api/headers")
	if got := resp.Header.Get("Content-Location"); got != "/api/here" {
		t.Errorf("Content-Location = %q, want /api/here", got)
	}
	if got := resp.Header.Get("Refresh"); got != "5; url=/api/refreshed" {
		t.Errorf("Refresh = %q, want 5; url=/api/refreshed", got)
	}
	if got := resp.Header.Get("Link"); got != `</api/style.css>; rel=preload, </other/x>; rel=alternate` {
		t.Errorf("Link = %q", got)
	}

	resp = doGet(t, gw, "public.test", "/api/cookie")
	cookies := strings.Join(resp.Header.Values("Set-Cookie"), "\n")
	if !strings.Contains(cookies, "Path=/api/sub") {
		t.Errorf("cookie path not rewritten: %q", cookies)
	}
}

func TestResponsePathRewriteHTML(t *testing.T) {
	srv := pathRewriteBackend(t)
	gw := mustStripPrefixGateway(t, fmt.Sprintf(`{
		"routes": [{
			"host": "public.test", "path": "/api/*",
			"backend": %q, "stripPrefix": "/api"
		}]
	}`, srv.URL+"/v1"))

	resp := doGet(t, gw, "public.test", "/api/html")
	got := body(t, resp)

	want := []string{
		`<base href="/api/">`,
		`href="/api/style.css"`,
		`content="0; url=/api/next"`,
		`url("/api/bg2.png")`,
		`href="/api/next"`,
		`href="relative"`,
		`href="/api/already"`,
		`href="https://other.example/v1/x"`,
		`src="/api/img.png" srcset="/api/a.png 1x, /api/b.png 2x"`,
		`src="/api/app.js"`,
		`action="/api/submit"`,
		`url('/api/bg.png')`,
	}
	for _, w := range want {
		if !strings.Contains(got, w) {
			t.Errorf("HTML missing %q\n%s", w, got)
		}
	}

	// Non-HTML bodies are not touched (and stay valid JSON).
	resp = doGet(t, gw, "public.test", "/api/json")
	if got := body(t, resp); got != `{"href":"/v1/next"}` {
		t.Errorf("JSON body rewritten: %q", got)
	}

	// Gzip is decoded before the path rewrite (as for the other body
	// injectors), then stripped from the response.
	resp = doGet(t, gw, "public.test", "/api/gzhtml")
	got = body(t, resp)
	if !strings.Contains(got, `href="/api/next"`) {
		t.Errorf("gzip HTML path not rewritten: %q", got)
	}
	if enc := resp.Header.Get("Content-Encoding"); enc != "" {
		t.Errorf("Content-Encoding = %q after decode", enc)
	}
}

func TestResponsePathRewriteBackendRoot(t *testing.T) {
	srv := pathRewriteBackend(t)
	gw := mustStripPrefixGateway(t, fmt.Sprintf(`{
		"routes": [{
			"host": "public.test", "path": "/api/*",
			"backend": %q, "stripPrefix": "/api"
		}]
	}`, srv.URL))

	resp := doGet(t, gw, "public.test", "/api/plain")
	got := body(t, resp)
	if !strings.Contains(got, `href="/api/next"`) {
		t.Errorf("root-relative path not prefixed: %s", got)
	}
	if !strings.Contains(got, `href="/api/already"`) {
		t.Errorf("already-public path was prefixed twice: %s", got)
	}

	resp = doGet(t, gw, "public.test", "/api/redirect-root")
	if got := resp.Header.Get("Location"); got != "/api/next" {
		t.Errorf("Location = %q, want /api/next", got)
	}

	resp = doGet(t, gw, "public.test", "/api/cookie-root")
	cookies := strings.Join(resp.Header.Values("Set-Cookie"), "\n")
	if !strings.Contains(cookies, "Path=/api/foo") {
		t.Errorf("non-root cookie path not prefixed: %q", cookies)
	}
	if !strings.Contains(cookies, "Path=/;") && !strings.HasSuffix(cookies, "Path=/") {
		t.Errorf("root cookie path should stay /: %q", cookies)
	}
}

func TestResponsePathRewriteComposesWithUpstreamRedirects(t *testing.T) {
	srv := pathRewriteBackend(t)
	gw := mustStripPrefixGateway(t, fmt.Sprintf(`{
		"routes": [{
			"host": "public.test", "path": "/api/*",
			"backend": %q, "stripPrefix": "/api",
			"upstream": { "rewriteRedirects": true }
		}]
	}`, srv.URL+"/v1"))

	resp := doGet(t, gw, "public.test", "/api/redirect-abs")
	want := "https://public.test/api/next?x=1"
	if got := resp.Header.Get("Location"); got != want {
		t.Errorf("Location = %q, want %q", got, want)
	}
}
