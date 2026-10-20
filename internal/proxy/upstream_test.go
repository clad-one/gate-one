package proxy

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// upstreamTestServer: echo backend simulating the essentials of a
// basic-auth-protected Cloudflare worker — exposes what it received
// (Host, Authorization, custom headers), knows how to redirect
// (absolute/relative Location via ?loc=) and serves HTML with a CSP.
//
// bigPageLen / hugePageLen / hugeGzPageLen: exact sizes of /big,
// /huge and /hugegz (filled in by the constructor for the
// assertions).
var (
	bigPageLen    int
	hugePageLen   int
	hugeGzPageLen int
)

func upstreamTestServer(t *testing.T) *httptest.Server {
	t.Helper()

	mux := http.NewServeMux()

	mux.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"host":            r.Host,
			"authorization":   r.Header.Get("Authorization"),
			"custom":          r.Header.Get("X-Custom"),
			"strip_present":   len(r.Header.Values("X-Strip-Me")) > 0,
			"accept-encoding": r.Header.Get("Accept-Encoding"),
		})
	})

	mux.HandleFunc("/redirect", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, r.URL.Query().Get("loc"), http.StatusFound)
	})

	mux.HandleFunc("/page", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte("<html><head></head><body>x</body></html>"))
	})

	// Image asset served WITHOUT Cache-Control (the no-heuristic
	// case browserCache covers) — the ?cc= query simulates an
	// origin MAKING its own declaration.
	mux.HandleFunc("/img", func(w http.ResponseWriter, r *http.Request) {
		if cc := r.URL.Query().Get("cc"); cc != "" {
			w.Header().Set("Cache-Control", cc)
		}
		w.Header().Set("Content-Type", "image/webp")
		_, _ = w.Write([]byte("IMAGEDATA"))
	})

	// Conditional image (ETag match): 304 without body.
	mux.HandleFunc("/img304", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/webp")
		w.WriteHeader(http.StatusNotModified)
	})

	// HTML served gzip (Content-Encoding: gzip) — simulates an
	// origin that compresses (Cloudflare does it systematically).
	mux.HandleFunc("/gz", func(w http.ResponseWriter, r *http.Request) {
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		_, _ = zw.Write([]byte(
			"<html><head><title>gz</title></head><body>gzip-ok</body></html>"))
		zw.Close()
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(buf.Bytes())
	})

	// "brotli" (arbitrary bytes): NEVER decodable by the stdlib —
	// the response must pass through intact, without injection.
	mux.HandleFunc("/br", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "br")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte{0x1b, 0x02, 0x00, 0x00, 0x00})
	})

	// JS asset served gzip: non-HTML, never touched by
	// decompression (compressed passthrough up to the browser).
	mux.HandleFunc("/app.gz.js", func(w http.ResponseWriter, r *http.Request) {
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		_, _ = zw.Write([]byte("console.log('gz');"))
		zw.Close()
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Type", "application/javascript")
		_, _ = w.Write(buf.Bytes())
	})

	// Page above the old limit (1 MiB): must be injected AND served
	// in full (jacquelot book: ~6 MB — its instrumentation is the
	// use case).
	bigBody := "<html><head><title>big</title></head><body>" +
		strings.Repeat("x", (3<<20)/2) + "</body></html>"
	bigPageLen = len(bigBody)
	mux.HandleFunc("/big", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(bigBody))
	})

	// Page with an early encoding declaration: the charset meta must
	// stay within the browser's detection window (first 1024
	// bytes) AFTER injection — the guard inserts itself after it,
	// not before (otherwise the browser decodes as windows-1252:
	// "DÃ©connexion").
	mux.HandleFunc("/meta", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte("<html><head>" +
			"<meta charset=\"utf-8\"><title>m</title></head>" +
			"<body>meta-ok</body></html>"))
	})

	// Page exceeding maxGuardBody (32 MiB): served IN FULL, without
	// injection or truncation (fail-open net).
	hugeBody := "<html><head><title>huge</title></head><body>" +
		strings.Repeat("y", (68<<20)/2) + "</body></html>"
	hugePageLen = len(hugeBody)
	mux.HandleFunc("/huge", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(hugeBody))
	})

	// HUGE gzip page (2 MB decompressed), served in chunks of the
	// gzip.Writer: the lazy gunzip + the streaming injection must
	// deliver it intact, injected, without buffering (the
	// gzip→guard→client PIPE stays bounded).
	plainHugeGz := "<html><head><title>huge-gz-title</title></head><body>" +
		strings.Repeat("g", 2<<20) + "</body></html>"
	hugeGzPageLen = len(plainHugeGz)
	mux.HandleFunc("/hugegz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Encoding", "gzip")
		zw := gzip.NewWriter(w)
		_, _ = zw.Write([]byte(plainHugeGz[:1000]))
		zw.Flush()
		_, _ = zw.Write([]byte(plainHugeGz[1000:]))
		zw.Close()
	})

	// Rewrite page (rewriteBody): plain HTML + gzip version.
	// The origin host cited in the page = r.Host (the host the
	// gateway imposes on the backend, host:port of the test server).
	mux.HandleFunc("/rwpage", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(rwPageHTML(r.Host)))
	})
	mux.HandleFunc("/rwgz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Encoding", "gzip")
		zw := gzip.NewWriter(w)
		_, _ = zw.Write([]byte(rwPageHTML(r.Host)))
		_ = zw.Close()
	})

	mux.HandleFunc("/setcookie", func(w http.ResponseWriter, r *http.Request) {
		// one raw Set-Cookie per ?set= parameter (rewriteCookies tests)
		for _, raw := range r.URL.Query()["set"] {
			w.Header().Add("Set-Cookie", raw)
		}
		w.WriteHeader(http.StatusNoContent)
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// rwPageHTML: rewrite page (rewriteBody) served by /rwpage —
// ABSOLUTE URLs of the origin site (rebuilt with the received host,
// the one the gateway imposes via upstream.host: host:port of the
// test origin), reading exceptions, alternative target, counter-
// examples (other hosts, boundaries).
func rwPageHTML(originHost string) string {
	return fmt.Sprintf(`<html><head><title>rw</title></head><body>
<a href="https://%[1]s/edit/page?x=1">edit</a>
<a href="https://%[1]s/lecture/bonpapa/">a string exception</a>
<a href="https://%[1]s/alt/chemin">alternative host</a>
<a href="https://%[1]s/l1/detail/ou">long alternative</a>
<a href="https://%[1]s/l1/autre">long exception kept</a>
<a href="//%[1]s/img.png">scheme-relative</a>
<a href="https://%[1]s/port">explicit port</a>
<a href="https://autre.example/x">other origin</a>
<a href="https://%[1]s.more/interieur">longer host</a>
<a href="wss://%[1]s/ws">websocket</a>
<img srcset="https://%[1]s/a.jpg 2x, //%[1]s/b.jpg 1x">
<style>body{background:url(https://%[1]s/fond.css)}</style>
<p>plain text: https://%[1]s/txt/fin — end of text</p>
</body></html>`, originHost)
}

// upstreamGateway: gateway built from a routes JSON (BACKEND
// replaced by the echo backend's URL), loaded via core.Load's strict
// grammar — as in production.
func upstreamGateway(
	t *testing.T,
	routesJSON string,
) (*Gateway, *url.URL) {
	t.Helper()
	clearAuthCache() // global cache: every test starts neutral

	srv := upstreamTestServer(t)

	routesJSON = strings.ReplaceAll(routesJSON, "BACKEND", srv.URL)
	cfg := loadForTest(t, routesJSON)

	gw, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}

	return gw, u
}

// doRequestWithHeaders: GET with the simulated client's headers.
func doRequestWithHeaders(
	t *testing.T,
	gw http.Handler,
	host, path string,
	headers map[string]string,
) *http.Response {
	t.Helper()

	req := httptest.NewRequest(http.MethodGet, "http://"+host+path, nil)
	req.Host = host
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)
	return rec.Result()
}

func echoOf(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("non-JSON echo: %s", string(b))
	}
	return out
}

// Historical default: without an upstream policy, the browser's
// public Host is preserved toward the backend (internal network).
func TestUpstreamDefaultPreservesPublicHost(t *testing.T) {
	gw, _ := upstreamGateway(t, `{
		"routes": [{
			"host": "public.test", "path": "/*",
			"backend": "BACKEND"
		}]
	}`)

	resp := doGet(t, gw, "public.test", "/echo")
	if got := echoOf(t, resp)["host"]; got != "public.test" {
		t.Errorf("Host upstream = %v, want public.test", got)
	}
}

// upstream.host: true → the Host sent to the backend is the one of
// its origin (required for an external site that routes by Host).
func TestUpstreamHostRewrite(t *testing.T) {
	gw, backend := upstreamGateway(t, `{
		"routes": [{
			"host": "public.test", "path": "/*", "frontend": true,
			"backend": "BACKEND",
			"upstream": {"host": true}
		}]
	}`)

	resp := doGet(t, gw, "public.test", "/echo")
	if got := echoOf(t, resp)["host"]; got != backend.Host {
		t.Errorf("Host upstream = %v, want %q", got, backend.Host)
	}
}

// hostOverride: explicit Host different from the backend and the
// public host (precedence over host).
func TestUpstreamHostOverride(t *testing.T) {
	gw, _ := upstreamGateway(t, `{
		"routes": [{
			"host": "public.test", "path": "/*",
			"backend": "BACKEND",
			"upstream": {"host": true, "hostOverride": "interne.svc:8000"}
		}]
	}`)

	resp := doGet(t, gw, "public.test", "/echo")
	if got := echoOf(t, resp)["host"]; got != "interne.svc:8000" {
		t.Errorf("Host upstream = %v, want interne.svc:8000", got)
	}
}

// Static headers: set with Set (overwrite the client — machine-to-
// machine mode), ${VAR} interpolation resolved at load, empty value
// = header removed from the request.
func TestUpstreamHeaders(t *testing.T) {
	t.Setenv("UPSTREAM_TEST_TOKEN", "c2VjcmV0")

	gw, _ := upstreamGateway(t, `{
		"routes": [{
			"host": "public.test", "path": "/*",
			"backend": "BACKEND",
			"upstream": {"headers": {
			  "Authorization": "Basic ${UPSTREAM_TEST_TOKEN}",
			  "X-Custom": "set-by-gateway",
			  "X-Strip-Me": ""
			}}
		}]
	}`)

	resp := doRequestWithHeaders(t, gw, "public.test", "/echo", map[string]string{
		"Authorization": "Bearer client-token",
		"X-Strip-Me":    "client-value",
	})
	echo := echoOf(t, resp)

	if got := echo["authorization"]; got != "Basic c2VjcmV0" {
		t.Errorf("Authorization upstream = %v, want Basic c2VjcmV0 (overwrites the client)", got)
	}
	if got := echo["custom"]; got != "set-by-gateway" {
		t.Errorf("X-Custom upstream = %v", got)
	}
	if got := echo["strip_present"]; got != false {
		t.Errorf("X-Strip-Me transmitted despite empty value: %v", got)
	}
}

// Without upstream.headers, the client's Authorization goes through
// as-is ("forward the source site's auth" mode).
func TestUpstreamForwardsClientAuthorization(t *testing.T) {
	gw, _ := upstreamGateway(t, `{
		"routes": [{
			"host": "public.test", "path": "/*",
			"backend": "BACKEND",
			"upstream": {"host": true}
		}]
	}`)

	resp := doRequestWithHeaders(t, gw, "public.test", "/echo", map[string]string{
		"Authorization": "Basic base64-client",
	})
	if got := echoOf(t, resp)["authorization"]; got != "Basic base64-client" {
		t.Errorf("client Authorization not forwarded: %v", got)
	}
}

// rewriteRedirects: absolute Locations targeting the backend's
// ORIGIN are brought back to the public host (https scheme,
// path/query preserved).
func TestUpstreamRewriteRedirects(t *testing.T) {
	gw, backend := upstreamGateway(t, `{
		"routes": [{
			"host": "public.test", "path": "/*", "frontend": true,
			"backend": "BACKEND",
			"upstream": {"host": true, "rewriteRedirects": true}
		}]
	}`)

	absolu := backend.Scheme + "://" + backend.Host + "/Correspondances/?a=1"
	resp := doGet(t, gw, "public.test", "/redirect?loc="+url.QueryEscape(absolu))
	if got := resp.Header.Get("Location"); got != "https://public.test/Correspondances/?a=1" {
		t.Errorf("Location = %q, want https://public.test/Correspondances/?a=1", got)
	}

	// Relative Location: goes through as-is.
	resp = doGet(t, gw, "public.test", "/redirect?loc="+url.QueryEscape("/relatif"))
	if got := resp.Header.Get("Location"); got != "/relatif" {
		t.Errorf("relative Location altered: %q", got)
	}

	// Location of ANOTHER origin (e.g. a Cloudflare Access team
	// domain): passes intact.
	resp = doGet(t, gw, "public.test", "/redirect?loc="+url.QueryEscape("https://equipe.cloudflareaccess.com/x"))
	if got := resp.Header.Get("Location"); got != "https://equipe.cloudflareaccess.com/x" {
		t.Errorf("Location of another origin altered: %q", got)
	}
}

// Without rewriteRedirects (default): an absolute Location goes
// through as-is — unchanged historical behavior.
func TestUpstreamRedirectsUntouchedByDefault(t *testing.T) {
	gw, backend := upstreamGateway(t, `{
		"routes": [{
			"host": "public.test", "path": "/*", "frontend": true,
			"backend": "BACKEND",
			"upstream": {"host": true}
		}]
	}`)

	absolu := backend.Scheme + "://" + backend.Host + "/ailleurs"
	resp := doGet(t, gw, "public.test", "/redirect?loc="+url.QueryEscape(absolu))
	if got := resp.Header.Get("Location"); got != absolu {
		t.Errorf("Location = %q, want %q (not rewritten)", got, absolu)
	}
}

// browserCache: an image served by the origin with NO Cache-Control
// (the book page case: no Last-Modified either — without it the
// browser validates on each view BEFORE caching... nothing at all)
// carries the freshness duration declared by the policy.
func TestUpstreamBrowserCacheImages(t *testing.T) {
	gw, _ := upstreamGateway(t, `{
		"routes": [{
			"host": "public.test", "path": "/*", "frontend": true,
			"backend": "BACKEND",
			"upstream": {"host": true,
			             "browserCache": {"imagesMaxAgeSeconds": 604800}}
		}]
	}`)

	resp := doGet(t, gw, "public.test", "/img")
	if got := resp.Header.Get("Cache-Control"); got != "private, max-age=604800" {
		t.Errorf("Cache-Control = %q, want %q", got, "private, max-age=604800")
	}
}

// The origin's own declaration wins: an already-present
// Cache-Control is never touched.
func TestUpstreamBrowserCacheRespectsOriginDeclaration(t *testing.T) {
	gw, _ := upstreamGateway(t, `{
		"routes": [{
			"host": "public.test", "path": "/*", "frontend": true,
			"backend": "BACKEND",
			"upstream": {"host": true,
			             "browserCache": {"imagesMaxAgeSeconds": 604800}}
		}]
	}`)

	resp := doGet(t, gw, "public.test", "/img?cc=max-age=9")
	if got := resp.Header.Get("Cache-Control"); got != "max-age=9" {
		t.Errorf("origin Cache-Control = %q, want untouched %q", got, "max-age=9")
	}
}

// Cautious semantics: HTML bodies and non-200 answers (conditional
// 304 here) never receive the header — the feature fills only the
// silence, for the browser's image resources.
func TestUpstreamBrowserCacheOnlyImagesAnd200s(t *testing.T) {
	gw, _ := upstreamGateway(t, `{
		"routes": [{
			"host": "public.test", "path": "/*", "frontend": true,
			"backend": "BACKEND",
			"upstream": {"host": true,
			             "browserCache": {"imagesMaxAgeSeconds": 604800}}
		}]
	}`)

	resp := doGet(t, gw, "public.test", "/page")
	if got := resp.Header.Get("Cache-Control"); got != "" {
		t.Errorf("HTML body: Cache-Control = %q, want absent", got)
	}

	resp = doGet(t, gw, "public.test", "/img304")
	if resp.StatusCode != http.StatusNotModified {
		t.Fatalf("304 status = %d", resp.StatusCode)
	}
	if got := resp.Header.Get("Cache-Control"); got != "" {
		t.Errorf("304: Cache-Control = %q, want absent", got)
	}
}

// Without the browserCache block (default): headers pass as-is,
// identical historical behavior.
func TestUpstreamBrowserCacheOffByDefault(t *testing.T) {
	gw, _ := upstreamGateway(t, `{
		"routes": [{
			"host": "public.test", "path": "/*", "frontend": true,
			"backend": "BACKEND",
			"upstream": {"host": true}
		}]
	}`)

	resp := doGet(t, gw, "public.test", "/img")
	if got := resp.Header.Get("Cache-Control"); got != "" {
		t.Errorf("default: Cache-Control = %q, want absent", got)
	}
}

// responseHeaders: remove (an origin CSP that would block the
// injected tags) and set (added/overwritten header).
func TestUpstreamResponseHeaders(t *testing.T) {
	gw, _ := upstreamGateway(t, `{
		"routes": [{
			"host": "public.test", "path": "/*", "frontend": true,
			"backend": "BACKEND",
			"upstream": {"responseHeaders": {
			  "remove": ["Content-Security-Policy"],
			  "set": {"X-Gate-One-Note": "instrumented"}
			}}
		}]
	}`)

	resp := doGet(t, gw, "public.test", "/page")
	if got := resp.Header.Get("Content-Security-Policy"); got != "" {
		t.Errorf("CSP not removed: %q", got)
	}
	if got := resp.Header.Get("X-Gate-One-Note"); got != "instrumented" {
		t.Errorf("X-Gate-One-Note = %q", got)
	}
}

// "Local site" parity: the guard script injection keeps applying to
// proxified HTML of an external site (upstream → guard chaining).
func TestUpstreamGuardStillInjected(t *testing.T) {
	gw, _ := upstreamGateway(t, `{
		"routes": [{
			"host": "public.test", "path": "/*", "frontend": true,
			"backend": "BACKEND",
			"upstream": {"host": true, "headers": {"Authorization": "Basic abc"}}
		}]
	}`)

	resp := doGet(t, gw, "public.test", "/page")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if b := body(t, resp); !strings.Contains(b, "__cladoneAuthGuard") {
		t.Error("guard script missing from the proxified HTML")
	}
}

// Multi-megabyte pages (the old 1 MiB limit, then the 6 MB book):
// injected AND served in full.
func TestGuardInjectsMidsizePageCompletely(t *testing.T) {
	gw, _ := upstreamGateway(t, `{
		"routes": [{
			"host": "public.test", "path": "/*", "frontend": true,
			"backend": "BACKEND",
			"upstream": {"host": true}
		}]
	}`)

	resp := doGet(t, gw, "public.test", "/big")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw[:2048]), "__cladoneAuthGuard") {
		t.Error("guard not injected on a 1.5 MiB page")
	}
	if len(raw) != bigPageLen+guardInjectedLen(t) {
		t.Errorf("body = %d bytes, want %d (injection + full page)",
			len(raw), bigPageLen+guardInjectedLen(t))
	}
	// unchanged: the end of the document is exactly the site's
	if !strings.HasSuffix(string(raw), "</body></html>") {
		t.Error("document tail altered")
	}
}

// guardInjectedLen: exact size of the script the route injects
// (same Sprintf as buildInjectors).
func guardInjectedLen(t *testing.T) int {
	t.Helper()
	gw, _ := upstreamGateway(t, `{
		"routes": [{
			"host": "public.test", "path": "/*", "frontend": true,
			"backend": "http://127.0.0.1:1"
		}]
	}`)
	route := gw.routes[0].route
	backend, err := url.Parse(route.Backend)
	if err != nil {
		t.Fatal(err)
	}
	script := fmt.Sprintf(
		guardScript,
		gw.config.LoginURLFor(route),
		AuthStatePath,
		uiGateJSON(route),
		userBadgeJSON(route),
		rewriteGuardJSON(route, backend),
		patchJSONFor(route),
	)
	return len(script)
}

// HUGE page (34 MiB, beyond the old 32 MiB buffering budget): served
// IN FULL and INJECTED — the injection is streaming, truncation is
// structurally impossible (no ReadAll anymore).
// len(stream) == page + script is THE net: one missing or duplicated
// byte breaks it.
func TestGuardStreamsHugePageWithoutTruncation(t *testing.T) {
	gw, _ := upstreamGateway(t, `{
		"routes": [{
			"host": "public.test", "path": "/*", "frontend": true,
			"backend": "BACKEND",
			"upstream": {"host": true}
		}]
	}`)

	resp := doGet(t, gw, "public.test", "/huge")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != hugePageLen+guardInjectedLen(t) {
		t.Errorf("body = %d bytes, want %d (34 MiB page: injection + full page)",
			len(raw), hugePageLen+guardInjectedLen(t))
	}
	if !strings.Contains(string(raw[:2048]), "__cladoneAuthGuard") {
		t.Error("guard not injected on the 34 MiB page")
	}
	if !strings.HasSuffix(string(raw), "</body></html>") {
		t.Error("document tail altered (truncation?)")
	}
}

// The site's charset meta stays within the detection window (first
// 1024 bytes) AFTER injection: the guard inserts itself AFTER it —
// the browser decodes the document with the right encoding.
func TestGuardInjectsAfterCharsetMeta(t *testing.T) {
	gw, _ := upstreamGateway(t, `{
		"routes": [{
			"host": "public.test", "path": "/*", "frontend": true,
			"backend": "BACKEND",
			"upstream": {"host": true}
		}]
	}`)

	resp := doGet(t, gw, "public.test", "/meta")
	b := body(t, resp)

	metaPos := strings.Index(b, "charset=")
	guardPos := strings.Index(b, "__cladoneAuthGuard")
	if metaPos < 0 || metaPos >= 1024 {
		t.Errorf("charset meta at %d, must stay < 1024", metaPos)
	}
	if guardPos < 0 {
		t.Fatal("guard missing")
	}
	if guardPos < metaPos {
		t.Errorf("guard (%d) injected BEFORE the charset meta (%d)",
			guardPos, metaPos)
	}
	if !strings.Contains(b, "meta-ok") {
		t.Error("site body altered")
	}
}

// The guard's JSON payload is 100 % ASCII (non-ASCII escaped
// \uXXXX, surrogate pairs beyond the BMP): an accented label from
// the config never becomes mojibake, whatever the encoding declared
// by the third-party site.
func TestGuardPayloadIsPureASCII(t *testing.T) {
	gw, _ := upstreamGateway(t, `{
		"routes": [{
			"host": "public.test", "path": "/*", "frontend": true,
			"backend": "BACKEND",
			"userBadge": {
			  "claims": ["preferred_username", "prénom"],
			  "logoutLabel": "Log out ☺"
			}
		}]
	}`)

	resp := doGet(t, gw, "public.test", "/page")
	b := body(t, resp)

	i := strings.Index(b, "var USERBADGE = ")
	if i < 0 {
		t.Fatal("USERBADGE payload missing")
	}
	j := strings.Index(b[i:], ";")
	payload := b[i : i+j]
	for k, r := range payload {
		if r > 0x7F {
			t.Errorf("non-ASCII payload at %d: %q", k, payload[k:])
		}
	}
	if !strings.Contains(payload, `\u263a`) {
		t.Errorf("☺ not escaped: %.120s", payload)
	}
}

// Gateway-side auth cache: N requests with the same cookies = ONE
// auth-bridge round-trip (the images of a heavy page must not pay
// auth on every call). Failures are not cached (a re-sign-in must
// work immediately).
func TestAuthCacheCollapsesBridgeCalls(t *testing.T) {
	oldTTL := authCacheTTL
	authCacheTTL = 5 * time.Second
	t.Cleanup(func() { authCacheTTL = oldTTL; clearAuthCache() })
	clearAuthCache()

	var calls int32
	bridge := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&calls, 1)
			w.Header().Set("X-User-Id", "u1")
			w.Header().Set("X-Username", "alice")
			w.WriteHeader(http.StatusOK)
		},
	))
	t.Cleanup(bridge.Close)

	srv := upstreamTestServer(t)
	routesJSON := `{
		"routes": [{
			"host": "public.test", "path": "/*", "frontend": true,
			"backend": "SRV",
			"auth": {}
		}]
	}`
	routesJSON = strings.ReplaceAll(routesJSON, "SRV", srv.URL)
	cfg := loadForTest(t, routesJSON)

	gw, err := New(cfg, WithAuthBridgeURL(bridge.URL))
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 5; i++ {
		resp := doRequestWithHeaders(t, gw, "public.test", "/echo",
			map[string]string{"Cookie": "access_token=tok"})
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("call %d: status = %d, want 200", i, resp.StatusCode)
		}
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Errorf("auth-bridge called %d times, want 1 (cache ineffective)", got)
	}

	// a failure is not cached: a NEW session (different cookie — a
	// refresh/relogin changes cookies, hence the key) must
	// re-consult the bridge, which refuses
	atomic.StoreInt32(&calls, 0)
	deny := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&calls, 1)
			w.WriteHeader(http.StatusUnauthorized)
		},
	))
	t.Cleanup(deny.Close)
	gw2, err := New(cfg, WithAuthBridgeURL(deny.URL))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		resp := doRequestWithHeaders(t, gw2, "public.test", "/echo",
			map[string]string{"Cookie": "access_token=tok2"})
		if resp.StatusCode != http.StatusFound {
			t.Fatalf("failure %d: status = %d, want 302", i, resp.StatusCode)
		}
	}
	if got := atomic.LoadInt32(&calls); got != 3 {
		t.Errorf("failures called %d times, want 3 (a failure got cached)", got)
	}
}

// rateLimit / quota: fixed window per identity (user otherwise IP)
// — the 3rd request of a window of 2 is refused 429 + Retry-After;
// ANOTHER identity keeps its own bucket; the When splits (requests
// outside the conditions consume nothing).
func TestRateLimitAndQuota(t *testing.T) {
	gw, _ := upstreamGateway(t, `{
		"routes": [{
			"host": "public.test", "path": "/*",
			"backend": "BACKEND",
			"rateLimit": {"requests": 2, "period": "minute"},
			"quota": {"limit": 4, "period": "hour"}
		}]
	}`)

	// first 2: pass (200 proxified), the 3rd: 429
	for i := 0; i < 2; i++ {
		resp := doRequestWithHeaders(t, gw, "public.test", "/echo",
			map[string]string{"X-Forwarded-For": "1.2.3.4"})
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("req %d: status = %d, want 200", i, resp.StatusCode)
		}
	}
	resp := doRequestWithHeaders(t, gw, "public.test", "/echo",
		map[string]string{"X-Forwarded-For": "1.2.3.4"})
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("req 3: status = %d, want 429", resp.StatusCode)
	}
	if ra := resp.Header.Get("Retry-After"); ra == "" {
		t.Error("429 without Retry-After")
	}

	// ANOTHER identity: its own bucket
	resp = doRequestWithHeaders(t, gw, "public.test", "/echo",
		map[string]string{"X-Forwarded-For": "5.6.7.8"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("other IP: status = %d, want 200", resp.StatusCode)
	}
}

// healthz + stats: gateway-served operations endpoints.
func TestHealthzAndStats(t *testing.T) {
	gw, _ := upstreamGateway(t, `{
		"routes": [{
			"host": "public.test", "path": "/*",
			"backend": "BACKEND"
		}]
	}`)

	resp := doGet(t, gw, "any.host.at.all", "/healthz")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("healthz: status = %d, want 200", resp.StatusCode)
	}
	if b := body(t, resp); !strings.Contains(b, `"ok"`) {
		t.Errorf("healthz body: %s", b)
	}

	doGet(t, gw, "public.test", "/echo")
	resp = doGet(t, gw, "any.host.at.all", "/__gate-one/stats")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("stats: status = %d, want 200", resp.StatusCode)
	}
	b := body(t, resp)
	if !strings.Contains(b, "authBridgeCalls") ||
		!strings.Contains(b, "public.test") {
		t.Errorf("incomplete stats: %s", b)
	}
}

// WEDGED auth-bridge (never answers): the gateway must not freeze
// — checkAuth times out (authBridgeClientTimeout) and the page route
// answers 302 login (2026-10-17 incident: auth-bridge in CPU
// busy-loop = all authenticated routes dead).
func TestHangingAuthBridgeTimesOut(t *testing.T) {
	old := authBridgeClientTimeout
	authBridgeClientTimeout = 300 * time.Millisecond
	t.Cleanup(func() { authBridgeClientTimeout = old })

	release := make(chan struct{})
	hang := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			<-release // never answers… except at cleanup
		},
	))
	// Server.Close waits for in-flight handlers: release them first.
	t.Cleanup(func() {
		close(release)
		hang.Close()
	})

	routesJSON := `{
		"routes": [{
			"host": "public.test", "path": "/*", "frontend": true,
			"backend": "BACKEND",
			"auth": {}
		}]
	}`

	// gateway with auth-bridge pointing at the hanging server:
	// manual construction (the helper points at its own stub).
	srv := upstreamTestServer(t)
	routesJSON = strings.ReplaceAll(routesJSON, "BACKEND", srv.URL)
	cfg := loadForTest(t, routesJSON)

	gw, err := New(cfg, WithAuthBridgeURL(hang.URL))
	if err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	resp := doGet(t, gw, "public.test", "/echo")
	elapsed := time.Since(start)

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want 302 (login) after timeout", resp.StatusCode)
	}
	if elapsed > 3*time.Second {
		t.Errorf("response in %v, want < 3s (timeout not applied)", elapsed)
	}
}

// The gateway auth (auth: {}) stays orthogonal to the upstream:
// without identity, the request is refused BEFORE reaching the
// backend (page route → 302 login, backend never contacted).
func TestUpstreamAuthStillEnforced(t *testing.T) {
	gw, _ := upstreamGateway(t, `{
		"routes": [{
			"host": "public.test", "path": "/*", "frontend": true,
			"backend": "BACKEND",
			"auth": {},
			"upstream": {"host": true}
		}]
	}`)

	// unreachable auth-bridge stub → auth failure → the page route
	// (frontend) answers 302 toward the login.
	resp := doGet(t, gw, "public.test", "/echo")
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want 302 (login redirect)", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); !strings.HasPrefix(loc, testLoginURL) {
		t.Errorf("Location = %q, want prefix %q", loc, testLoginURL)
	}
}

// --- Compression (2026-10-17 incident: Cloudflare answered brotli
// to the browser, the injector manipulated the compressed body →
// unreadable page despite a 200). ---

// Injectable route + gzip-answering origin: the browser receives
// PLAIN (decompressed) HTML, guard injected, Content-Encoding
// removed — whatever the browser offers.
func TestInjectableRouteServesPlainHTMLFromGzip(t *testing.T) {
	gw, _ := upstreamGateway(t, `{
		"routes": [{
			"host": "public.test", "path": "/*", "frontend": true,
			"backend": "BACKEND",
			"upstream": {"host": true}
		}]
	}`)

	resp := doRequestWithHeaders(t, gw, "public.test", "/gz", map[string]string{
		"Accept-Encoding": "gzip, deflate, br, zstd",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Encoding"); got != "" {
		t.Errorf("Content-Encoding survives: %q (unreadable page)", got)
	}
	b := body(t, resp)
	if !strings.Contains(b, "gzip-ok") {
		t.Errorf("HTML not decompressed: %.80q", b)
	}
	if !strings.Contains(b, "__cladoneAuthGuard") {
		t.Error("guard not injected on the decompressed gzip HTML")
	}
}

// Injectable route: the outgoing Accept-Encoding is FORCED to gzip
// (decodable by the stdlib — brotli/zstd are not), whatever the
// browser's offer.
func TestInjectableRouteForcesAcceptEncodingGzip(t *testing.T) {
	gw, _ := upstreamGateway(t, `{
		"routes": [{
			"host": "public.test", "path": "/*", "frontend": true,
			"backend": "BACKEND",
			"upstream": {"host": true}
		}]
	}`)

	resp := doRequestWithHeaders(t, gw, "public.test", "/echo", map[string]string{
		"Accept-Encoding": "br, zstd",
	})
	if got := echoOf(t, resp)["accept-encoding"]; got != "gzip" {
		t.Errorf("Accept-Encoding upstream = %v, want gzip", got)
	}
}

// NON-injectable route (API without guard/PWA): the client's
// Accept-Encoding goes through as-is (unchanged optimal
// passthrough).
func TestNonInjectedRouteKeepsClientAcceptEncoding(t *testing.T) {
	gw, _ := upstreamGateway(t, `{
		"routes": [{
			"host": "public.test", "path": "/*",
			"backend": "BACKEND"
		}]
	}`)

	resp := doRequestWithHeaders(t, gw, "public.test", "/echo", map[string]string{
		"Accept-Encoding": "br, zstd",
	})
	if got := echoOf(t, resp)["accept-encoding"]; got != "br, zstd" {
		t.Errorf("Accept-Encoding upstream = %v, want br, zstd (intact)", got)
	}
}

// Undecodable content (brotli that got past the forcing): the
// response passes INTACT — never manipulated compressed bytes, no
// guard injected into them.
func TestIndecodableEncodingPassthrough(t *testing.T) {
	gw, _ := upstreamGateway(t, `{
		"routes": [{
			"host": "public.test", "path": "/*", "frontend": true,
			"backend": "BACKEND",
			"upstream": {"host": true}
		}]
	}`)

	resp := doRequestWithHeaders(t, gw, "public.test", "/br", nil)
	if got := resp.Header.Get("Content-Encoding"); got != "br" {
		t.Errorf("Content-Encoding = %q, want br (intact)", got)
	}
	b := body(t, resp)
	if !strings.Contains(b, "__cladoneAuthGuard") {
		t.Logf("brotli body served as-is (guard absent, expected)")
	}
}

// Non-HTML asset served gzip: never decompressed — compressed
// passthrough up to the browser (Content-Encoding preserved).
func TestGzippedAssetPassthrough(t *testing.T) {
	gw, _ := upstreamGateway(t, `{
		"routes": [{
			"host": "public.test", "path": "/*", "frontend": true,
			"backend": "BACKEND",
			"upstream": {"host": true}
		}]
	}`)

	resp := doRequestWithHeaders(t, gw, "public.test", "/app.gz.js", map[string]string{
		"Accept-Encoding": "gzip, br",
	})
	if got := resp.Header.Get("Content-Encoding"); got != "gzip" {
		t.Errorf("Content-Encoding = %q, want gzip (asset intact)", got)
	}

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	zr, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("asset body is no longer valid gzip: %v", err)
	}
	dec, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(dec), "console.log('gz');") {
		t.Errorf("asset content corrupted: %.60q", dec)
	}
}

// Demo port: the client host carries a NON-STANDARD port — the
// rewritten Location must mirror scheme AND host:port (an https-only
// or port-less Location would throw the browser out of the proxy:
// nothing listens on 443/80 there).
func TestUpstreamRewriteRedirectsDemoPort(t *testing.T) {
	gw, backend := upstreamGateway(t, `{
		"routes": [{
			"host": "wikipedia.demo.localhost", "path": "/*",
			"frontend": true, "backend": "BACKEND",
			"upstream": {"host": true, "rewriteRedirects": true}
		}]
	}`)

	absolu := backend.Scheme + "://" + backend.Host + "/Correspondances/?a=1"
	// the direct-HTTP demo variant: NO X-Forwarded-Proto (doGet
	// simulates the prod ingress and forces https) — clientScheme
	// falls back to plain http, as in the real demo.
	resp := doRequestWithHeaders(t, gw, "wikipedia.demo.localhost:3000",
		"/redirect?loc="+url.QueryEscape(absolu), nil)
	if got := resp.Header.Get("Location"); got != "http://wikipedia.demo.localhost:3000/Correspondances/?a=1" {
		t.Errorf("Location = %q (status %d), want http://wikipedia.demo.localhost:3000/Correspondances/?a=1",
			got, resp.StatusCode)
	}
}

// Wildcard {lang}: one route, N sites — the expansion happened at
// load; the request path is the historical one: routing per expanded
// host, backend receiving ITS origin as Host, SSRF blocked (a label
// outside the allow-list has no route), rewriting mirroring the
// client origin (scheme + host:port).
func TestWildcardRoutingE2E(t *testing.T) {
	// ALIAS form: the capture stays out of the backend (one fixed
	// local backend, N hosts) — the whole e2e runs on the loopback,
	// no network. The BOUND form ({lang} in the backend) is covered
	// at string level by TestWildcardExpansion and live by the demo.
	gw, backend := upstreamGateway(t, `{
		"routes": [{
			"host": "{lang}.wild.test", "path": "/*",
			"backend": "BACKEND",
			"wildcard": {"lang": ["fr", "en"]},
			"frontend": true,
			"upstream": {"host": true, "rewriteRedirects": true,
			             "rewriteBody": {"enabled": true}}
		}]
	}`)

	// routing per expanded host
	resp := doGet(t, gw, "fr.wild.test:3000", "/echo")
	if got := echoOf(t, resp)["host"]; got != backend.Host {
		t.Errorf("backend Host = %v, want %v (upstream.host: true)", got, backend.Host)
	}

	// the OTHER expansion routes too (same route, same backend)
	resp = doGet(t, gw, "en.wild.test:3000", "/echo")
	if got := echoOf(t, resp)["host"]; got != backend.Host {
		t.Errorf("backend Host = %v, want %v", got, backend.Host)
	}

	// SSRF fail-closed: a label outside the allow-list has NO route
	resp = doGet(t, gw, "evil.wild.test:3000", "/echo")
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404 (fail-closed anti-SSRF)", resp.StatusCode)
	}

	// redirects: the rewritten Location mirrors the CLIENT origin
	// (scheme + host:port)
	absolu := backend.Scheme + "://" + backend.Host + "/Correspondances/?a=1"
	resp = doRequestWithHeaders(t, gw, "fr.wild.test:3000",
		"/redirect?loc="+url.QueryEscape(absolu), nil)
	if got := resp.Header.Get("Location"); got != "http://fr.wild.test:3000/Correspondances/?a=1" {
		t.Errorf("Location = %q, want http://fr.wild.test:3000/Correspondances/?a=1", got)
	}

	// the backend cites its own origin — rewritten to the client
	// origin (with port), the reader stays in the proxy (the
	// direct-HTTP demo variant: no X-Forwarded-Proto)
	html := body(t, doRequestWithHeaders(t, gw, "fr.wild.test:3000",
		"/rwpage", nil))
	if !strings.Contains(html, `href="http://fr.wild.test:3000/edit/page?x=1"`) {
		t.Errorf("captured-origin link not rewritten: %s", html)
	}
	// the documented traps stay intact: the longer-host decoy
	// (host:port.more) and the websocket scheme
	if !strings.Contains(html, `wss://`) {
		t.Errorf("websocket link altered: %s", html)
	}
}
