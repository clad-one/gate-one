package proxy

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"cladone/gate-one/internal/core"
)

// cspInject runs one injection on an HTML response, with the given
// nonce placed in the request context (as ServeHTTP does).
func cspInject(
	t *testing.T,
	csp *core.CSPPolicy,
	html, originPolicy, nonce string,
) (*http.Response, string) {
	t.Helper()

	req := httptest.NewRequest(http.MethodGet, "http://public.test/", nil)
	if nonce != "" {
		req = req.WithContext(
			context.WithValue(req.Context(), cspNonceKey{}, nonce))
	}

	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header: http.Header{
			"Content-Type": {"text/html; charset=utf-8"},
		},
		Body:    io.NopCloser(strings.NewReader(html)),
		Request: req,
	}
	if originPolicy != "" {
		resp.Header.Set("Content-Security-Policy", originPolicy)
	}

	inj := &cspInjector{
		policy: csp,
		hashes: inlineScriptHashes([]byte(`<script>gateOne()</script>`)),
	}
	if err := inj.modify(resp); err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp, string(b)
}

// nonce mode: inline scripts are stamped, external ones are not (a
// blind stamp would turn the policy into "trust everything").
func TestCSPNonceStampsInlineScriptsOnly(t *testing.T) {
	csp := &core.CSPPolicy{
		Mode:       "nonce",
		Directives: map[string]core.DirectiveSources{"default-src": {"'self'"}},
	}
	html := `<html><head>` +
		`<script>inline()</script>` +
		`<script src="/app.js"></script>` +
		`</head><body><script type="module">tail()</script></body></html>`

	resp, got := cspInject(t, csp, html, "", "NONCE123")

	if !strings.Contains(got, `<script nonce="NONCE123">inline()</script>`) {
		t.Errorf("inline script not stamped: %s", got)
	}
	if !strings.Contains(got, `<script type="module" nonce="NONCE123">tail()</script>`) {
		t.Errorf("tail script not stamped: %s", got)
	}
	if strings.Contains(got, `nonce="NONCE123" src=`) ||
		strings.Contains(got, `nonce="NONCE123"/app.js`) {
		t.Errorf("external script must stay unstamped: %s", got)
	}

	policy := resp.Header.Get("Content-Security-Policy")
	if !strings.Contains(policy, "'nonce-NONCE123'") {
		t.Errorf("policy lacks the nonce: %q", policy)
	}
	if strings.Contains(policy, "'unsafe-inline'") {
		t.Errorf("gateway added unsafe-inline: %q", policy)
	}
	if !strings.Contains(policy, "report-uri "+core.DefaultCSPReportPath) {
		t.Errorf("default report-uri absent: %q", policy)
	}
}

func TestCSPNonceAppendsToStyleSrc(t *testing.T) {
	csp := &core.CSPPolicy{
		Mode: "nonce",
		Directives: map[string]core.DirectiveSources{
			"default-src": {"'self'"},
			"style-src":   {"'self'"},
		},
	}
	resp, _ := cspInject(t, csp, `<style>x{}</style>`, "", "N")
	policy := resp.Header.Get("Content-Security-Policy")
	if !strings.Contains(policy, "style-src 'self' 'nonce-N'") {
		t.Errorf("style-src nonce absent: %q", policy)
	}
}

func TestCSPNonceStyleSrcElemWins(t *testing.T) {
	csp := &core.CSPPolicy{
		Mode: "nonce",
		Directives: map[string]core.DirectiveSources{
			"style-src":      {"'self'"},
			"style-src-elem": {"'none'"},
		},
	}
	resp, _ := cspInject(t, csp, `<style>x{}</style>`, "", "N")
	policy := resp.Header.Get("Content-Security-Policy")
	if !strings.Contains(policy, "style-src-elem 'none' 'nonce-N'") {
		t.Errorf("style-src-elem nonce absent: %q", policy)
	}
}

func TestCSPNonceScriptSrcElemWins(t *testing.T) {
	csp := &core.CSPPolicy{
		Mode: "nonce",
		Directives: map[string]core.DirectiveSources{
			"script-src":      {"'self'"},
			"script-src-elem": {"'none'"},
		},
	}
	resp, _ := cspInject(t, csp, `<script>x()</script>`, "", "N")
	policy := resp.Header.Get("Content-Security-Policy")
	if !strings.Contains(policy, "script-src-elem 'none' 'nonce-N'") {
		t.Errorf("script-src-elem nonce absent: %q", policy)
	}
}

// A JS string containing "<script" must not be rewritten: the state
// machine never scans a script body.
func TestCSPNonceDoesNotCorruptScriptBody(t *testing.T) {
	csp := &core.CSPPolicy{Mode: "nonce"}
	html := `<script>var s = "<script>"; guard();</script>`

	_, got := cspInject(t, csp, html, "", "N")

	if !strings.Contains(got, `var s = "<script>";`) {
		t.Errorf("script body corrupted: %s", got)
	}
	if strings.Count(got, "nonce=") != 1 {
		t.Errorf("expected exactly one stamped tag: %s", got)
	}
}

// A script that already carries a nonce (origin-managed) is left as-is.
func TestCSPNonceKeepsExistingNonce(t *testing.T) {
	csp := &core.CSPPolicy{Mode: "nonce"}
	html := `<script nonce="origin">origin()</script>`

	_, got := cspInject(t, csp, html, "", "OURS")

	if !strings.Contains(got, `<script nonce="origin">`) {
		t.Errorf("origin nonce overwritten: %s", got)
	}
	if strings.Contains(got, "OURS") {
		t.Errorf("body stamped despite an existing nonce: %s", got)
	}
}

// stampScripts "all": external scripts are stamped too (host list or
// 'strict-dynamic' then decides).
func TestCSPNonceStampAllIncludesExternal(t *testing.T) {
	csp := &core.CSPPolicy{Mode: "nonce", StampScripts: "all"}
	html := `<script src="/app.js"></script>`

	_, got := cspInject(t, csp, html, "", "N")

	if !strings.Contains(got, `<script src="/app.js" nonce="N">`) {
		t.Errorf("external script not stamped with stampScripts=all: %s", got)
	}
}

// hash mode: no nonce, no body rewrite, the gateway's own scripts are
// allow-listed by hash.
func TestCSPHashModeEmitsHashesWithoutTouchingBody(t *testing.T) {
	csp := &core.CSPPolicy{Mode: "hash"}
	html := `<script>inline()</script>`

	resp, got := cspInject(t, csp, html, "", "")

	if got != html {
		t.Errorf("body modified in hash mode: %s", got)
	}
	policy := resp.Header.Get("Content-Security-Policy")
	sum := sha256.Sum256([]byte("gateOne()"))
	want := "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
	if !strings.Contains(policy, want) {
		t.Errorf("gateway script hash absent: %q", policy)
	}
}

// merge mode: the origin policy is preserved and amended, no policy of
// our own is added.
func TestCSPMergePreservesOriginPolicy(t *testing.T) {
	csp := &core.CSPPolicy{Mode: "merge"}
	html := `<script>x()</script>`
	origin := "default-src 'self'; script-src 'none'; object-src 'none'"

	resp, got := cspInject(t, csp, html, origin, "")

	if got != html {
		t.Errorf("body modified in merge mode: %s", got)
	}
	values := resp.Header.Values("Content-Security-Policy")
	if len(values) != 1 {
		t.Fatalf("headers = %#v, want exactly the amended origin policy", values)
	}
	if !strings.Contains(values[0], "script-src 'none' 'sha256-") {
		t.Errorf("hash not appended to script-src: %q", values[0])
	}
	if !strings.Contains(values[0], "object-src 'none'") {
		t.Errorf("origin directive removed: %q", values[0])
	}
	if !strings.Contains(values[0], "default-src 'self'") {
		t.Errorf("origin directive removed: %q", values[0])
	}
}

// Two policies are enforced (the browser applies all of them): the
// gateway's policy is ADDED, never substituted for the origin's.
func TestCSPAddsSecondPolicy(t *testing.T) {
	csp := &core.CSPPolicy{Mode: "nonce", Directives: map[string]core.DirectiveSources{
		"script-src": {"'self'"},
	}}
	resp, _ := cspInject(t, csp, `<script>x()</script>`, "default-src 'self'", "N")
	values := resp.Header.Values("Content-Security-Policy")
	if len(values) != 2 {
		t.Fatalf("headers = %#v, want origin + gateway", values)
	}
}

// reportOnly: the non-enforcing header name, the origin's enforcing
// policy untouched (but amended).
func TestCSPReportOnlyHeader(t *testing.T) {
	csp := &core.CSPPolicy{Mode: "hash", ReportOnly: true}

	resp, _ := cspInject(t, csp, `<p>x</p>`, "", "")

	if resp.Header.Get("Content-Security-Policy") != "" {
		t.Error("enforcing header emitted in report-only mode")
	}
	if resp.Header.Get("Content-Security-Policy-Report-Only") == "" {
		t.Error("report-only header absent")
	}
}

// appendHashesToPolicy: the effective script directive wins
// (script-src-elem > script-src > default-src), and a policy that
// leaves scripts unrestricted is not touched.
func TestCSPAppendHashesTargets(t *testing.T) {
	h := []string{"'sha256-AAA'"}

	cases := []struct {
		name, policy, want string
	}{
		{
			"script-src-elem wins",
			"script-src 'self'; script-src-elem 'none'",
			"script-src 'self'; script-src-elem 'none' 'sha256-AAA'",
		},
		{
			"script-src",
			"script-src 'self'",
			"script-src 'self' 'sha256-AAA'",
		},
		{
			"default-src fallback",
			"default-src 'self'",
			"default-src 'self' 'sha256-AAA'",
		},
		{
			"no script directive: untouched",
			"frame-ancestors 'none'",
			"frame-ancestors 'none'",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := appendHashesToPolicy(c.policy, h); got != c.want {
				t.Errorf("got %q, want %q", got, c.want)
			}
		})
	}
}

// inlineScriptHashes: one hash per inline script, none for external
// ones, deterministic.
func TestCSPInlineScriptHashes(t *testing.T) {
	html := `<script>a()</script><script src="/x.js"></script>` +
		`<script type="module">b()</script><script></script>`

	got := inlineScriptHashes([]byte(html))
	if len(got) != 2 {
		t.Fatalf("hashes = %#v, want 2", got)
	}
	sum := sha256.Sum256([]byte("a()"))
	if got[0] != "'sha256-"+base64.StdEncoding.EncodeToString(sum[:])+"'" {
		t.Errorf("bad hash: %q", got[0])
	}
}

// chunkReader: returns at most n bytes per Read (chunk-boundary test).
type chunkReader struct {
	data []byte
	n    int
}

func (r *chunkReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	n := r.n
	if n > len(p) {
		n = len(p)
	}
	if n > len(r.data) {
		n = len(r.data)
	}
	copy(p, r.data[:n])
	r.data = r.data[n:]
	return n, nil
}

func (r *chunkReader) Close() error { return nil }

// The stamper must be independent of chunk boundaries (downstream
// flushes are arbitrary): byte-per-byte input yields the same document
// as a single chunk.
func TestCSPStampChunkBoundaries(t *testing.T) {
	html := `<html><head><script src="/a.js"></script>` +
		`<script>inline()</script></head>` +
		`<body><script>var s = "<script>";</script></body></html>`

	stamped := func(chunk int) string {
		s := newCSPStampStream(&chunkReader{data: []byte(html), n: chunk}, "N", false)
		out, err := io.ReadAll(s)
		if err != nil {
			t.Fatal(err)
		}
		return string(out)
	}

	whole, one := stamped(len(html)), stamped(1)
	if whole != one {
		t.Errorf("chunking changed the output:\nwhole=%s\none=%s", whole, one)
	}
	if !strings.Contains(whole, `<script nonce="N">inline()</script>`) {
		t.Errorf("inline not stamped: %s", whole)
	}
	if strings.Contains(whole, `nonce="N" src=`) {
		t.Errorf("external stamped: %s", whole)
	}
	if !strings.Contains(whole, `var s = "<script>";`) {
		t.Errorf("script body corrupted: %s", whole)
	}
}

// A truncated tag at EOF must not hang nor corrupt: served as-is.
func TestCSPStampTruncatedTag(t *testing.T) {
	s := newCSPStampStream(
		io.NopCloser(strings.NewReader(`<div><script`)), "N", false)
	out, err := io.ReadAll(s)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != `<div><script` {
		t.Errorf("truncated tag altered: %q", out)
	}
}

// Two responses never share a nonce.
func TestCSPNonceUnique(t *testing.T) {
	seen := make(map[string]bool, 256)
	for i := 0; i < 256; i++ {
		n := newCSPNonce()
		if n == "" {
			t.Fatal("empty nonce")
		}
		if seen[n] {
			t.Fatalf("nonce reused: %q", n)
		}
		seen[n] = true
	}
}

// ---------------------------------------------------------------------
// End-to-end through the gateway: nonce generation, guard stamping,
// gzip decode, collector.
// ---------------------------------------------------------------------

var cspNonceInHeader = regexp.MustCompile(`'nonce-([^']+)'`)

// The gateway generates the nonce in ServeHTTP, emits the policy, and
// the stamper (installed last) stamps the guard script it injected
// itself — no per-feature plumbing.
func TestCSPNonceEndToEnd(t *testing.T) {
	gw, hosts := testGateway(t, `{
		"routes": [{
			"host": "csp.test", "path": "/*", "frontend": true,
			"backend": "BACKEND",
			"csp": {"mode": "nonce", "directives": {"default-src": "'self'"}}
		}]
	}`)

	resp := doGet(t, gw, hosts["csp.test"], "/")
	policy := resp.Header.Get("Content-Security-Policy")

	m := cspNonceInHeader.FindStringSubmatch(policy)
	if m == nil {
		t.Fatalf("no nonce in the policy: %q", policy)
	}
	nonce := m[1]

	b := body(t, resp)
	if !strings.Contains(b, `nonce="`+nonce+`"`) {
		t.Errorf("body not stamped with the header nonce: %.200s", b)
	}
	if !strings.Contains(b, "__cladoneAuthGuard") {
		t.Error("guard script missing")
	}

	// The guard's own <script> is stamped (it is injected BEFORE the
	// stamper in the chain).
	if !regexp.MustCompile(`<script nonce="` + regexp.QuoteMeta(nonce) + `">`).MatchString(b) {
		t.Errorf("gateway-injected script not stamped: %.400s", b)
	}
}

// Two requests get two different nonces.
func TestCSPNonceRotates(t *testing.T) {
	gw, hosts := testGateway(t, `{
		"routes": [{
			"host": "csp.test", "path": "/*", "frontend": true,
			"backend": "BACKEND",
			"csp": {"mode": "nonce"}
		}]
	}`)

	nonceOf := func() string {
		resp := doGet(t, gw, hosts["csp.test"], "/")
		m := cspNonceInHeader.FindStringSubmatch(
			resp.Header.Get("Content-Security-Policy"))
		if m == nil {
			t.Fatal("no nonce")
		}
		return m[1]
	}

	if a, b := nonceOf(), nonceOf(); a == b {
		t.Errorf("nonce reused across requests: %q", a)
	}
}

// A gzip origin is DECODED before the stamper runs (otherwise the bytes
// would be scanned as text and corrupted).
func TestCSPNonceDecodesGzipUpstream(t *testing.T) {
	gw, _ := upstreamGateway(t, `{
		"routes": [{
			"host": "public.test", "path": "/*",
			"backend": "BACKEND",
			"csp": {"mode": "nonce"}
		}]
	}`)

	resp := doRequestWithHeaders(t, gw, "public.test", "/gz", map[string]string{
		"Accept-Encoding": "br, zstd, gzip",
	})
	if got := resp.Header.Get("Content-Encoding"); got != "" {
		t.Errorf("Content-Encoding survives: %q", got)
	}
	if b := body(t, resp); !strings.Contains(b, "gzip-ok") {
		t.Errorf("gzip body not decoded before stamping: %.80q", b)
	}
	if resp.Header.Get("Content-Security-Policy") == "" {
		t.Error("policy absent on the decoded response")
	}
}

// Non-HTML responses are never touched.
func TestCSPIgnoresNonHTML(t *testing.T) {
	csp := &core.CSPPolicy{Mode: "nonce"}
	req := httptest.NewRequest(http.MethodGet, "http://x/", nil)
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": {"application/json"}},
		Body:       io.NopCloser(strings.NewReader(`{"a":1}`)),
		Request:    req,
	}
	inj := &cspInjector{policy: csp}
	if err := inj.modify(resp); err != nil {
		t.Fatal(err)
	}
	if resp.Header.Get("Content-Security-Policy") != "" {
		t.Error("policy emitted on JSON")
	}
	if b, _ := io.ReadAll(resp.Body); string(b) != `{"a":1}` {
		t.Errorf("JSON body modified: %s", b)
	}
}

// Collector: a well-formed report is accepted (204) and kept in the
// bounded ring; wrong method and oversized body are refused.
func TestCSPReportCollector(t *testing.T) {
	resetCSPReports()
	t.Cleanup(resetCSPReports)

	gw, hosts := testGateway(t, `{
		"routes": [{
			"host": "csp.test", "path": "/*", "frontend": true,
			"backend": "BACKEND",
			"csp": {"mode": "nonce"}
		}]
	}`)

	post := func(body string) *http.Response {
		req := httptest.NewRequest(
			http.MethodPost,
			"http://csp.test"+core.DefaultCSPReportPath,
			strings.NewReader(body))
		req.Host = hosts["csp.test"]
		rec := httptest.NewRecorder()
		gw.ServeHTTP(rec, req)
		return rec.Result()
	}

	resp := post(`{"csp-report":{"document-uri":"https://csp.test/","effective-directive":"script-src","blocked-uri":"inline","line-number":12}}`)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("valid report: status = %d, want 204", resp.StatusCode)
	}

	reports := recentCSPReports()
	if len(reports) != 1 {
		t.Fatalf("reports = %d, want 1", len(reports))
	}
	if reports[0].Directive != "script-src" ||
		reports[0].Blocked != "inline" ||
		reports[0].Line != 12 ||
		reports[0].Document != "https://csp.test/" {
		t.Errorf("report parsed incorrectly: %+v", reports[0])
	}

	// Legacy violated-directive form ("script-src 'self'").
	if r := post(`{"violated-directive":"img-src 'self'"}`); r.StatusCode != http.StatusNoContent {
		t.Errorf("legacy report: status = %d", r.StatusCode)
	}
	if reports := recentCSPReports(); reports[len(reports)-1].Directive != "img-src" {
		t.Errorf("legacy directive not normalized: %+v", reports[len(reports)-1])
	}

	// Oversized body.
	big := `{"csp-report":{"blocked-uri":"` +
		strings.Repeat("x", cspReportMaxBody) + `"}}`
	if r := post(big); r.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("oversized report: status = %d, want 413", r.StatusCode)
	}

	// GET is refused.
	req := httptest.NewRequest(http.MethodGet,
		"http://csp.test"+core.DefaultCSPReportPath, nil)
	req.Host = hosts["csp.test"]
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET collector: status = %d, want 405", rec.Code)
	}
}

// The collector is bounded (ring), never unbounded memory.
func TestCSPReportRingBound(t *testing.T) {
	resetCSPReports()
	t.Cleanup(resetCSPReports)

	for i := 0; i < cspReportRing+40; i++ {
		recordCSPReport(cspReport{Directive: "script-src"})
	}
	if n := len(recentCSPReports()); n != cspReportRing {
		t.Errorf("ring holds %d entries, want %d", n, cspReportRing)
	}
}
