package proxy

import (
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"cladone/gateway/internal/core"
	"cladone/gateway/internal/pwa"
)

// Test rewrite policy: origin "origin.example" rewritten toward
// "https://public.test", exceptions covering the three verdicts:
// stay at the origin (string form), alternative host ({path,to}),
// and longest-prefix wins (/l1/detail long rule against /l1).
// Sort: longest prefix first (as after compilation).
func rewriteTestPlan() *rewritePlan {
	except := []core.RewriteExcept{
		{Path: "/lecture/bonpapa"},
		{Path: "/l1/detail", To: "https://deep.example"},
		{Path: "/l1"},
		{Path: "/alt", To: "https://alt.example"},
	}
	maxExcept := 0
	for _, e := range except {
		if len(e.Path) > maxExcept {
			maxExcept = len(e.Path)
		}
	}
	return &rewritePlan{
		origins:   []string{"origin.example"},
		pub:       "https://public.test",
		except:    except,
		hold:      len("https://") + len("origin.example"),
		maxExcept: maxExcept,
	}
}

// rewriteTestSpec: the same policy on the client SW side.
func rewriteTestSpec() *pwa.RewriteSpec {
	return rewriteTestPlan().clientSpec()
}

type rwCase struct {
	Name string
	// Input: HTML/text input; for SW parity: pure absolute URL.
	Input string
	// Expect = EXACT expected output; empty = the original text goes
	// through unmodified (no interception/rewrite).
	Expect string
}

// rewriteTextCases: shared list of semantics — the streaming engine
// (chunk sizes 1..4096 bytes), the independent buffered oracle and
// the SW JS (node harness, see rewrite_parity_harness.cjs) must
// produce EXACTLY the same output for these inputs.
func rewriteTextCases() []rwCase {
	return []rwCase{
		{
			Name:   "https simple",
			Input:  `<a href="https://origin.example/edit/page?x=1">edit</a>`,
			Expect: `<a href="https://public.test/edit/page?x=1">edit</a>`,
		},
		{
			Name:   "http simple rewritten to https",
			Input:  `<a href="http://origin.example/x">`,
			Expect: `<a href="https://public.test/x">`,
		},
		{
			Name:   "relative scheme",
			Input:  `<img src="//origin.example/img.png">`,
			Expect: `<img src="https://public.test/img.png">`,
		},
		{
			Name:  "string exception: stays at the origin",
			Input: `<a href="https://origin.example/lecture/bonpapa/ch1">l</a>`,
		},
		{
			Name:  "string exception with query",
			Input: `<a href="https://origin.example/lecture/bonpapa/fin?y=2">l</a>`,
		},
		{
			Name:   "{path,to} exception",
			Input:  `<a href="https://origin.example/alt/chemin">a</a>`,
			Expect: `<a href="https://alt.example/alt/chemin">a</a>`,
		},
		{
			Name:   "longest prefix wins (to)",
			Input:  `<a href="https://origin.example/l1/detail/ou">d</a>`,
			Expect: `<a href="https://deep.example/l1/detail/ou">d</a>`,
		},
		{
			Name:  "longest prefix wins (stayed at the origin)",
			Input: `<a href="https://origin.example/l1/autre">k</a>`,
		},
		{
			Name:   "explicit port: rewritten, port lost",
			Input:  `<a href="https://origin.example:4443/port">p</a>`,
			Expect: `<a href="https://public.test/port">p</a>`,
		},
		{
			Name:  "port + string exception: text as-is",
			Input: `<a href="https://origin.example:9/lecture/bonpapa">p</a>`,
		},
		{
			Name:  "other host: untouched",
			Input: `<a href="https://autre.example/x">a</a>`,
		},
		{
			Name:  "longer host (suffix): untouched",
			Input: `<a href="https://origin.example.more/interieur">m</a>`,
		},
		{
			Name:  "wss: untouched (left boundary)",
			Input: `<a href="wss://origin.example/ws">w</a>`,
		},
		{
			Name:  "word glued before the scheme: untouched",
			Input: `<a href="xhttps://origin.example/x">g</a>`,
		},
		{
			Name:   "srcset double",
			Input:  `<img srcset="https://origin.example/a.jpg 2x, //origin.example/b.jpg 1x">`,
			Expect: `<img srcset="https://public.test/a.jpg 2x, https://public.test/b.jpg 1x">`,
		},
		{
			Name:   "CSS url()",
			Input:  `body{background:url(https://origin.example/fond.css)}`,
			Expect: `body{background:url(https://public.test/fond.css)}`,
		},
		{
			Name:   "plain text",
			Input:  `<p>voir https://origin.example/txt/fin — suite</p>`,
			Expect: `<p>voir https://public.test/txt/fin — suite</p>`,
		},
		{
			Name:   "URL inside a query",
			Input:  `<a href="https://origin.example/api?u=https://origin.example/other">q</a>`,
			Expect: `<a href="https://public.test/api?u=https://public.test/other">q</a>`,
		},
		{
			Name:   "fragment",
			Input:  `<a href="https://origin.example/doc#ici">f</a>`,
			Expect: `<a href="https://public.test/doc#ici">f</a>`,
		},
		{
			Name:  "bare host without scheme: untouched",
			Input: `<p>voir origin.example/txt</p>`,
		},
	}
}

// rewriteReference: buffered oracle INDEPENDENT of the streaming
// engine — total context (never a window question), semantics
// described in rewrite.go, distinct implementation.
func rewriteReference(body []byte, plan *rewritePlan) string {
	var sb bytes.Buffer
	i := 0
	for i < len(body) {
		// first occurrence of an origin host; at equal index the
		// longest (mirror of findHost)
		h, hl := -1, 0
		for _, o := range plan.origins {
			j := bytes.Index(body[i:], []byte(o))
			if j < 0 {
				continue
			}
			j += i
			if h == -1 || j < h || (j == h && len(o) > hl) {
				h, hl = j, len(o)
			}
		}
		if h == -1 {
			sb.Write(body[i:])
			return sb.String()
		}

		// (scheme) form entirely present in body[i:h]
		formLen := 0
		switch {
		case h-8 >= i && string(body[h-8:h]) == "https://":
			formLen = 8
		case h-7 >= i && string(body[h-7:h]) == "http://":
			formLen = 7
		case h-2 >= i && string(body[h-2:h]) == "//":
			formLen = 2
		}
		if formLen == 0 {
			sb.Write(body[i : h+1])
			i = h + 1
			continue
		}
		formStart := h - formLen

		invalid := false
		if formLen == 2 {
			if formStart > 0 && !isRelBoundary(body[formStart-1]) {
				invalid = true
			}
		} else if formStart > 0 && isHostChar(body[formStart-1]) {
			invalid = true
		}

		// optional :digits port — included in the rewritten prefix,
		// absent from the replacements
		portEnd := h + hl
		if !invalid && portEnd < len(body) && body[portEnd] == ':' {
			k := portEnd + 1
			for k < len(body) && body[k] >= '0' && body[k] <= '9' {
				k++
			}
			if k == portEnd+1 {
				invalid = true // ':' without a digit (":/x")
			} else {
				portEnd = k
			}
		}
		if !invalid && portEnd < len(body) && isHostChar(body[portEnd]) {
			invalid = true // host that continues (a.b within a.b.c)
		}
		if invalid {
			sb.Write(body[i : h+1])
			i = h + 1
			continue
		}

		// exceptions: longest prefix wins (sorted upstream)
		keep, repl := false, plan.pub
		end := len(body)
		for j := portEnd; j < len(body); j++ {
			if isPathStop(body[j]) {
				end = j
				break
			}
		}
		for _, e := range plan.except {
			if len(e.Path) <= end-portEnd &&
				bytes.HasPrefix(body[portEnd:end], []byte(e.Path)) {
				if e.To != "" {
					repl = e.To
				} else {
					keep = true
				}
				break
			}
		}

		sb.Write(body[i:formStart])
		if keep {
			sb.Write(body[formStart:portEnd])
		} else {
			sb.WriteString(repl)
		}
		i = portEnd
	}
	return sb.String()
}

func rewriteStreamCase(t *testing.T, plan *rewritePlan, body []byte, chunk int) string {
	t.Helper()
	rs := newRewriteStream(
		io.NopCloser(&sizedReader{src: bytes.NewReader(body), n: chunk}),
		plan,
	)
	got, err := io.ReadAll(rs)
	if err != nil {
		t.Fatalf("stream (chunk %d): %v", chunk, err)
	}
	return string(got)
}

// The streaming engine must produce EXACTLY the oracle's output,
// whatever the read chunking (1 byte = worst case: the sliding
// window is exercised at every byte).
func TestRewriteStreamMatchesReference(t *testing.T) {
	plan := rewriteTestPlan()
	for _, c := range rewriteTextCases() {
		want := c.Expect
		if want == "" {
			want = c.Input
		}
		body := []byte(c.Input)
		if got := rewriteReference(body, plan); got != want {
			t.Errorf("oracle %q:\n got  %q\n want %q", c.Name, got, want)
			continue
		}
		for _, n := range []int{1, 2, 3, 5, 7, 8, 13, 33, 64, 4096} {
			if got := rewriteStreamCase(t, plan, body, n); got != want {
				t.Errorf(
					"stream %q (chunk %d):\n got  %q\n want %q",
					c.Name, n, got, want,
				)
			}
		}
	}
}

// Chaotic assemblies of cases: 1-byte chunks over the whole page
// (all semantics crossed within ONE stream, window always at the
// edge).
func TestRewriteStreamWholePageChunkOfOne(t *testing.T) {
	plan := rewriteTestPlan()
	var body bytes.Buffer
	for _, c := range rewriteTextCases() {
		body.WriteString(c.Input)
		body.WriteString("\n")
	}
	want := rewriteReference(body.Bytes(), plan)
	if got := rewriteStreamCase(t, plan, body.Bytes(), 1); got != want {
		t.Fatalf("chunk-1 stream:\n got  %q\n want %q", got, want)
	}
}

// Huge page sprinkled with origin URLs: delivered IN FULL and
// rewritten (one missing or duplicated byte breaks the exact length —
// like guardStream, truncation is structurally impossible).
func TestRewriteStreamsHugePageWithoutTruncation(t *testing.T) {
	plan := rewriteTestPlan()
	var body bytes.Buffer
	body.WriteString("<html><head><title>huge</title></head><body>")
	for i := 0; i < 20000; i++ {
		fmt.Fprintf(&body,
			`<a href="https://origin.example/p/%d">x</a>`, i)
	}
	body.WriteString("</body></html>")

	want := rewriteReference(body.Bytes(), plan)
	got := rewriteStreamCase(t, plan, body.Bytes(), 4096)
	if got != want {
		t.Fatalf("page %d bytes: got %d bytes (truncation?)",
			body.Len(), len(got))
	}
	if !strings.Contains(got, "https://public.test/p/19999") {
		t.Error("last URL not rewritten")
	}
}

// Transport error: propagated (never swallowed), per guardStream.
func TestRewriteStreamPropagatesTransportError(t *testing.T) {
	plan := rewriteTestPlan()
	boom := errors.New("boom transport")
	rs := newRewriteStream(io.NopCloser(&errorReader{boom}), plan)
	_, err := io.ReadAll(rs)
	if err != boom {
		t.Fatalf("err = %v, want %v", err, boom)
	}
}

// Data then transport error IN THE MIDDLE of a URL: the bytes
// already received go out RAW (a cut-off body must not be
// half-rewritten), then the error comes out (never swallowed).
func TestRewriteStreamRawFlushThenError(t *testing.T) {
	plan := rewriteTestPlan()
	boom := errors.New("cut")
	// Valid URL… cut in the middle of the host (< hold retained does
	// not change anything: the error forces the brutal emission)
	src := io.MultiReader(
		strings.NewReader(`<a href="https://origin.exa`),
		&errorReader{boom},
	)
	rs := newRewriteStream(io.NopCloser(src), plan)
	out, err := io.ReadAll(rs)
	if err != boom {
		t.Fatalf("err = %v, want %v", err, boom)
	}
	if string(out) != `<a href="https://origin.exa` {
		t.Errorf("pre-error bytes rewritten despite the cut: %q", string(out))
	}
}

// E2E through the full gateway (real JSON config, core.Load's strict
// grammar): the HTML page is rewritten (outside exceptions), the
// guard stays injected, Content-Length/Content-Encoding removed
// (chunked), and the gzip page is decompressed then rewritten.
func TestRewriteBodyGatewayE2E(t *testing.T) {
	gw, backend := upstreamGateway(t, `{
		"routes": [{
			"host": "public.test", "path": "/*", "frontend": true,
			"backend": "BACKEND",
			"upstream": {
				"host": true,
				"rewriteBody": {
					"enabled": true,
					"except": [
						"/lecture/bonpapa",
						{"path": "/alt", "to": "https://alt.example"},
						"/l1",
						{"path": "/l1/detail", "to": "https://deep.example"}
					]
				}
			}
		}]
	}`)
	backendHost := backend.Host // host:port imposed to the backend

	for _, path := range []string{"/rwpage", "/rwgz"} {
		resp := doGet(t, gw, "public.test", path)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: status = %d", path, resp.StatusCode)
		}
		b, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		s := string(b)

		if resp.ContentLength != -1 ||
			resp.Header.Get("Content-Length") != "" ||
			resp.Header.Get("Content-Encoding") != "" {
			t.Errorf("%s: CL=%d CE=%q — rewritten = plain chunked",
				path, resp.ContentLength, resp.Header.Get("Content-Encoding"))
		}
		if !strings.Contains(s, "__cladoneAuthGuard") {
			t.Errorf("%s: guard missing", path)
		}

		origin := "https://" + backendHost
		for _, want := range []string{
			`https://public.test/edit/page?x=1`, // standard rewrite
			origin + `/lecture/bonpapa/`,        // exception: origin
			`https://alt.example/alt/chemin`,    // {path,to}: path follows
			`https://deep.example/l1/detail/ou`, // /l1/detail (long)
			origin + `/l1/autre`,                // /l1 (short): origin
			`https://public.test/img.png`,       // //origin
			`https://public.test/port`,          // port lost
			`https://autre.example/x`,           // other host untouched
			origin + `.more/interieur`,          // suffix untouched
			`wss://` + backendHost + `/ws`,      // wss untouched
			`https://public.test/a.jpg 2x, https://public.test/b.jpg 1x`,
			`url(https://public.test/fond.css)`,
			`https://public.test/txt/fin`,
		} {
			if !strings.Contains(s, want) {
				t.Errorf("%s: missing %q", path, want)
			}
		}
		for _, not := range []string{
			origin + `/edit`,
			origin + `/alt/chemin`,
			origin + `/l1/detail`,
			backendHost + `/port`,
		} {
			if strings.Contains(s, not) {
				t.Errorf("%s: missed rewrite %q", path, not)
			}
		}
	}
}

// A JS asset is not rewritten (the client SW covers the runtime) nor
// decompressed (HTML decompression only): the zipped body passes
// identical, Content-Encoding included.
func TestRewriteJSAssetUntouched(t *testing.T) {
	// EXACT gzip bytes served by the origin
	buf := &bytes.Buffer{}
	zw := gzip.NewWriter(buf)
	_, _ = zw.Write([]byte("console.log('gz');"))
	_ = zw.Close()
	zipped := buf.Bytes()

	gw, _ := upstreamGateway(t, `{
		"routes": [{
			"host": "public.test", "path": "/*", "frontend": true,
			"backend": "BACKEND",
			"upstream": {"host": true, "rewriteBody": {"enabled": true}}
		}]
	}`)

	resp := doGet(t, gw, "public.test", "/app.gz.js")
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(body, zipped) {
		t.Errorf("JS body modified: %d bytes (want %d identical)",
			len(body), len(zipped))
	}
	if resp.Header.Get("Content-Encoding") != "gzip" {
		t.Errorf("Content-Encoding = %q, want gzip (passthrough)", resp.Header.Get("Content-Encoding"))
	}
}

// The rewrite SW is served PRE-AUTH (the SW must register before any
// session) with the policy embedded and the headers making
// registration possible from the root.
func TestRewriteServiceWorkerServed(t *testing.T) {
	gw, _ := upstreamGateway(t, `{
		"routes": [{
			"host": "public.test", "path": "/*", "frontend": true,
			"backend": "BACKEND",
			"upstream": {"host": true, "rewriteBody": {"enabled": true}}
		}]
	}`)

	resp := doGet(t, gw, "public.test", pwa.SwURL)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (SW served pre-auth)", resp.StatusCode)
	}
	s := body(t, resp)
	if resp.Header.Get("Content-Type") != "text/javascript; charset=utf-8" {
		t.Errorf("Content-Type = %q", resp.Header.Get("Content-Type"))
	}
	if resp.Header.Get("Cache-Control") != "no-cache" {
		t.Errorf("Cache-Control = %q, want no-cache (the SW re-checks)",
			resp.Header.Get("Cache-Control"))
	}
	if resp.Header.Get("Service-Worker-Allowed") != "/" {
		t.Errorf("Service-Worker-Allowed = %q, want /",
			resp.Header.Get("Service-Worker-Allowed"))
	}
	// the policy is embedded: target + BARE origin host (the payload
	// goes through its own SW without self-rewrite)
	if !strings.Contains(s, `"target":"https://public.test"`) ||
		!strings.Contains(s, `127.0.0.1`) {
		t.Error("rewrite policy missing from the served SW")
	}
}

// rewriteSWRequestCases: SW parity cases — REQUESTS (pure absolute
// URL, the material of a service worker). Voluntarily out of scope:
// an origin URL NESTED in the query (the SW rewrites the requested
// URL, not the text it carries — the server layer rewrites the HTML)
// and the bare origin without path (a request always has a path).
func rewriteSWRequestCases() []string {
	return []string{
		"https://origin.example/edit/page?x=1",
		"http://origin.example/x",
		"https://origin.example:4443/port",
		"https://origin.example/lecture/bonpapa/ch1",
		"https://origin.example/alt/chemin",
		"https://origin.example/l1/detail/ou",
		"https://origin.example/l1/autre",
		"https://autre.example/x",
		"https://origin.example.more/interieur",
		"https://origin.example/doc",
	}
}

// Go↔JS parity: the generated SW (node harness) applies the SAME
// policy as the Go reference on the same absolute requests.
func TestRewriteParityWithServiceWorkerJS(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node absent: SW parity skipped")
	}

	plan := rewriteTestPlan()
	cases := rewriteSWRequestCases()

	dir := t.TempDir()
	swPath := filepath.Join(dir, "sw.js")
	casesPath := filepath.Join(dir, "cases.txt")
	outPath := filepath.Join(dir, "results.txt")
	if err := os.WriteFile(swPath,
		[]byte(pwa.New(nil, rewriteTestSpec()).SwJS()), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(casesPath,
		[]byte(strings.Join(cases, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(node, "rewrite_parity_harness.cjs", swPath, casesPath, outPath)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if out, err := cmd.Output(); err != nil {
		t.Fatalf("node harness: %v\n%s\n%s", err, out, stderr.String())
	}
	raw, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	results := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(results) != len(cases) {
		t.Fatalf("%d results for %d cases:\n%s",
			len(results), len(cases), string(raw))
	}
	for i, u := range cases {
		got := results[i]
		if got == "NO-INTERCEPT" {
			got = u // not intercepted = the request passes as-is
		}
		want := rewriteReference([]byte(u), plan)
		if got != want {
			t.Errorf("SW %q: got %q want %q", u, got, want)
		}
	}
}

// DIRECT HTTP DEMO (no ingress, no X-Forwarded-Proto): origin URLs
// are rewritten to http:// — the scheme follows the real request,
// nothing is hardcoded.
func TestRewriteBodyGatewayE2EHTTPDemo(t *testing.T) {
	gw, _ := upstreamGateway(t, `{
		"routes": [{
			"host": "public.test", "path": "/*", "frontend": true,
			"backend": "BACKEND",
			"upstream": {"host": true, "rewriteBody": {"enabled": true}}
		}]
	}`)

	resp := doRequestWithHeaders(t, gw, "public.test", "/rwpage", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	b := readBody(t, resp)

	if !strings.Contains(b, "http://public.test/edit/page?x=1") {
		t.Error("rewrite expected in http:// (direct demo)")
	}
	// the LINKS point to http://; the guard's DTO (target=https://…
	// metadata) stays documentary — the SW/patch rewrite toward
	// their real origin at runtime
	if strings.Contains(b, `href="https://public.test`) ||
		strings.Contains(b, `url(https://public.test`) {
		t.Error("links must not be hardcoded https: request scheme")
	}
}
