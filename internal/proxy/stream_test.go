package proxy

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
)

// Test kit of the STREAMING injection refactor. Cornerstone: PARITY
// between the streaming decision and the historical buffered
// algorithm (a divergent insertion point = guard at the wrong place
// or nowhere — and the 2026-10-17 encoding/truncation incidents all
// have their root here).

// guardBufferedReference: EXACT replica of the buffered algorithm
// from before streaming (2026-10-18) — the parity reference.
func guardBufferedReference(body []byte, script string) string {
	var out []byte
	if idx := headOpen.FindIndex(body); idx != nil {
		injectAt := idx[1]
		sniff := body
		if len(sniff) > encodingSniffWindow {
			sniff = sniff[:encodingSniffWindow]
		}
		if m := charsetMeta.FindIndex(sniff); m != nil && m[1] > injectAt {
			injectAt = m[1]
		}
		out = append(out, body[:injectAt]...)
		out = append(out, []byte(script)...)
		out = append(out, body[injectAt:]...)
	} else {
		out = append([]byte(script), body...)
	}
	return string(out)
}

// sizedReader: at most n bytes per Read (1 = worst case: the
// <head> tag split IN THE MIDDLE of a Read — the stream must still
// land the exact insertion point; the old algorithm only ever saw
// whole bodies, never this chunking).
type sizedReader struct {
	src io.Reader
	n   int
}

func (r *sizedReader) Read(p []byte) (int, error) {
	if len(p) > r.n {
		p = p[:r.n]
	}
	return r.src.Read(p)
}

var streamCases = []string{
	"<html><head><title>t</title></head><body>x</body></html>",
	// charset meta placed AFTER <head> but within the window:
	// injection happens after IT (mojibake incident)
	"<html><head><meta charset=\"utf-8\"><title>t</title></head>" +
		"<body>meta-almost-early</body></html>",
	// no head at all: historical fallback (script at the top)
	"pas du html du tout",
	// multi-line head with attribute + meta behind it
	"<!DOCTYPE html>\n<html lang=\"fr\">\n<head data-x=\"1\">" +
		"<meta charset=\"utf-8\">suite",
	// head just before the end of the sniff window (1024)
	strings.Repeat("z", 995) + "<html><head>meta-late</head>",
	// head AFTER the sniff window but WITHIN the scan window:
	// the buffered algorithm searched <head> in the whole body and
	// injected after it — the stream must do exactly the same
	strings.Repeat("z", 4096) + "<html><head>late-head</head>",
	// page WITHOUT a head bigger than the scan window: fallback,
	// identical to the buffered one (it also prefixed)
	strings.Repeat("f", 70*1024),
	// page WITH a head much bigger than everything: decision around
	// byte 1024, the rest passes WITHOUT re-reading
	"<html><head><meta charset=\"utf-8\"><title>big</title></head>" +
		"<body>" + strings.Repeat("b", 300*1024) + "</body></html>",
}

func TestGuardStreamMatchesBufferedInjection(t *testing.T) {
	script := "<script>var GUARD=1;</script>"

	for ci, doc := range streamCases {
		want := guardBufferedReference([]byte(doc), script)
		for _, chunk := range []int{1, 2, 3, 4096, 64 << 10} {
			gs := newGuardStream(
				io.NopCloser(&sizedReader{
					src: strings.NewReader(doc),
					n:   chunk,
				}),
				script,
			)
			got, err := io.ReadAll(gs)
			if err != nil {
				t.Fatalf("case %d chunk %d: %v", ci, chunk, err)
			}
			if string(got) != want {
				t.Errorf(
					"case %d chunk %d: the stream diverges from the buffered algorithm",
					ci, chunk,
				)
			}
		}
	}
}

// head placed AFTER the scan window (malformed document): the
// stream falls back (script at the top) — DOCUMENTED DIVERGENCE
// from the buffered version (which searched head in the whole
// body), tested to stay aware of its existence; the document stays
// whole.
func TestGuardStreamHeadBeyondWindowFallsBack(t *testing.T) {
	script := "<script>var GUARD=2;</script>"
	doc := strings.Repeat("w", 70*1024) + "<html><head>very late</head>"

	gs := newGuardStream(
		io.NopCloser(&sizedReader{src: strings.NewReader(doc), n: 4096}),
		script,
	)
	got, err := io.ReadAll(gs)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(got), script) {
		t.Error("expected fallback: script at the top of the document")
	}
	// the whole document follows the script identically (never truncated)
	if !strings.HasSuffix(string(got), doc) {
		t.Error("the original body must follow the script identically")
	}
}

// decodeGzipBody streaming: the decompressed body comes out as it
// goes, whatever the origin's chunk sizes.
func TestGunzipStreamsHugeBody(t *testing.T) {
	plain := "<html><head><title>huge</title></head><body>" +
		strings.Repeat("g", 2<<20) + "</body></html>"

	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	if _, err := zw.Write([]byte(plain)); err != nil {
		t.Fatal(err)
	}
	zw.Close()

	resp := &http.Response{
		Header: http.Header{
			"Content-Encoding": {"gzip"},
			"Content-Length":   {strconv.Itoa(gz.Len())},
		},
		ContentLength: int64(gz.Len()),
		Body:          io.NopCloser(bytes.NewReader(gz.Bytes())),
	}
	if err := decodeGzipBody(resp); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if string(got) != plain {
		t.Errorf("decompressed body = %d bytes, want %d (damage?)",
			len(got), len(plain))
	}
	if resp.ContentLength != -1 ||
		resp.Header.Get("Content-Encoding") != "" ||
		resp.Header.Get("Content-Length") != "" {
		t.Error("gzip/Content-Length headers not cleaned — unreadable page")
	}
}

// End to end through the gateway: a HUGE gzip page (2 MB) is served
// DECOMPRESSED and INJECTED, intact, chunked — the lazy gunzip and
// the guardStream chain without buffering.
func TestGunzipAndGuardStreamHugePageThroughGateway(t *testing.T) {
	gw, _ := upstreamGateway(t, `{
		"routes": [{
			"host": "public.test", "path": "/*", "frontend": true,
			"backend": "BACKEND"
		}]
	}`)

	resp := doGet(t, gw, "public.test", "/hugegz")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != hugeGzPageLen+guardInjectedLen(t) {
		t.Errorf("body = %d bytes, want %d (gunzip + streaming injection)",
			len(raw), hugeGzPageLen+guardInjectedLen(t))
	}
	head := string(raw[:2048])
	if !strings.Contains(string(raw), "huge-gz-title") {
		t.Error("head content lost by the streaming gunzip")
	}
	if !strings.Contains(head, "__cladoneAuthGuard") {
		t.Error("guard not injected on the 2 MB gzip page")
	}
	if resp.Header.Get("Content-Length") != "" {
		t.Error("Content-Length must disappear on a streaming-injected page")
	}
}

// A transport error MID-STREAM (origin cut off): the bytes already
// written are served then the error is PROPAGATED — it is never
// silently swallowed (otherwise: a half-dead page with no trace on
// the gateway side).
func TestGuardStreamPropagatesTransportError(t *testing.T) {
	script := "<script>var GUARD=3;</script>"
	srcErr := io.ErrUnexpectedEOF
	// origin: serve 60 bytes of the head then an error
	head := "<html><head><title>t</title></head>"
	src := io.MultiReader(
		strings.NewReader(head),
		&errorReader{srcErr},
	)

	gs := newGuardStream(io.NopCloser(src), script)
	out, firstErr := io.ReadAll(gs)
	// ReadAll returns data + err: the error is propagated…
	if firstErr != srcErr {
		t.Fatalf("transport error swallowed: %v (want %v)", firstErr, srcErr)
	}
	// … and the arrived bytes hold everything in order: the scan
	// fallback (forced EOF) inserted the script after <head>.
	got := string(out)
	if !strings.HasPrefix(got, "<html><head>") ||
		!strings.HasSuffix(got, "<title>t</title></head>") {
		t.Errorf("origin bytes lost on transport error: %q", got)
	}
	if len(out) != len(head)+len(script) {
		t.Errorf("length = %d, want %d (badly served bytes)",
			len(out), len(head)+len(script))
	}
}

// errorReader: serves the error immediately — to force the
// error-mid-stream path of a guardStream.
type errorReader struct{ err error }

func (r *errorReader) Read(p []byte) (int, error) {
	return 0, r.err
}
