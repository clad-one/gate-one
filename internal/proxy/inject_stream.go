package proxy

// Insertion stream for CUSTOM injections (a route's bundle) — the
// guard's mechanics generalized to named targets. Two O(1) machines:
//
//   - "head" target (default): after <head> and after the charset
//     meta of the detection window — same decision as the guard, BUT
//     fail-open without a <head>: the snippet is skipped (custom
//     content must never precede <!doctype: none of the guard's
//     "everything at the top" fallback, which is infrastructure);
//   - "body-end" target: before </body> — the decision may land
//     after megabytes (the book): retention of a bounded tail (never
//     the whole body), the rest passes without re-reading; at EOF
//     without the marker the content goes out at the very end
//     (document without </body>).

import (
	"io"
	"net/http"
	"regexp"
	"strings"

	"cladone/gateway/internal/core"
)

var bodyCloseTag = regexp.MustCompile(`(?i)</body`)

// tailHold: bytes retained to detect a marker straddling the read
// boundary (</body> = 7 bytes).
const tailHold = 8

// newInjectStream: the insertion stream according to the target.
func newInjectStream(src io.ReadCloser, content, target string) io.ReadCloser {
	if target == "body-end" {
		return &tailInjectStream{
			src:     src,
			content: content,
			scratch: make([]byte, 4096),
		}
	}
	// "head" (default): early decision, guardStream mechanics —
	// without the "everything at the top" fallback: no head in the
	// window = snippet skipped (fail-open).
	return &guardStream{
		src:     src,
		script:  content,
		skipNF:  true, // no-head: skip, never a forced prefix
		scratch: make([]byte, 4096),
	}
}

// tailInjectStream: insertion before </body> — every chunk is
// scanned, only a compact tail is retained for markers straddling
// the read boundary. O(1) regardless of the page size.
type tailInjectStream struct {
	src     io.ReadCloser
	content string

	scratch  []byte
	tail     []byte // last tailHold bytes (straddling markers)
	pend     []byte // output pending emission
	pendOff  int
	inserted bool
	err      error
	eof      bool
}

func (t *tailInjectStream) Read(p []byte) (int, error) {

	for t.pendOff >= len(t.pend) {
		t.pend = t.pend[:0]
		t.pendOff = 0

		if t.eof {
			if t.err != nil {
				return 0, t.err
			}
			return t.src.Read(p)
		}

		n, rerr := t.src.Read(t.scratch)
		chunk := t.scratch[:n]
		if rerr != nil && rerr != io.EOF {
			if t.err == nil {
				t.err = rerr
			}
			t.eof = true
		}

		data := append(t.tail, chunk...)
		if rerr == io.EOF {
			t.eof = true
		}

		if idx := bodyCloseTag.FindIndex(data); idx != nil {
			// before </body>: the rest of the stream follows as-is
			t.pend = append(t.pend, data[:idx[0]]...)
			t.pend = append(t.pend, t.content...)
			t.pend = append(t.pend, data[idx[0]:]...)
			t.inserted = true
			t.tail = nil
			// the rest of src is relayed without re-reading
			t.eof = true
			t.pendOff = 0
			break
		}

		if t.eof {
			// no </body>: the content goes out at the very end
			// (no byte lost or duplicated)
			t.pend = append(t.pend, data...)
			if !t.inserted {
				t.pend = append(t.pend, t.content...)
				t.inserted = true
			}
			t.tail = nil
			break
		}

		// no marker: emit everything except the tail (a marker
		// straddling the read boundary stays detectable)
		keep := tailHold
		if len(data) < keep {
			keep = len(data)
		}
		t.pend = append(t.pend, data[:len(data)-keep]...)
		t.tail = append(t.tail[:0], data[len(data)-keep:]...)
	}

	n := copy(p, t.pend[t.pendOff:])
	t.pendOff += n
	return n, nil
}

func (t *tailInjectStream) Close() error { return t.src.Close() }

// itemMatchesPath: the bundle's per-page targeting — path prefix
// (same grammar as route.path: "/*" = whole host). The request keeps
// its path in resp.Request (the director only rewrites the Host).
func itemMatchesPath(item *core.InjectContent, req *http.Request) bool {
	if item.WhenPath == "" || item.WhenPath == "/*" || req == nil {
		return true
	}
	p := "/"
	if req.URL != nil && req.URL.Path != "" {
		p = req.URL.Path
	}
	return strings.HasPrefix(p, strings.TrimSuffix(item.WhenPath, "*"))
}
