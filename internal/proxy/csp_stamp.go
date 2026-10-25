package proxy

// Streaming nonce stamper: adds nonce="…" to the <script> tags of an
// HTML response without buffering (O(1) memory, same contract as the
// guard/path/rewrite streams).
//
// Correctness rules:
//   - a <script> already carrying a nonce is left untouched (merge
//     with an origin that manages its own nonces);
//   - by default only INLINE scripts are stamped (no src attribute):
//     an external script stays governed by the host allow-list, so a
//     CSP injected by the origin/XSS cannot be turned into "trust
//     everything" by a blind stamp;
//   - text inside a script BODY is never scanned (a JS string
//     containing "<script" must not be corrupted) — a small state
//     machine tracks the body until </script>;
//   - anything undecidable is served AS-IS (fail-open): a missing
//     nonce blocks a script, it never corrupts the document.

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"strings"
)

const (
	cspScriptOpen = "<script"
	cspScriptEnd  = "</script"
	// cspMaxTagLen: beyond this, a "tag" is not a tag — fail-open.
	cspMaxTagLen = 64 << 10
)

type cspStampStream struct {
	src      io.ReadCloser
	attr     []byte // ` nonce="…"`
	stampAll bool

	inBody bool
	buf    []byte // undecided bytes
	pend   []byte // ready for the client
	off    int
	eof    bool
	err    error

	scratch []byte
}

func newCSPStampStream(src io.ReadCloser, nonce string, stampAll bool) *cspStampStream {
	return &cspStampStream{
		src:      src,
		attr:     []byte(` nonce="` + nonce + `"`),
		stampAll: stampAll,
		buf:      make([]byte, 0, 32<<10),
		scratch:  make([]byte, 16<<10),
	}
}

func (s *cspStampStream) Read(p []byte) (int, error) {

	for {
		if s.off < len(s.pend) {
			n := copy(p, s.pend[s.off:])
			s.off += n
			return n, nil
		}

		if s.eof {
			if s.err != nil {
				err := s.err
				s.err = nil
				return 0, err
			}
			return 0, io.EOF
		}

		if out := s.process(false); len(out) > 0 {
			s.pend = out
			s.off = 0
			continue
		}

		n, err := s.src.Read(s.scratch)
		if n > 0 {
			s.buf = append(s.buf, s.scratch[:n]...)
		}
		if err != nil {
			s.eof = true
			if err != io.EOF {
				s.err = err
			}
			if out := s.process(true); len(out) > 0 {
				s.pend = out
				s.off = 0
			}
		}
	}
}

func (s *cspStampStream) Close() error { return s.src.Close() }

// process consumes what it can decide from s.buf and returns the bytes
// ready to be forwarded.
func (s *cspStampStream) process(final bool) []byte {

	var out []byte

	for {
		if s.inBody {
			i := indexFoldASCII(s.buf, cspScriptEnd)
			if i < 0 {
				if final {
					out = append(out, s.buf...)
					s.buf = s.buf[:0]
					return out
				}
				keep := len(cspScriptEnd) - 1
				if len(s.buf) <= keep {
					return out
				}
				n := len(s.buf) - keep
				out = append(out, s.buf[:n]...)
				s.buf = append(s.buf[:0], s.buf[n:]...)
				return out
			}
			rel := bytes.IndexByte(s.buf[i:], '>')
			if rel < 0 {
				if final {
					out = append(out, s.buf...)
					s.buf = s.buf[:0]
					return out
				}
				out = append(out, s.buf[:i]...)
				s.buf = append(s.buf[:0], s.buf[i:]...)
				return out
			}
			stop := i + rel + 1
			out = append(out, s.buf[:stop]...)
			s.buf = append(s.buf[:0], s.buf[stop:]...)
			s.inBody = false
			continue
		}

		i := bytes.IndexByte(s.buf, '<')
		if i < 0 {
			out = append(out, s.buf...)
			s.buf = s.buf[:0]
			return out
		}
		if i > 0 {
			out = append(out, s.buf[:i]...)
			s.buf = append(s.buf[:0], s.buf[i:]...)
		}

		// s.buf starts with '<'
		if len(s.buf) < len(cspScriptOpen) {
			if !final {
				return out
			}
			out = append(out, s.buf...)
			s.buf = s.buf[:0]
			return out
		}
		if !bytes.EqualFold(s.buf[:len(cspScriptOpen)], []byte(cspScriptOpen)) {
			out = append(out, s.buf[0])
			s.buf = s.buf[1:]
			continue
		}
		if len(s.buf) == len(cspScriptOpen) {
			if !final {
				return out
			}
			out = append(out, s.buf...)
			s.buf = s.buf[:0]
			return out
		}
		if !isTagDelimiter(s.buf[len(cspScriptOpen)]) {
			out = append(out, s.buf[0])
			s.buf = s.buf[1:]
			continue
		}

		end := tagEndIndex(s.buf)
		if end < 0 {
			if !final && len(s.buf) <= cspMaxTagLen {
				return out // wait for the rest of the tag
			}
			out = append(out, s.buf[0])
			s.buf = s.buf[1:]
			continue
		}

		tag := s.buf[:end+1]
		selfClosing := end > 0 && s.buf[end-1] == '/'

		if hasAttr(tag, "nonce") || (!s.stampAll && hasAttr(tag, "src")) {
			out = append(out, tag...)
		} else {
			at := end
			if selfClosing {
				at = end - 1
			}
			out = append(out, s.buf[:at]...)
			out = append(out, s.attr...)
			out = append(out, s.buf[at:end+1]...)
		}

		s.buf = append(s.buf[:0], s.buf[end+1:]...)
		s.inBody = !selfClosing
	}
}

// inlineScriptHashes: 'sha256-…' for every INLINE script of a static
// HTML fragment. Computed once at route compile time for the fragments
// the gateway injects (guard, PWA wiring, custom bundle).
func inlineScriptHashes(html []byte) []string {

	var hashes []string

	for i := 0; i < len(html); {
		rel := indexFoldASCII(html[i:], cspScriptOpen)
		if rel < 0 {
			break
		}
		open := i + rel
		k := open + len(cspScriptOpen)
		if k >= len(html) || !isTagDelimiter(html[k]) {
			i = open + 1
			continue
		}
		endRel := tagEndIndex(html[open:])
		if endRel < 0 {
			break
		}
		end := open + endRel
		tag := html[open : end+1]
		selfClosing := end > open && html[end-1] == '/'

		closeRel := indexFoldASCII(html[end+1:], cspScriptEnd)
		if closeRel < 0 {
			break
		}
		closeIdx := end + 1 + closeRel

		if !selfClosing && !hasAttr(tag, "src") && closeIdx > end+1 {
			sum := sha256.Sum256(html[end+1 : closeIdx])
			hashes = append(hashes,
				"'sha256-"+base64.StdEncoding.EncodeToString(sum[:])+"'")
		}

		gt := bytes.IndexByte(html[closeIdx:], '>')
		if gt < 0 {
			break
		}
		i = closeIdx + gt + 1
	}

	return dedupeStrings(hashes)
}

// hasAttr: name is a complete attribute of the tag (case-insensitive),
// not a suffix of another name (data-nonce does not match nonce).
func hasAttr(tag []byte, name string) bool {

	i := len(cspScriptOpen)
	for i < len(tag) {
		for i < len(tag) && isTagSpace(tag[i]) {
			i++
		}
		if i >= len(tag) || tag[i] == '>' || tag[i] == '/' {
			return false
		}
		start := i
		for i < len(tag) && !isTagSpace(tag[i]) &&
			tag[i] != '=' && tag[i] != '>' && tag[i] != '/' {
			i++
		}
		attr := strings.ToLower(string(tag[start:i]))
		for i < len(tag) && isTagSpace(tag[i]) {
			i++
		}
		if i < len(tag) && tag[i] == '=' {
			i++
			for i < len(tag) && isTagSpace(tag[i]) {
				i++
			}
			if i < len(tag) && (tag[i] == '"' || tag[i] == '\'') {
				quote := tag[i]
				i++
				for i < len(tag) && tag[i] != quote {
					i++
				}
				if i < len(tag) {
					i++
				}
			} else {
				for i < len(tag) && !isTagSpace(tag[i]) && tag[i] != '>' {
					i++
				}
			}
		}
		if attr == name {
			return true
		}
	}
	return false
}

// tagEndIndex: index of the '>' closing the tag, quotes honored (an
// attribute value may legitimately contain '>').
func tagEndIndex(b []byte) int {
	var quote byte
	for i := 0; i < len(b); i++ {
		c := b[i]
		if quote != 0 {
			if c == quote {
				quote = 0
			}
			continue
		}
		switch c {
		case '"', '\'':
			quote = c
		case '>':
			return i
		}
	}
	return -1
}

func isTagDelimiter(c byte) bool {
	return isTagSpace(c) || c == '>' || c == '/'
}

func indexFoldASCII(b []byte, sub string) int {
	n := len(sub)
	if n == 0 {
		return 0
	}
	if n > len(b) {
		return -1
	}
	for i := 0; i+n <= len(b); i++ {
		if bytes.EqualFold(b[i:i+n], []byte(sub)) {
			return i
		}
	}
	return -1
}
