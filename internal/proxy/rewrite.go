package proxy

import (
	"bytes"
	"io"
	"net"
	"net/url"
	"sort"

	"cladone/gate-one/internal/core"
	"cladone/gate-one/internal/pwa"
)

//
// HTML body rewrite (upstream.rewriteBody) — STREAMING engine.
//
// The proxified external site cites its own URLs in its pages
// ("https://origin/…", "//origin/…"): without rewriting, the
// browser leaves the proxy at the first occurrence (session,
// instrumentation lost). The gateway rewrites those occurrences
// toward the route's PUBLIC host without buffering the body (like
// guardStream: the incoming byte goes out quickly, O(1) memory
// regardless of the page size).
//
// Semantics shared with the client SW (pwa.Handler) and the guard
// script's patch layer: the three layers implement the SAME policy
// (origins × except × target) — parity is tested in rewrite_test.go
// over the same case list.
//
// Rewritten forms: "https://HOST…", "http://HOST…", "//HOST…" (HOST
// = the route's origin hostname, without port; an explicit
// ":digits" port is part of the rewritten prefix and is LOST — the
// public target is served on the standard port). Path, query and
// fragment follow as-is. Exceptions: longest path prefix wins
// (descending sort); string entry = stay at the origin,
// {path,to} entry = "to" replacement base.
//
// Sibling origins (another concrete route from the same wildcard
// expansion) are rewritten toward THAT route's public host, keeping
// the request's scheme and port; the route's exceptions apply to its
// own origin only. The map is compiled once at load.
//
// Bounded sliding window: the engine never waits for more than
// "https://" + longest host + longest exception prefix (config:
// ≤ 256 bytes per prefix); plus the optional explicit port, left
// pending at window edges. A URL is NEVER rewritten partially: if a
// decision lacks context, the relevant bytes are held until
// resolution; absent a candidate, everything is emitted except the
// last `hold` bytes (a pattern smaller than that can never straddle
// the window edge). End of stream: everything is resolved/emitted;
// transport error: buf goes out raw then the error propagates (never
// swallowed), per guardStream.
//

// rewritePlan: a route's compiled rewrite policy, shared between
// the streaming engine (Go) and the client SW (pwa).
type rewritePlan struct {
	// origin hosts whose absolute URLs are rewritten — hostname
	// without port, lowercased (plausible self-references of the
	// origin HTML: backend host + optional hostOverride, plus the
	// backend origins of sibling routes from the same wildcard
	// expansion).
	origins []string
	// siblings: sibling-origin hostname → sibling PUBLIC host (no
	// scheme/port), compiled from the wildcard expansion. A hit here
	// is rewritten toward that public host, never toward this
	// route's own host. nil when there is no unambiguous mapping.
	siblings map[string]string
	// pub: default replacement base in https ("https://host.public")
	// — the form handed to the client SW (which uses it as
	// documentation; at runtime it rewrites toward ITS origin) and
	// to the test oracle.
	pub string
	// pubHost: public host without scheme — the SERVER rewrite
	// prefixes the request's real scheme onto it (https in prod,
	// http in demo: X-Forwarded-Proto / direct TLS).
	pubHost string
	// except: exceptions sorted by descending length (longest
	// prefix wins); empty To = stay at the origin.
	except []core.RewriteExcept
	// hold: max fragments held at the end of the window —
	// "https://" + longest host (no pattern can straddle beyond).
	hold int
	// maxExcept: longest exception prefix (right context needed
	// for a decision).
	maxExcept int
}

// rewritePlanFor compiles the route's rewriteBody policy; nil when
// the route has none (absent or disabled).
func rewritePlanFor(route *core.Route, backend *url.URL) *rewritePlan {
	rb := route.UpstreamRewriteBody()
	if rb == nil {
		return nil
	}

	up := route.Upstream
	origins := make([]string, 0, 2)
	siblings := make(map[string]string, len(route.RewriteSiblings()))
	addOrigin := func(h string) {
		h = normalizeHost(h)
		if h == "" {
			return
		}
		for _, have := range origins {
			if have == h {
				return
			}
		}
		origins = append(origins, h)
	}
	addOrigin(backend.Hostname())
	if up.HostOverride != "" {
		addOrigin(up.HostOverride)
	}

	// Sibling routes expanded from the same wildcard: their backend
	// origins are rewritten toward their public hosts. A sibling
	// origin never shadows one of this route's own origins.
	for origin, publicHost := range route.RewriteSiblings() {
		origin = normalizeHost(origin)
		if origin == "" {
			continue
		}
		self := false
		for _, have := range origins {
			if have == origin {
				self = true
				break
			}
		}
		if self {
			continue
		}
		siblings[origin] = normalizeHost(publicHost)
		addOrigin(origin)
	}
	if len(siblings) == 0 {
		siblings = nil
	}
	sort.Strings(origins)

	maxHost := 0
	for _, h := range origins {
		if len(h) > maxHost {
			maxHost = len(h)
		}
	}

	// exceptions: longest prefix first (the first match wins, on
	// the Go side as on the client SW side).
	except := make([]core.RewriteExcept, len(rb.Except))
	copy(except, rb.Except)
	for i := 1; i < len(except); i++ {
		for j := i; j > 0 && len(except[j].Path) > len(except[j-1].Path); j-- {
			except[j], except[j-1] = except[j-1], except[j]
		}
	}

	maxExcept := 0
	for _, e := range except {
		if len(e.Path) > maxExcept {
			maxExcept = len(e.Path)
		}
	}

	return &rewritePlan{
		origins:   origins,
		siblings:  siblings,
		pub:       "https://" + normalizeHost(route.Host),
		pubHost:   normalizeHost(route.Host),
		except:    except,
		hold:      len("https://") + maxHost,
		maxExcept: maxExcept,
	}
}

// clientSpec: adapter for the client SW (pwa.RewriteSpec).
func (p *rewritePlan) clientSpec() *pwa.RewriteSpec {
	return &pwa.RewriteSpec{
		Origins:  p.origins,
		Target:   p.pub,
		Siblings: p.siblings,
		Except:   p.except,
	}
}

// rewriteGuardDTO: serialized into the guard script, for SW
// registration (parameterized like the SW above) and the patching
// of runtime calls (fetch/XHR/…). The payload goes through the
// rewrite engine: origin hosts appear there WITHOUT a scheme —
// never in a "scheme://origin" form that would be rewritten in its
// own transport.
type rewriteGuardDTO struct {
	Sw       string               `json:"sw"`
	Target   string               `json:"target"`
	Origins  []string             `json:"origins"`
	Siblings map[string]string    `json:"siblings,omitempty"`
	Except   []core.RewriteExcept `json:"except"`
}

// rewriteGuardDTOFor: version for the guard script; nil when the
// route has no rewriteBody.
func rewriteGuardDTOFor(route *core.Route, backend *url.URL) *rewriteGuardDTO {
	plan := rewritePlanFor(route, backend)
	if plan == nil {
		return nil
	}
	return &rewriteGuardDTO{
		Sw:       pwa.SwURL,
		Target:   plan.pub,
		Origins:  plan.origins,
		Siblings: plan.siblings,
		Except:   plan.except,
	}
}

//
// Streaming engine.
//
//	buf: bytes received, not yet emitted (bounded by hold, plus the
//	     optional right context of a candidate pending context).
//	out: resolved bytes, ready to go out.
//

type rewriteStream struct {
	src io.ReadCloser
	cfg *rewritePlan
	// scheme: the rewritten URLs' scheme (request's real scheme);
	// "" = https (default).
	scheme string
	// reqHost: the CLIENT request's host, with its port when
	// non-standard (app1.demo.localhost:3000) — the rewritten URLs
	// keep the browser on the origin it called. Empty = the route's
	// own public host (https production default).
	reqHost string

	scratch  []byte
	buf      []byte
	out      []byte
	outOff   int
	lastByte byte // last byte already emitted (left context of a candidate at the start of buf)
	emitted  bool
	done     bool
	err      error
}

func newRewriteStream(src io.ReadCloser, cfg *rewritePlan) *rewriteStream {
	return newRewriteStreamWithScheme(src, cfg, "https")
}

func newRewriteStreamWithScheme(
	src io.ReadCloser,
	cfg *rewritePlan,
	scheme string,
) *rewriteStream {
	return newRewriteStreamForRequest(src, cfg, scheme, "")
}

// newRewriteStreamForRequest: the scheme AND the client host (with
// its port when non-standard) — the rewritten URLs mirror the origin
// the browser called, so it never leaves the proxy (demo :3000).
func newRewriteStreamForRequest(
	src io.ReadCloser,
	cfg *rewritePlan,
	scheme, reqHost string,
) *rewriteStream {
	return &rewriteStream{
		src:     src,
		cfg:     cfg,
		scheme:  scheme,
		reqHost: reqHost,
		scratch: make([]byte, 4096),
	}
}

func (s *rewriteStream) Read(p []byte) (int, error) {
	for {
		if s.outOff < len(s.out) {
			n := copy(p, s.out[s.outOff:])
			s.outOff += n
			if s.outOff == len(s.out) {
				s.out = s.out[:0]
				s.outOff = 0
			}
			return n, nil
		}
		if s.done {
			if s.err != nil {
				return 0, s.err
			}
			return s.src.Read(p)
		}
		s.step()
	}
}

func (s *rewriteStream) step() {
	n, rerr := s.src.Read(s.scratch)
	if n > 0 {
		s.buf = append(s.buf, s.scratch[:n]...)
	}
	if rerr != nil && rerr != io.EOF {
		// transport error: buf goes out RAW (a cut-off body must
		// not be half-rewritten), the error will surface
		// afterwards — like guardStream, never swallowed.
		if s.err == nil {
			s.err = rerr
		}
		s.done = true
		s.emit(len(s.buf))
		return
	}
	if rerr == io.EOF {
		s.done = true
	}
	s.resolve()
}

// resolve applies the rewrite decisions to buf and moves what is
// settled to out.
func (s *rewriteStream) resolve() {

	scan := 0
	for {
		h, host := s.findHost(scan)
		if h < 0 {
			// no more whole occurrence (= also beyond):
			if s.done {
				// end of stream → everything leaves (the
				// candidates settled above already exhausted
				// their replacements)
				s.emit(len(s.buf))
			} else {
				// emit up to the safe point: the last hold
				// bytes may straddle a future pattern
				safe := len(s.buf) - s.cfg.hold
				if safe > 0 {
					s.emit(safe)
				}
			}
			return
		}

		m := s.evaluate(h, host)
		switch m.state {
		case candInvalid:
			// not an origin URL (boundaries): look for the
			// next one — another host may coincide here, the
			// longest one was already picked by findHost
			scan = h + 1
		case candPending:
			// insufficient (left/right) context: wait for
			// bytes. What precedes the pattern is settled.
			if s.done {
				replacement, keep := s.decision(m)
				s.applyCandidate(m, replacement, keep)
				scan = rescan(scan, m.portEnd)
				continue
			}
			s.emit(m.formStart)
			return
		default:
			replacement, keep := s.decision(m)
			s.applyCandidate(m, replacement, keep)
			// buf was truncated of buf[:portEnd]: the scan
			// indexes shift by that amount (earlier invalid
			// skips, below portEnd, already left in emission —
			// finished).
			scan = rescan(scan, m.portEnd)
		}
	}
}

// rescan: scan resume index after a truncation of buf[:cut] — a
// stale scan would point into the wrong buf and miss any occurrence
// held downstream (bug discovered by the E2E trace: an invalid skip
// followed by a settled candidate froze the engine).
func rescan(scan, cut int) int {
	if scan > cut {
		return scan - cut
	}
	return 0
}

// findHost: first occurrence (lowest index) of an origin host in
// buf[from:]; at equal index the longest host wins (e.g. two
// origins, one a suffix of the other). Returns (index, len). An
// occurrence LONGER than buf (host cut at the edge) does not exist
// for Index: it will be seen when more bytes arrive — the last
// `hold` bytes of buf are therefore never emitted outside "done".
func (s *rewriteStream) findHost(from int) (int, string) {
	best, bhost := -1, ""
	for _, host := range s.cfg.origins {
		i := bytes.Index(s.buf[from:], []byte(host))
		if i < 0 {
			continue
		}
		i += from
		switch {
		case best < 0 || i < best:
			best, bhost = i, host
		case i == best && len(host) > len(bhost):
			bhost = host
		}
	}
	return best, bhost
}

type candKind int

const (
	candInvalid candKind = iota
	candPending
	candDecided
)

type cand struct {
	state     candKind
	host      string // matched origin host (self or sibling)
	formStart int    // pattern start (https:// … or //)
	formEnd   int    // host end (exclusive) = path start
	portEnd   int    // after the optional port (:digits) — otherwise formEnd
}

var (
	httpsPrefix = []byte("https://")
	httpPrefix  = []byte("http://")
	slashPrefix = []byte("//")
)

// evaluate determines the candidate at index h (host): URL form
// (https:// | http:// | //) with left + right boundaries verified,
// then right context availability (path for the exceptions).
func (s *rewriteStream) evaluate(h int, host string) cand {

	hostLen := len(host)

	formLen := 0
	switch {
	case h >= len(httpsPrefix) && bytes.Equal(s.buf[h-len(httpsPrefix):h], httpsPrefix):
		formLen = len(httpsPrefix)
	case h >= len(httpPrefix) && bytes.Equal(s.buf[h-len(httpPrefix):h], httpPrefix):
		formLen = len(httpPrefix)
	case h >= len(slashPrefix) && bytes.Equal(s.buf[h-len(slashPrefix):h], slashPrefix):
		formLen = len(slashPrefix)
	default:
		return cand{state: candInvalid}
	}

	formStart := h - formLen

	// left boundary: the character before the pattern is not part
	// of a longer token (wss://, xhttps://, mail@…).
	bound := byte(0)
	switch {
	case formStart == 0 && !s.emitted:
		// start of document: de facto boundary
	case formStart == 0:
		bound = s.lastByte
	default:
		bound = s.buf[formStart-1]
	}
	if formStart > 0 || s.emitted {
		if formLen == len(slashPrefix) {
			// //host: after a quote, parenthesis, space… — not
			// after ':' (excluding other schemes, wss://…)
			if !isRelBoundary(bound) {
				return cand{state: candInvalid}
			}
		} else {
			// http(s)://: not glued to a host character
			if isHostChar(bound) {
				return cand{state: candInvalid}
			}
		}
	}

	formEnd := h + hostLen

	// optional ":digits" port — the origin URL may cite an explicit
	// port (origin on a non-standard port, tests). The port
	// qualifies the host: it belongs to the rewritten prefix and is
	// ABSENT from the replacements (the public target is served on
	// the standard port).
	portEnd := formEnd
	if portEnd < len(s.buf) && s.buf[portEnd] == ':' {
		k := portEnd + 1
		for k < len(s.buf) && s.buf[k] >= '0' && s.buf[k] <= '9' {
			k++
		}
		switch {
		case k == portEnd+1 && !s.done:
			// ':' without a digit yet: a port may follow
			return cand{state: candPending, host: host, formStart: formStart, formEnd: formEnd, portEnd: portEnd}
		case k == portEnd+1:
			// ':' followed by a non-digit (":/x"): not a target form
			return cand{state: candInvalid}
		case k >= len(s.buf) && !s.done:
			// port truncated at the window edge: wait
			return cand{state: candPending, host: host, formStart: formStart, formEnd: formEnd, portEnd: portEnd}
		}
		portEnd = k
	}

	// right boundary: the host does not continue (a.b within a
	// longer a.b.c).
	if portEnd < len(s.buf) {
		if isHostChar(s.buf[portEnd]) {
			return cand{state: candInvalid}
		}
	} else if !s.done {
		// at least one byte after the host is required to settle
		// the right boundary; nothing here: wait.
		return cand{state: candPending, host: host, formStart: formStart, formEnd: formEnd, portEnd: portEnd}
	}

	// right context: path (for the exceptions). Sibling origins are
	// not subject to this route's exceptions, so they settle here.
	if _, sibling := s.cfg.siblings[host]; !sibling {
		pathStart := portEnd
		stop := -1
		for i := pathStart; i < len(s.buf) && i < pathStart+s.cfg.maxExcept; i++ {
			if isPathStop(s.buf[i]) {
				stop = i
				break
			}
		}
		if !s.done && stop < 0 && len(s.buf)-pathStart < s.cfg.maxExcept {
			return cand{state: candPending, host: host, formStart: formStart, formEnd: formEnd, portEnd: portEnd}
		}
	}

	return cand{state: candDecided, host: host, formStart: formStart, formEnd: formEnd, portEnd: portEnd}
}

// decision: verdict for candidate m — according to the exceptions
// (longest prefix wins, descending sort). keep=true: the original
// text (port included) goes out as-is. replacement: text replacing
// scheme://host[:port] (the path, starting at portEnd, follows).
func (s *rewriteStream) decision(m cand) (replacement string, keep bool) {

	// Sibling expansion: the origin belongs to another concrete route
	// of the same wildcard. Rewrite toward THAT route's public host,
	// on the current listener (same scheme and port as the request).
	// This route's path exceptions do not apply to a sibling's paths.
	if publicHost, sibling := s.cfg.siblings[m.host]; sibling {
		return s.altBase(publicHost), false
	}

	pathStart := m.portEnd
	end := len(s.buf)
	if end > pathStart {
		// at the first terminator (end of the path)
		for i := pathStart; i < end; i++ {
			if isPathStop(s.buf[i]) {
				end = i
				break
			}
		}
	}
	if end-pathStart > s.cfg.maxExcept {
		end = pathStart + s.cfg.maxExcept
	}

	for _, e := range s.cfg.except {
		if len(e.Path) <= end-pathStart &&
			bytes.HasPrefix(s.buf[pathStart:], []byte(e.Path)) {
			if e.To != "" {
				return e.To, false // alternative public host
			}
			return "", true // exception: stay at the origin
		}
	}
	// standard rewrite: the scheme AND the host follow the request —
	// the client host (with its non-standard port in the demo) so
	// the browser never leaves the proxy on a rewritten link.
	host := s.reqHost
	if host == "" {
		host = s.cfg.pubHost
	}
	if s.scheme == "" || s.scheme == "https" {
		return "https://" + host, false
	}
	return s.scheme + "://" + host, false
}

// altBase: absolute base of a sibling public host, keeping the
// request's scheme and non-standard port (demo :3000). The gateway
// serves every route on the same listener, so the sibling lives on
// the same port as the page that links to it.
func (s *rewriteStream) altBase(publicHost string) string {
	host := publicHost
	if port := requestPort(s.reqHost); port != "" {
		host = net.JoinHostPort(host, port)
	}
	if s.scheme == "" || s.scheme == "https" {
		return "https://" + host
	}
	return s.scheme + "://" + host
}

// requestPort: the port of a Host header ("" when absent).
func requestPort(hostport string) string {
	_, port, err := net.SplitHostPort(hostport)
	if err != nil {
		return ""
	}
	return port
}

// applyCandidate emits buf[:formStart] then (unchanged original or
// replacement), and removes the prefix (through the port) from the
// window; the path remains, rescanned normally afterwards.
func (s *rewriteStream) applyCandidate(m cand, replacement string, keep bool) {
	s.out = append(s.out, s.buf[:m.formStart]...)
	if keep {
		s.out = append(s.out, s.buf[m.formStart:m.portEnd]...)
	} else if replacement != "" {
		s.out = append(s.out, replacement...)
	}
	s.rememberLast()
	s.buf = append([]byte(nil), s.buf[m.portEnd:]...)
}

// emit: buf[:n] moves to out (nothing more retained).
func (s *rewriteStream) emit(n int) {
	if n <= 0 {
		return
	}
	s.out = append(s.out, s.buf[:n]...)
	s.rememberLast()
	s.buf = append([]byte(nil), s.buf[n:]...)
}

func (s *rewriteStream) rememberLast() {
	if len(s.out) > 0 {
		s.lastByte = s.out[len(s.out)-1]
		s.emitted = true
	}
}

// isHostChar: letters/digits + '.' '-' '_' — host characters; true
// on either side of the pattern, the occurrence is not part of a
// neighboring token (wss://, longer subdomain…).
func isHostChar(b byte) bool {
	switch {
	case b >= 'a' && b <= 'z', b >= 'A' && b <= 'Z', b >= '0' && b <= '9':
		return true
	case b == '.', b == '-', b == '_':
		return true
	}
	return false
}

// isRelBoundary: valid boundary before a protocol-relative "//host"
// (':' excluded — all other schemes, wss://…).
func isRelBoundary(b byte) bool {
	switch b {
	case ' ', '\t', '\n', '\r', '"', '\'', '(', '=', '<', ',', ';', '{', '[':
		return true
	}
	return false
}

// isPathStop: end of path (guarantee: before this terminator the
// exception prefixes are compared; the bytes go out as-is).
func isPathStop(b byte) bool {
	switch b {
	case '"', '\'', '<', '>', ' ', '\t', '\n', '\r', '?', '#', '&',
		'(', ')', ',', ';', '{', '}', '[', ']', '\\':
		return true
	}
	return false
}

func (s *rewriteStream) Close() error {
	return s.src.Close()
}
