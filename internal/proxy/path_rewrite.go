package proxy

// Response path rewriting for route.stripPrefix.
//
// A request mounted under a public prefix (/api) is stripped before it
// reaches the backend (/v1/foo). Without the reverse transformation the
// browser leaves the mount at the first redirect or root-relative link:
// Location: /v1/next, <a href="/v1/next">, Set-Cookie: Path=/v1…
//
// This injector mirrors the request mapping on responses:
//
//	public /api/foo  <->  backend /v1/foo
//
// Only paths that are actually inside the backend base are rewritten;
// relative references ("next", "../x", "?q", "#f") are left alone, as
// are absolute URLs targeting another origin. Rewriting happens before
// rewriteBody/upstream in the chain, so origin rewriting still composes
// naturally (path first, then host).
//
// The HTML side is streaming (golang.org/x/net/html tokenizer): a tag
// is rewritten in place, text is passed through, and style blocks only
// get url(...) values rewritten. Script strings and CSS @import are
// intentionally out of scope.

import (
	"io"
	"net/http"
	"net/url"
	"strings"

	"cladone/gate-one/internal/core"
	"golang.org/x/net/html"
)

type pathRewritePlan struct {
	// publicPrefix: normalized route.stripPrefix, e.g. "/api".
	publicPrefix string
	// backendBase: normalized backend URL path, "" for the origin root,
	// e.g. "/v1".
	backendBase string
	// backendHost: backend URL host:port (for absolute URLs).
	backendHost string
}

func pathRewritePlanFor(route *core.Route, backend *url.URL) *pathRewritePlan {
	if route.StripPrefix == "" {
		return nil
	}
	return &pathRewritePlan{
		publicPrefix: route.StripPrefix,
		backendBase:  normalizeBackendBase(backend.Path),
		backendHost:  backend.Host,
	}
}

func normalizeBackendBase(p string) string {
	if p == "" || p == "/" {
		return ""
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	p = strings.TrimRight(p, "/")
	if p == "" || p == "/" {
		return ""
	}
	return p
}

// rewritePath maps a backend path to its public path. The bool is false
// when the path is outside the mount (or is already public).
func (p *pathRewritePlan) rewritePath(path string) (string, bool) {
	if path == "" || path[0] != '/' {
		return path, false
	}
	if p.isPublicPath(path) {
		return path, false
	}

	if p.backendBase != "" {
		if path == p.backendBase {
			return p.publicPrefix, true
		}
		if strings.HasPrefix(path, p.backendBase+"/") {
			return p.publicPrefix + path[len(p.backendBase):], true
		}
		return path, false
	}

	return p.publicPrefix + path, true
}

func (p *pathRewritePlan) isPublicPath(path string) bool {
	return path == p.publicPrefix || strings.HasPrefix(path, p.publicPrefix+"/")
}

// rewriteURL rewrites the path of a root-relative URL, a
// protocol-relative URL, or an absolute URL targeting the backend.
func (p *pathRewritePlan) rewriteURL(raw string) string {
	if raw == "" {
		return raw
	}

	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	// javascript:, mailto:, data:… are not paths.
	if u.Scheme != "" && u.Host == "" {
		return raw
	}
	// Another origin: not ours to rewrite.
	if u.Host != "" && u.Host != p.backendHost {
		return raw
	}

	oldRaw := u.EscapedPath()
	newPath, ok := p.rewritePath(u.Path)
	if !ok {
		return raw
	}
	u.Path = newPath
	if oldRaw != "" && oldRaw != newPath {
		if newRaw, ok := p.rewritePath(oldRaw); ok && newRaw != newPath {
			u.RawPath = newRaw
		} else {
			u.RawPath = ""
		}
	} else {
		u.RawPath = ""
	}
	return u.String()
}

// rewriteHeaders applies the path mapping to response headers.
func (p *pathRewritePlan) rewriteHeaders(resp *http.Response) {
	for i, v := range resp.Header["Location"] {
		resp.Header["Location"][i] = p.rewriteURL(strings.TrimSpace(v))
	}
	for i, v := range resp.Header["Content-Location"] {
		resp.Header["Content-Location"][i] = p.rewriteURL(strings.TrimSpace(v))
	}
	for i, v := range resp.Header["Refresh"] {
		resp.Header["Refresh"][i] = p.rewriteRefresh(v)
	}
	for i, v := range resp.Header["Link"] {
		resp.Header["Link"][i] = p.rewriteLinkHeader(v)
	}
	for i, v := range resp.Header["Set-Cookie"] {
		resp.Header["Set-Cookie"][i] = p.rewriteSetCookie(v)
	}
}

func (p *pathRewritePlan) rewriteRefresh(v string) string {
	lower := strings.ToLower(v)
	idx := strings.Index(lower, "url=")
	if idx < 0 {
		return v
	}

	start := idx + len("url=")
	for start < len(v) && isCSSSpace(v[start]) {
		start++
	}
	end := len(v)
	if start < len(v) && (v[start] == '"' || v[start] == '\'') {
		quote := v[start]
		start++
		if q := strings.IndexByte(v[start:], quote); q >= 0 {
			end = start + q
		}
	}

	old := strings.TrimSpace(v[start:end])
	newURL := p.rewriteURL(old)
	if newURL == old {
		return v
	}
	return v[:start] + newURL + v[end:]
}

func (p *pathRewritePlan) rewriteLinkHeader(v string) string {
	var b strings.Builder
	from := 0
	for {
		open := strings.IndexByte(v[from:], '<')
		if open < 0 {
			b.WriteString(v[from:])
			break
		}
		open += from
		close := strings.IndexByte(v[open+1:], '>')
		if close < 0 {
			b.WriteString(v[from:])
			break
		}
		close += open + 1

		b.WriteString(v[from : open+1])
		raw := v[open+1 : close]
		b.WriteString(p.rewriteURL(raw))
		b.WriteByte('>')
		from = close + 1
	}
	return b.String()
}

func (p *pathRewritePlan) rewriteSetCookie(line string) string {
	parts := strings.Split(line, ";")
	changed := false
	for i, part := range parts {
		trimmed := strings.TrimSpace(part)
		if len(trimmed) < len("path=") ||
			!strings.EqualFold(trimmed[:len("path=")], "path=") {
			continue
		}
		old := trimmed[len("path="):]
		newPath := p.rewriteCookiePath(old)
		if newPath == old {
			continue
		}
		lead := part[:len(part)-len(strings.TrimLeft(part, " \t"))]
		parts[i] = lead + trimmed[:len("path=")] + newPath
		changed = true
	}
	if !changed {
		return line
	}
	return strings.Join(parts, ";")
}

func (p *pathRewritePlan) rewriteCookiePath(path string) string {
	if path == "" || path[0] != '/' {
		return path
	}
	if p.isPublicPath(path) {
		return path
	}
	if p.backendBase != "" {
		if path == p.backendBase {
			return p.publicPrefix
		}
		if strings.HasPrefix(path, p.backendBase+"/") {
			return p.publicPrefix + path[len(p.backendBase):]
		}
		return path
	}
	// A backend mounted at the root keeps Path=/ as the broadest
	// scope; only non-root paths need the public prefix.
	if path == "/" {
		return path
	}
	return p.publicPrefix + path
}

//
// HTML body rewriting.
//

type pathRewriteStream struct {
	src     io.ReadCloser
	z       *html.Tokenizer
	plan    *pathRewritePlan
	out     []byte
	err     error
	inStyle bool
}

func newPathRewriteStream(src io.ReadCloser, plan *pathRewritePlan) io.ReadCloser {
	return &pathRewriteStream{
		src:  src,
		z:    html.NewTokenizer(src),
		plan: plan,
	}
}

func (s *pathRewriteStream) Read(p []byte) (int, error) {
	for len(s.out) == 0 {
		if s.err != nil {
			err := s.err
			s.err = nil
			return 0, err
		}

		switch s.z.Next() {
		case html.ErrorToken:
			err := s.z.Err()
			if raw := s.z.Raw(); len(raw) > 0 {
				s.out = append(s.out, raw...)
			}
			if err == nil {
				err = io.EOF
			}
			s.err = err
		case html.StartTagToken:
			raw := s.z.Raw()
			if rawTagName(raw) == "style" {
				s.inStyle = true
			}
			out, _ := rewriteStartTagRaw(raw, s.plan)
			s.out = append(s.out, out...)
		case html.SelfClosingTagToken:
			out, _ := rewriteStartTagRaw(s.z.Raw(), s.plan)
			s.out = append(s.out, out...)
		case html.EndTagToken:
			raw := s.z.Raw()
			if rawTagName(raw) == "style" {
				s.inStyle = false
			}
			s.out = append(s.out, raw...)
		case html.TextToken:
			raw := s.z.Raw()
			if s.inStyle {
				raw = []byte(s.plan.rewriteCSSURLs(string(raw)))
			}
			s.out = append(s.out, raw...)
		default:
			s.out = append(s.out, s.z.Raw()...)
		}
	}

	n := copy(p, s.out)
	s.out = s.out[n:]
	return n, nil
}

func (s *pathRewriteStream) Close() error {
	return s.src.Close()
}

type pathAttrSpan struct {
	name       string
	start, end int
}

// parseStartTag extracts the tag name and attribute value spans from a
// raw start tag. Quote characters and whitespace are preserved by the
// caller; only the value bytes [start,end) are replaced.
func parseStartTag(raw []byte) (string, []pathAttrSpan, bool) {
	i := 1
	if i >= len(raw) || raw[i] == '/' || raw[i] == '!' || raw[i] == '?' {
		return "", nil, false
	}
	for i < len(raw) && isTagSpace(raw[i]) {
		i++
	}
	nameStart := i
	for i < len(raw) && !isTagSpace(raw[i]) && raw[i] != '>' && raw[i] != '/' {
		i++
	}
	name := strings.ToLower(string(raw[nameStart:i]))

	var attrs []pathAttrSpan
	for i < len(raw) {
		for i < len(raw) && isTagSpace(raw[i]) {
			i++
		}
		if i >= len(raw) || raw[i] == '>' {
			break
		}
		if raw[i] == '/' {
			i++
			continue
		}

		attrStart := i
		for i < len(raw) && !isTagSpace(raw[i]) &&
			raw[i] != '=' && raw[i] != '>' && raw[i] != '/' {
			i++
		}
		if i == attrStart {
			i++
			continue
		}
		attrName := strings.ToLower(string(raw[attrStart:i]))

		for i < len(raw) && isTagSpace(raw[i]) {
			i++
		}
		if i >= len(raw) || raw[i] != '=' {
			continue
		}
		i++
		for i < len(raw) && isTagSpace(raw[i]) {
			i++
		}
		if i >= len(raw) {
			break
		}

		var start, end int
		if raw[i] == '"' || raw[i] == '\'' {
			quote := raw[i]
			i++
			start = i
			for i < len(raw) && raw[i] != quote {
				i++
			}
			end = i
			if i < len(raw) {
				i++
			}
		} else {
			start = i
			for i < len(raw) && !isTagSpace(raw[i]) && raw[i] != '>' {
				i++
			}
			end = i
		}
		attrs = append(attrs, pathAttrSpan{name: attrName, start: start, end: end})
	}
	return name, attrs, true
}

func rawTagName(raw []byte) string {
	i := 1
	if i < len(raw) && raw[i] == '/' {
		i++
	}
	for i < len(raw) && isTagSpace(raw[i]) {
		i++
	}
	start := i
	for i < len(raw) && !isTagSpace(raw[i]) && raw[i] != '>' && raw[i] != '/' {
		i++
	}
	return strings.ToLower(string(raw[start:i]))
}

var pathURLAttrs = map[string]bool{
	"href":       true,
	"src":        true,
	"action":     true,
	"formaction": true,
	"poster":     true,
	"data":       true,
	"cite":       true,
	"background": true,
	"longdesc":   true,
	"usemap":     true,
	"manifest":   true,
	"profile":    true,
	"codebase":   true,
	"xlink:href": true,
}

var pathSrcsetAttrs = map[string]bool{
	"srcset":      true,
	"imagesrcset": true,
}

func rewriteStartTagRaw(raw []byte, p *pathRewritePlan) ([]byte, string) {
	name, attrs, ok := parseStartTag(raw)
	if !ok {
		return raw, name
	}

	metaRefresh := false
	if name == "meta" {
		for _, a := range attrs {
			if a.name == "http-equiv" &&
				strings.EqualFold(strings.TrimSpace(string(raw[a.start:a.end])), "refresh") {
				metaRefresh = true
				break
			}
		}
	}

	var out []byte
	copyStart := 0
	for _, a := range attrs {
		old := string(raw[a.start:a.end])
		newValue := old
		switch {
		case pathURLAttrs[a.name]:
			newValue = p.rewriteURL(old)
		case pathSrcsetAttrs[a.name]:
			newValue = p.rewriteSrcset(old)
		case a.name == "ping":
			newValue = p.rewriteSpaceURLs(old)
		case a.name == "style":
			newValue = p.rewriteCSSURLs(old)
		case a.name == "content" && metaRefresh:
			newValue = p.rewriteRefresh(old)
		}
		if newValue == old {
			continue
		}
		if out == nil {
			out = make([]byte, 0, len(raw)+len(newValue))
		}
		out = append(out, raw[copyStart:a.start]...)
		out = append(out, newValue...)
		copyStart = a.end
	}
	if out == nil {
		return raw, name
	}
	out = append(out, raw[copyStart:]...)
	return out, name
}

func (p *pathRewritePlan) rewriteSrcset(v string) string {
	if strings.Contains(strings.ToLower(v), "data:") {
		return v
	}
	parts := strings.Split(v, ",")
	changed := false
	for i, part := range parts {
		fields := strings.Fields(strings.TrimSpace(part))
		if len(fields) == 0 {
			continue
		}
		newURL := p.rewriteURL(fields[0])
		if newURL == fields[0] {
			continue
		}
		fields[0] = newURL
		parts[i] = strings.Join(fields, " ")
		changed = true
	}
	if !changed {
		return v
	}
	return strings.Join(parts, ", ")
}

func (p *pathRewritePlan) rewriteSpaceURLs(v string) string {
	fields := strings.Fields(v)
	changed := false
	for i, field := range fields {
		newURL := p.rewriteURL(field)
		if newURL != field {
			fields[i] = newURL
			changed = true
		}
	}
	if !changed {
		return v
	}
	return strings.Join(fields, " ")
}

type cssURLSpan struct {
	start, end  int
	replacement string
}

func (p *pathRewritePlan) rewriteCSSURLs(s string) string {
	lower := strings.ToLower(s)
	var spans []cssURLSpan
	from := 0
	for {
		rel := strings.Index(lower[from:], "url(")
		if rel < 0 {
			break
		}
		idx := from + rel
		i := idx + len("url(")
		for i < len(s) && isCSSSpace(s[i]) {
			i++
		}

		quote := byte(0)
		if i < len(s) && (s[i] == '"' || s[i] == '\'') {
			quote = s[i]
			i++
		}
		start := i
		for i < len(s) {
			if quote != 0 {
				if s[i] == quote {
					break
				}
			} else if s[i] == ')' {
				break
			}
			i++
		}
		end := i
		old := strings.TrimSpace(s[start:end])
		newURL := p.rewriteURL(old)
		if newURL != old {
			spans = append(spans, cssURLSpan{start: start, end: end, replacement: newURL})
		}
		from = end
		if from <= idx {
			from = idx + len("url(")
		}
	}

	if len(spans) == 0 {
		return s
	}

	var b strings.Builder
	last := 0
	for _, sp := range spans {
		b.WriteString(s[last:sp.start])
		b.WriteString(sp.replacement)
		last = sp.end
	}
	b.WriteString(s[last:])
	return b.String()
}

func isTagSpace(b byte) bool {
	switch b {
	case ' ', '\t', '\n', '\r', '\f':
		return true
	}
	return false
}

func isCSSSpace(b byte) bool {
	return isTagSpace(b)
}

// pathRewriteInjector: response-side counterpart of route.stripPrefix.
type pathRewriteInjector struct {
	plan *pathRewritePlan
}

func (i *pathRewriteInjector) name() string { return "pathRewrite" }

func (i *pathRewriteInjector) modify(resp *http.Response) error {
	i.plan.rewriteHeaders(resp)
	if !isHTMLResponse(resp) {
		return nil
	}

	// Streaming HTML rewrite: no buffering, Content-Length removed
	// (chunked, like the other body injectors).
	resp.Header.Del("Content-Length")
	resp.Header.Del("Content-Encoding")
	resp.ContentLength = -1
	resp.Body = newPathRewriteStream(resp.Body, i.plan)
	return nil
}
