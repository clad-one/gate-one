package proxy

// Content-Security-Policy: header emission, nonce, merge with the
// origin's policy, and the violation collector.
//
// The policy is applied to HTML responses only (the only documents a
// CSP governs). Two properties matter:
//
//   - the origin's policy is NEVER removed or weakened. The gateway's
//     policy is added as a SECOND header: browsers enforce every
//     policy they receive, so the effective rule is the strictest of
//     the two. The only edit to the origin's policy is APPENDING the
//     hashes of the scripts the gateway injects (guard, PWA, custom):
//     without them a strict origin policy would block those scripts.
//   - in nonce mode the body is stamped in STREAMING mode (O(1)
//     memory), and the upstream is forced to gzip (injectsBody): a
//     brotli/zstd body must never be scanned as plain text.

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"cladone/gate-one/internal/core"
)

// cspNonceKey: per-request nonce, set by ServeHTTP before proxying and
// read by the injector (resp.Request.Context()).
type cspNonceKey struct{}

// nonceBytes: 128 bits of entropy, base64url (no padding, no quote,
// no HTML metacharacter).
const nonceBytes = 16

func newCSPNonce() string {
	var b [nonceBytes]byte
	if _, err := rand.Read(b[:]); err != nil {
		// Never emit a predictable nonce: without one the policy is
		// skipped (fail-open, logged).
		log.Printf("CSP nonce: entropy source failed: %v", err)
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(b[:])
}

func cspNonceFrom(req *http.Request) string {
	if req == nil {
		return ""
	}
	nonce, _ := req.Context().Value(cspNonceKey{}).(string)
	return nonce
}

// cspInjector: header-only (plus the streaming stamper in nonce mode).
// Installed LAST in the injection chain so the stamper sees the bytes
// the other injectors added (guard, PWA, custom) — no per-feature
// nonce plumbing.
type cspInjector struct {
	policy *core.CSPPolicy
	// hashes: 'sha256-…' of every inline script the gateway injects
	// (computed at route compile time).
	hashes []string
}

func (i *cspInjector) name() string { return "csp" }

func (i *cspInjector) modify(resp *http.Response) error {

	if !isHTMLResponse(resp) {
		return nil
	}

	// Never weaken the origin: append our injected scripts' hashes to
	// its own policy (script-src-elem, else script-src, else
	// default-src).
	i.amendOrigin(resp)

	switch i.policy.Mode {

	case "nonce":
		nonce := cspNonceFrom(resp.Request)
		if nonce == "" {
			return nil // fail-open: no policy rather than a broken one
		}
		// The stamper changes the body size: chunked, no stale
		// Content-Encoding/Length.
		resp.Header.Del("Content-Length")
		resp.Header.Del("Content-Encoding")
		resp.ContentLength = -1
		resp.Body = newCSPStampStream(resp.Body, nonce, i.policy.StampsAll())
		resp.Header.Add(i.policy.Header(), i.policyString(nonce))

	case "hash":
		resp.Header.Add(i.policy.Header(), i.policyString(""))
	}

	return nil
}

// policyString: our own policy, deterministic (directives sorted).
func (i *cspInjector) policyString(nonce string) string {

	directives := make(map[string][]string, len(i.policy.Directives)+2)
	for name, sources := range i.policy.Directives {
		directives[name] = append([]string(nil), sources...)
	}

	// Scripts: append the nonce and the gateway's injected-script
	// hashes to the directive the browser actually uses for
	// parser-inserted scripts (script-src-elem > script-src).
	scriptTarget := "script-src"
	if _, ok := directives["script-src-elem"]; ok {
		scriptTarget = "script-src-elem"
	}
	script := directives[scriptTarget]
	if nonce != "" {
		script = append(script, "'nonce-"+nonce+"'")
	}
	script = append(script, i.hashes...)
	if len(script) > 0 {
		directives[scriptTarget] = dedupeStrings(script)
	}

	// Styles: the guard creates a <style> at runtime and sets its
	// nonce from document.currentScript.nonce. Append the same
	// per-response nonce to the directive that governs <style>
	// elements (style-src-elem > style-src). A config without either
	// directive keeps its default-src fallback and must declare
	// style-src explicitly to allow the guard's stylesheet.
	if nonce != "" {
		styleTarget := "style-src"
		if _, ok := directives["style-src-elem"]; ok {
			styleTarget = "style-src-elem"
		}
		if style, ok := directives[styleTarget]; ok {
			directives[styleTarget] = dedupeStrings(
				append(style, "'nonce-"+nonce+"'"))
		}
	}

	if _, ok := directives["report-uri"]; !ok {
		if _, ok := directives["report-to"]; !ok {
			directives["report-uri"] = []string{i.policy.Path()}
		}
	}

	names := make([]string, 0, len(directives))
	for name := range directives {
		names = append(names, name)
	}
	sort.Strings(names)

	var b strings.Builder
	for n, name := range names {
		if n > 0 {
			b.WriteString("; ")
		}
		b.WriteString(name)
		for _, src := range directives[name] {
			src = strings.TrimSpace(src)
			if src == "" {
				continue
			}
			b.WriteByte(' ')
			b.WriteString(src)
		}
	}
	return b.String()
}

// amendOrigin appends the injected scripts' hashes to the origin's
// enforced policy. A policy without script-src/script-src-elem nor
// default-src leaves scripts unrestricted — our injections already
// pass, nothing to add.
func (i *cspInjector) amendOrigin(resp *http.Response) {

	if len(i.hashes) == 0 {
		return
	}
	values := resp.Header.Values("Content-Security-Policy")
	if len(values) == 0 {
		return
	}

	amended := make([]string, 0, len(values))
	for _, policy := range values {
		amended = append(amended, appendHashesToPolicy(policy, i.hashes))
	}
	resp.Header["Content-Security-Policy"] = amended
}

type cspDirective struct {
	name    string
	sources []string
}

// appendHashesToPolicy: union with the origin's policy, never a
// removal. The target directive must be the one the browser actually
// uses for parser-inserted scripts (script-src-elem > script-src >
// default-src).
func appendHashesToPolicy(policy string, hashes []string) string {

	var parsed []cspDirective
	for _, part := range strings.Split(policy, ";") {
		fields := strings.Fields(part)
		if len(fields) == 0 {
			continue
		}
		parsed = append(parsed, cspDirective{
			name:    strings.ToLower(fields[0]),
			sources: fields[1:],
		})
	}

	target := -1
	for i, d := range parsed {
		if d.name == "script-src-elem" {
			target = i
			break
		}
	}
	if target < 0 {
		for i, d := range parsed {
			if d.name == "script-src" {
				target = i
				break
			}
		}
	}
	if target < 0 {
		for i, d := range parsed {
			if d.name == "default-src" {
				target = i
				break
			}
		}
	}
	if target < 0 {
		return policy
	}

	missing := make([]string, 0, len(hashes))
	for _, h := range hashes {
		found := false
		for _, src := range parsed[target].sources {
			if src == h {
				found = true
				break
			}
		}
		if !found {
			missing = append(missing, h)
		}
	}
	if len(missing) == 0 {
		return policy
	}
	parsed[target].sources = append(parsed[target].sources, missing...)

	var b strings.Builder
	for i, d := range parsed {
		if i > 0 {
			b.WriteString("; ")
		}
		b.WriteString(d.name)
		for _, src := range d.sources {
			b.WriteByte(' ')
			b.WriteString(src)
		}
	}
	return b.String()
}

func dedupeStrings(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// ---------------------------------------------------------------------
// Violation collector (report-uri) — bounded ring buffer, global rate
// limit, never proxied, never authenticated (violations come from
// anonymous pages too).
// ---------------------------------------------------------------------

const (
	cspReportRing      = 256
	cspReportMaxBody   = 16 << 10
	cspReportsPerSec   = 50
	cspReportFieldSize = 512
)

type cspReport struct {
	At        time.Time
	Host      string
	Document  string
	Directive string
	Blocked   string
	Source    string
	Line      int
}

var cspStore = struct {
	sync.Mutex
	entries     []cspReport
	next        int
	dropped     uint64
	windowStart time.Time
	inWindow    int
}{}

// serveCSPReport: POST only, bounded body, silently throttled. Always
// 204 on a well-formed report (a reporting client must not retry).
func (g *Gateway) serveCSPReport(w http.ResponseWriter, r *http.Request) {

	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !cspReportAllowed(time.Now()) {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, cspReportMaxBody+1))
	if err != nil {
		http.Error(w, "invalid report", http.StatusBadRequest)
		return
	}
	if len(body) > cspReportMaxBody {
		http.Error(w, "report too large", http.StatusRequestEntityTooLarge)
		return
	}

	rep, ok := parseCSPReport(body)
	if !ok {
		http.Error(w, "invalid report", http.StatusBadRequest)
		return
	}
	rep.At = time.Now()
	rep.Host = normalizeHost(r.Host)
	recordCSPReport(rep)

	w.WriteHeader(http.StatusNoContent)
}

func cspReportAllowed(now time.Time) bool {
	cspStore.Lock()
	defer cspStore.Unlock()
	if now.Sub(cspStore.windowStart) >= time.Second {
		cspStore.windowStart = now
		cspStore.inWindow = 0
	}
	if cspStore.inWindow >= cspReportsPerSec {
		cspStore.dropped++
		return false
	}
	cspStore.inWindow++
	return true
}

func recordCSPReport(rep cspReport) {

	cspStore.Lock()
	if len(cspStore.entries) < cspReportRing {
		cspStore.entries = append(cspStore.entries, rep)
	} else {
		cspStore.entries[cspStore.next] = rep
		cspStore.next = (cspStore.next + 1) % cspReportRing
	}
	dropped := cspStore.dropped
	cspStore.Unlock()

	log.Printf(
		"CSP VIOLATION host=%q directive=%q blocked=%q document=%q source=%q line=%d dropped=%d",
		rep.Host, rep.Directive, rep.Blocked, rep.Document, rep.Source, rep.Line, dropped)
}

// recentCSPReports / resetCSPReports: diagnostics and tests.
func recentCSPReports() []cspReport {
	cspStore.Lock()
	defer cspStore.Unlock()
	out := make([]cspReport, len(cspStore.entries))
	copy(out, cspStore.entries)
	return out
}

func resetCSPReports() {
	cspStore.Lock()
	defer cspStore.Unlock()
	cspStore.entries = nil
	cspStore.next = 0
	cspStore.dropped = 0
	cspStore.windowStart = time.Time{}
	cspStore.inWindow = 0
}

// parseCSPReport accepts the three shapes seen in the wild:
// {"csp-report":{…}} (report-uri), {…} (legacy), [{…}] (Reporting API).
func parseCSPReport(body []byte) (cspReport, bool) {

	raw := body

	var envelope struct {
		CSPReport json.RawMessage `json:"csp-report"`
	}
	if json.Unmarshal(body, &envelope) == nil && len(envelope.CSPReport) > 0 {
		raw = envelope.CSPReport
	}

	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil {
		var arr []map[string]any
		if err := json.Unmarshal(raw, &arr); err != nil || len(arr) == 0 {
			return cspReport{}, false
		}
		obj = arr[0]
	}

	str := func(keys ...string) string {
		for _, k := range keys {
			if v, ok := obj[k]; ok {
				if s, ok := v.(string); ok {
					return truncateField(s)
				}
			}
		}
		return ""
	}
	num := func(keys ...string) int {
		for _, k := range keys {
			if v, ok := obj[k]; ok {
				if f, ok := v.(float64); ok {
					return int(f)
				}
			}
		}
		return 0
	}

	directive := str("effective-directive", "effectiveDirective", "violated-directive")
	// Legacy reports carry "violated-directive: script-src 'self'" —
	// the directive is the first token.
	if i := strings.IndexByte(directive, ' '); i > 0 {
		directive = directive[:i]
	}

	return cspReport{
		Document:  str("document-uri", "documentURL"),
		Directive: directive,
		Blocked:   str("blocked-uri", "blockedURL"),
		Source:    str("source-file", "sourceFile"),
		Line:      num("line-number", "lineNumber"),
	}, true
}

func truncateField(s string) string {
	if len(s) <= cspReportFieldSize {
		return s
	}
	return s[:cspReportFieldSize] + "…"
}
