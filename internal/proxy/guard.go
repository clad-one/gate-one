package proxy

import (
	"embed"
	"io"
	"net/http"
	"regexp"
	"strings"

	"cladone/gate-one/internal/core"
)

// AuthStatePath is the gateway-served session probe: 200 + JSON
// {roles, scopes, claims} when the caller holds a valid session
// (Bearer header or cookies), 401 otherwise. Never proxied. Consumed
// by the injected guard script for the declarative [data-gtw-auth] /
// [data-gtw-auth-hidden] / [data-gtw-roles] / [data-gtw-scopes] /
// [data-gtw-claims] gating. MUST match the path hardcoded in
// guardScript below.
const AuthStatePath = "/__gate-one/auth"

// guardScript is injected into HTML responses of frontend routes. It
// wraps window.fetch so that a 401 answer (session expired: the
// gateway answers JSON 401 on API routes) triggers a login flow that
// does NOT reload the application:
//
//   - every fetch is cloned before being sent (a Request body can
//     only be read once), keeping a replayable copy ;
//   - on 401 the failed request is queued and a DISMISSABLE
//     banner ("Sign in" / ×) is shown: mid-flow 401s never open
//     a tab automatically (a background 401 must not steal focus).
//     The tab opens only on an explicit click: a
//     data-gtw-auth="before" element or the banner button. Dismissing resolves the pending requests with
//     their original 401 response (the app continues anonymously,
//     retryable later) and login() promises resolve false ;
//   - when the tab opens from the banner button, the click is a
//     genuine user gesture, so no popup-blocker issue ; if the tab
//     were opened programmatically on a stale activation, the
//     banner is the reliable path. No code in the app ;
//   - auth-bridge /auth/popup-done (same origin as the login page)
//     postMessages "cladone-auth:ok" to this page and closes the
//     tab. Queued requests are replayed and the ORIGINAL fetch
//     promises resolve with the replayed responses: the application
//     code never sees the authentication happen ;
//   - if the tab is closed without completing (user, blocker):
//     explicit login() promises resolve false silently ("not now");
//     the banner reappears only when real requests are frozen — it is
//     their exit surface (Sign in or ×) ;
//   - the banner is closable without any login action: ×, click
//     anywhere outside it, or Escape. Closing it closes the linked
//     login tab (if open) at the same time, resolves pending
//     requests with their original 401 and login() with false ;
//   - fallback to the historical full-page redirect when the request
//     cannot be cloned (streaming bodies) or window.open is
//     unavailable.
//
// Declarative gating (opt-in, zero app code) — two orthogonal
// dimensions. Full contract and behavioural test matrix:
// doc/ui-gating.adoc.
//
//	data-gtw-auth — when auth happens:
//	  "after"  : native click preserved, auth enforced at the request
//	    level (401 → queued → replayed after login) ; the login tab
//	    opens on click as an invitation ;
//	  "before" : the click is neutralized (no native request) and the
//	    login tab opens directly — authenticate first, act after ;
//	  absent   : fully transparent — first 401 → dismissable banner
//	    (never an auto-opened tab).
//
//	ACTIVATION only: turning a feature OFF is a deactivation — it is
//	let through without login. Turning a feature off never needs
//	authentication (the route policy usually only requires auth for
//	the request that turns it ON). A programmatic `el.checked = true`
//	fires no event and is NOT seen by the guard: the login is then
//	requested at the first real request (401 → banner), or by the app
//	through window.__cladoneAuth.login().
//
//	Control families:
//	  click = action: checkbox, radio, details/summary,
//	    aria-pressed/aria-checked/aria-expanded, reset (always a
//	    deactivation, never gated), submit/button/file/link (always
//	    an activation) ;
//	  change = action: select, range, date/time/datetime-local/month/
//	    week/color — clicking only opens the picker ;
//	  click = focus (never gated): text/search/email/url/tel/password/
//	    number/textarea — put the attribute on the submit button.
//
//	data-gtw-auth-off — value considered OFF for value controls
//	(select/range/date/time/color): moving TO it is a deactivation
//	(free), moving AWAY from it is an activation. Default: the
//	control's default value (select: the selected option, else the
//	first option). Ignored by the other control families.
//
//	data-gtw-auth-hidden — visibility:
//	  "before" : hidden while anonymous, shown once authed (silent
//	    gate — never a trigger; activating clicks are neutralized and
//	    show the banner) ;
//	  "after"  : visible while anonymous, hidden once authed (pure
//	    affordance, composable with gtw-auth="before" for padlocks) ;
//	  absent   : always visible.
//
// Pages using no attribute make no probe request and stay fully
// transparent (auth handled mid-flow by the wrapper, with the
// banner as login affordance).
//
// Notes:
//   - only fetch() calls are wrapped; document navigations are already
//     redirected server-side for page routes
//   - answers from the login page itself are ignored (no redirect loop)
//   - window.__cladoneAuth.login() exposes the same flow to apps that
//     want to trigger authentication from their own UI (opt-in; the
//     zero-code-change contract holds for everyone else)
//   - window.__cladoneAuth.refresh(opts) re-probes in place and
//     resolves to the new auth boolean; {quiet:true} suppresses the
//     reconnection banner, {sessionDeath:false} marks a deliberate
//     local logout (no session-death reload on a later re-login)
//   - window.__cladoneAuth.logout() is the production OIDC
//     end_session navigation; an app (or the local preview) may
//     override it for an in-place demo logout
//
// Gateway identity 403 (opt-in, authGuard.forbidden.banner): a fetch
// answer carrying the gateway's OWN marker (X-Gate-One-Forbidden — set
// only on the gateway's identity 403; a backend 403 never has it, and
// the header is stripped from proxied responses) shows a dismissable
// hint inviting the front authors to hide the feature (uiGate /
// data-gtw-*). No login is offered (a rights refusal would loop); the
// JSON 403 is returned to the app unchanged.
//
//go:embed guard/guard.css
var guardCSSFile string

// buildGuardCSS returns the full stylesheet injected by the guard:
// the static classes plus one anti-FOUC rule per uiGate selector. It
// is the EXACT text given to the browser, so the CSP layer can hash it
// and amend an origin style-src (merge mode) without unsafe-inline.
func buildGuardCSS(route *core.Route) string {
	css := strings.TrimRight(guardCSSFile, "\n")
	if route == nil {
		return css
	}
	for _, rule := range route.UIGate {
		if rule == nil || rule.Selector == "" {
			continue
		}
		css += "\nhtml:not(.cladone-evaluated) " +
			rule.Selector + "{display:none !important}"
	}
	return css
}

// guardScript: the guard script, LOCKED by tests (guardInjectedLen,
// node parity). The JS lives outside the Go code:
// guard/guard.js.tmpl (go:embed); the %[n]s are substituted by the
// buildInjectors Sprintf (login, probe, uiGate, badge, rewrite, patch,
// forbidden).
//
//go:embed guard/guard.js.tmpl
var guardScriptFS embed.FS

var guardScript = func() string {
	b, err := guardScriptFS.ReadFile("guard/guard.js.tmpl")
	if err != nil {
		panic("guard template: " + err.Error())
	}
	return string(b)
}()

var headOpen = regexp.MustCompile(`(?i)<head[^>]*>`)

// charsetMeta: encoding declaration of the served site inside the
// <head>. The browser only scans the FIRST 1024 bytes to detect it —
// the guard script (~28 KB) inserted BEFORE it pushed it out of the
// window: the browser fell back to windows-1252 and displayed
// "DÃ©connexion" (2026-10-17 incident). Injection therefore happens
// AFTER that meta when it is within the window.
var charsetMeta = regexp.MustCompile(`(?i)<meta[^>]*charset[^>]*>`)

// encodingSniffWindow: the browsers' encoding detection window
// (charset meta looked for in the first 1024 bytes).
const encodingSniffWindow = 1024

// maxGuardBody (32 MiB buffering budget) DISAPPEARED with streaming
// injection (2026-10-18): the body is no longer read, it flows
// through. See guardStream.

// guardEnabledFor resolves the route's authGuard policy: active by
// default on frontend routes, opt-out via {"enabled": false}, no-op on
// non-frontend routes.
func guardEnabledFor(route *core.Route) bool {
	if route.Frontend != true {
		return false
	}
	if route.AuthGuard == nil {
		return true
	}
	if route.AuthGuard.Enabled != nil {
		return *route.AuthGuard.Enabled
	}
	return true
}

// guardLoginURL returns the login URL configured for the guard, if any.
// (a route's login URL resolves via core.Config.LoginURLFor:
// authGuard.loginUrl wins over oidc.loginUrl — load-time validation
// guarantees an active-guard route has one).

// injectGuardScript installs the guard injection IN STREAMING mode: the
// body is no longer buffered (the pre-2026-10-18 algorithm read up to
// 32 MiB into memory) — the byte arriving from the origin goes out
// toward the client, memory stays O(1) and the browser starts
// rendering from the first chunk (TTFB == the origin's; the 6 MB
// proxified book renders page by page during download).
//
// With a size-changing exchange (script inserted), Content-Length is
// removed: the response goes out chunked, and ReverseProxy flushes
// after every write as soon as ContentLength is -1 (it reads the
// decision from resp.ContentLength). Pages LARGER than any limit:
// served IN FULL and injected — the 2026-10-17 truncation incident
// is structurally impossible (no ReadAll anymore).
func injectGuardScript(resp *http.Response, script string) {

	// The body changes size (~28 KB script inserted): the response is
	// served chunked. Clear in the pipeline: gzip decompression is
	// also streaming, Content-Encoding is already gone (that removal
	// remains a safety net, never a trigger).
	resp.Header.Del("Content-Length")
	resp.Header.Del("Content-Encoding")
	resp.ContentLength = -1
	resp.Body = newGuardStream(resp.Body, script)
}

// injectScanWindow: maximum bytes retained to decide the insertion
// point. Concretely the decision lands around byte 1024 (end of the
// encoding detection window) — <head> is within the first bytes of
// any real document; beyond the window without a <head> (framework
// app HTML fragment), historical fallback: the script is inserted at
// the very start of the document, then the rest of the body flows
// through.
const injectScanWindow = 64 << 10

// decideInjection: EXACT PARITY with the historical buffered
// algorithm (before streaming, 2026-10-18):
//   - <head> found: insertion AFTER it, but AFTER the charset meta
//     when the latter is WITHIN THE DETECTION WINDOW (< 1024 bytes of
//     the original document) — otherwise the browser decodes as
//     windows-1252 and displays "DÃ©connexion" (2026-10-17 incident);
//   - no <head> within the window: ok=false — the caller decides the
//     fallback: the GUARD inserts at the very start (historical
//     fallback of headless pages, it MUST get through); custom
//     content is SKIPPED (fail-open: never a snippet before
//     <!doctype).
//
// Returns (insertion index in buf, ok); ok=false means "no
// insertion possible" (head absent at window/EOF); index -1 means
// "not yet decided — read more"; eof=true forces the final decision
// (end of body, transport error included).
func decideInjection(buf []byte, eof bool) (int, bool) {

	if idx := headOpen.FindIndex(buf); idx != nil {
		if len(buf) < encodingSniffWindow && !eof {
			return -1, true // the charset meta may still appear up to 1024
		}
		injectAt := idx[1]
		sniff := buf
		if len(sniff) > encodingSniffWindow {
			sniff = sniff[:encodingSniffWindow]
		}
		if m := charsetMeta.FindIndex(sniff); m != nil && m[1] > injectAt {
			injectAt = m[1]
		}
		return injectAt, true
	}

	// no <head>: search up to the window, then fail-open.
	if len(buf) < injectScanWindow && !eof {
		return -1, true
	}
	return 0, false
}

// guardStream flows the body through and inserts the script once,
// at the point chosen from the first bytes. Everything following the
// injection passes WITHOUT a re-read copy: the 6 MB of the proxified
// book never reside in gateway memory.
//
// skipNF (custom content): without a <head> in the window, the
// content is SKIPPED (fail-open, never a snippet before <!doctype) —
// the guard keeps its historical fallback (insertion at the top: it
// MUST get through).
type guardStream struct {
	src    io.ReadCloser
	script string
	skipNF bool

	scratch  []byte // recycled read buffer
	buf      []byte // bytes held pending decision (≤ window)
	pend     []byte // bytes to emit (prefix + script + rest of buf)
	pendOff  int
	decided  bool
	streamed bool  // pend exhausted: direct passthrough
	err      error // transport error (served after pend, never swallowed)
}

func newGuardStream(src io.ReadCloser, script string) *guardStream {
	return &guardStream{
		src:     src,
		script:  script,
		scratch: make([]byte, 4096),
	}
}

func (g *guardStream) Read(p []byte) (int, error) {

	for g.pendOff >= len(g.pend) {

		if g.streamed {
			if g.err != nil {
				return 0, g.err // propagated, never silent
			}
			return g.src.Read(p)
		}

		n, rerr := g.src.Read(g.scratch)
		if n > 0 {
			g.buf = append(g.buf, g.scratch[:n]...)
		}
		eof := rerr == io.EOF
		if rerr != nil && !eof {
			if g.err == nil {
				g.err = rerr
			}
			// immediate decision on the bytes already arrived
			// (the underlying error will tick the copyResponse)
			eof = true
		}
		injectAt, ok := decideInjection(g.buf, eof)
		if injectAt < 0 {
			continue // buffer bounded by injectScanWindow
		}
		if !ok {
			// no <head> (framework app fragment): the guard
			// prefixes (historical behavior), custom content skips.
			if g.skipNF {
				g.pend = append(g.pend[:0], g.buf...)
				g.buf = nil
				g.streamed = true
				g.decided = true
				continue
			}
			injectAt = 0
		}
		g.decided = true
		out := make([]byte, 0, len(g.buf)+len(g.script))
		out = append(out, g.buf[:injectAt]...)
		out = append(out, g.script...)
		out = append(out, g.buf[injectAt:]...)
		g.pend = out
		g.pendOff = 0
		g.buf = nil
		g.streamed = true
	}

	n := copy(p, g.pend[g.pendOff:])
	g.pendOff += n
	return n, nil
}

func (g *guardStream) Close() error {
	return g.src.Close()
}
