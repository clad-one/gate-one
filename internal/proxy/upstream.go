package proxy

import (
	"log"
	"net/http"
	"net/url"
	"strings"

	"cladone/gate-one/internal/core"
)

// applyUpstreamDirector finalizes the outgoing request according to
// a route's upstream policy. The Host header follows the policy:
// historical default = public host preserved (internal-network
// backends, the req.Host = u.Host line left commented out for a
// long time in the Director); upstream.host/hostOverride = backend
// origin — required for an external site that routes by Host (e.g.
// Cloudflare). TLS/SNI negotiation, however, always targets the
// backend origin (Go's standard transport, derived from req.URL).
//
// Static headers are set with Set (overwriting any value sent by
// the client); value "" = header removed from the request (never
// transmitted empty). These values are never logged (secrets:
// basic auth, service tokens).
func applyUpstreamDirector(
	up *core.UpstreamPolicy,
	backend *url.URL,
	req *http.Request,
) {

	switch {
	case up.HostOverride != "":
		req.Host = up.HostOverride
	case up.Host != nil && *up.Host:
		req.Host = backend.Host
	}

	for k, v := range up.Headers {
		if v == "" {
			req.Header.Del(k)
			continue
		}
		req.Header.Set(k, v)
	}
}

// upstreamResponseModifier returns the upstream policy's response
// modifier: rewriting of absolute Locations targeting the backend
// origin toward the public host (otherwise the browser would leave
// the proxy at the target site's first absolute redirect), then
// adjustment of response headers (set/remove — e.g. removing an
// origin Content-Security-Policy that would block the injected
// tags). Installed UPSTREAM of the guard/PWA injections in the
// ModifyResponse chain (those only touch 200 HTML bodies — the
// order has no effect on them).
func upstreamResponseModifier(
	route *core.Route,
	backend *url.URL,
) func(*http.Response) error {

	up := route.Upstream
	publicHost := normalizeHost(route.Host)

	return func(resp *http.Response) error {

		if up.RewriteRedirects != nil && *up.RewriteRedirects {
			// the Location's replacement origin mirrors the CLIENT
			// request (scheme + host:port) — in the demo the gateway
			// runs on a non-standard port: an https-only or
			// port-less Location would throw the browser out of the
			// proxy. Absent context (direct test calls): the
			// historical https + route host.
			origin := "https://" + publicHost
			if resp.Request != nil {
				if scheme := requestSchemeOut(resp.Request); scheme != "" {
					if host := requestHostOut(resp.Request); host != "" {
						origin = scheme + "://" + host
					}
				}
			}
			rewriteUpstreamLocation(backend, origin, resp)
		}

		if rc := up.RewriteCookies; rc != nil {
			rewriteUpstreamCookies(route, backend, publicHost, rc, resp)
		}

		if rh := up.ResponseHeaders; rh != nil {
			for _, name := range rh.Remove {
				resp.Header.Del(name)
			}
			for k, v := range rh.Set {
				if v == "" {
					resp.Header.Del(k)
					continue
				}
				resp.Header.Set(k, v)
			}
		}

		return nil
	}
}

// rewriteUpstreamLocation rewrites the response's Location header
// in place when it targets the backend origin in absolute form
// (scheme://backend.host/...): the CLIENT origin (scheme://host:port,
// e.g. http://wikipedia.demo.localhost:3000 in the demo — https in
// production), path/query/fragment preserved. Relative Locations and
// those targeting another origin (e.g. a Cloudflare Access team
// domain) pass untouched.
func rewriteUpstreamLocation(
	backend *url.URL,
	publicOrigin string,
	resp *http.Response,
) {

	loc := resp.Header.Get("Location")
	if loc == "" {
		return
	}

	ru, err := url.Parse(loc)
	if err != nil || ru.Host == "" {
		return // relative (or unparseable): nothing to rewrite
	}

	// Only redirects toward the backend's own origin are brought
	// back to the public host — another origin does not belong to
	// us (e.g. Cloudflare Access login on the team domain).
	if ru.Host != backend.Host ||
		(ru.Scheme != "" && ru.Scheme != backend.Scheme) {
		return
	}

	origin, err := url.Parse(publicOrigin)
	if err != nil {
		return
	}

	ru.Scheme = origin.Scheme
	ru.Host = origin.Host

	resp.Header.Set("Location", ru.String())
}

// cookie names reserved for the gateway session (set by auth-bridge
// on the same public host as every proxified site): a Set-Cookie
// from the origin carrying one of them would overwrite the
// browser's auth.
var reservedCookieNames = map[string]bool{
	"access_token":  true,
	"refresh_token": true,
	"id_token":      true,
	"session":       true,
}

// rewriteUpstreamCookies translates Set-Cookies set by the origin
// toward the public host (upstream.rewriteCookies policy). A Domain
// attribute targeting the origin host (or a parent) is rejected by
// the browser from the public host: "rewrite" mode = transposed to
// the public host (the sharing scope — host + subdomains — is
// faithfully translated), "strip" mode = attribute removed
// (host-only on the public host). Other cookies pass intact —
// textual surgery on the original line: the other attributes (Path,
// Secure, HttpOnly, SameSite, Expires…) come out byte-exact.
// Headers only: no body/stream impact.
func rewriteUpstreamCookies(
	route *core.Route,
	backend *url.URL,
	publicHost string,
	rc *core.RewriteCookiesPolicy,
	resp *http.Response,
) {

	lines := resp.Header["Set-Cookie"]
	if len(lines) == 0 {
		return
	}

	out := make([]string, 0, len(lines))
	for _, line := range lines {
		name, _, _ := strings.Cut(line, "=")
		name = strings.TrimSpace(name)
		if reservedCookieNames[name] {
			// the name, never the value
			log.Printf(
				"COOKIE dropped host=%s: reserved name %q — an origin Set-Cookie would overwrite the gateway session",
				route.Host, name)
			continue
		}
		out = append(out, rewriteCookieDomain(
			line, backend.Hostname(), publicHost, rc.Domain))
	}
	resp.Header["Set-Cookie"] = out
}

// rewriteCookieDomain applies a Set-Cookie's Domain rule: a Domain
// targeting the origin host (equal or parent) → rewritten to the
// public host ("rewrite") or removed ("strip"); everything else
// comes out byte-exact.
func rewriteCookieDomain(line, originHost, publicHost, mode string) string {

	// attributes: from the first ';' outside quotes (a quoted value
	// may contain one)
	domainStart, domainEnd := -1, -1
	off := nextUnquotedSemicolon(line)
	for off >= 0 {
		rest := line[off+1:]
		attrEnd := len(line)
		var attr string
		if n := nextUnquotedSemicolon(rest); n < 0 {
			attr = rest // dernier attribut
		} else {
			attr = rest[:n]
			attrEnd = off + 1 + n
		}

		key, val, _ := strings.Cut(attr, "=")
		if strings.EqualFold(strings.TrimSpace(key), "domain") {
			dv := strings.Trim(strings.TrimSpace(val), `"`)
			dv = strings.TrimPrefix(dv, ".") // historical RFC .host form
			dv = strings.ToLower(dv)
			if dv == originHost || strings.HasSuffix(originHost, "."+dv) {
				domainStart, domainEnd = off, attrEnd
			}
			break // first Domain attribute: subsequent ones are illegal
		}
		if attrEnd >= len(line) {
			break // last attribute processed
		}
		// attrEnd = index of the ';' opening the next attribute — the
		// next iteration examines the one following it (off+1)
		off = attrEnd
	}
	if domainStart < 0 {
		return line // no Domain targeting the origin: untouched
	}

	if mode == "strip" {
		// the attribute AND its separator leave together
		return line[:domainStart] + line[domainEnd:]
	}
	// only the VALUE is replaced: the original "Domain=" key (case,
	// spacing) comes out as-is
	eq := domainStart + strings.Index(line[domainStart:domainEnd], "=")
	return line[:eq+1] + publicHost + line[domainEnd:]
}

// nextUnquotedSemicolon: index of the first ';' outside a quoted
// value, -1 if none.
func nextUnquotedSemicolon(s string) int {
	inQuote := false
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '"':
			inQuote = !inQuote
		case ';':
			if !inQuote {
				return i
			}
		}
	}
	return -1
}
