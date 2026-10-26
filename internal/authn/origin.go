package authn

import (
	"net"
	"net/url"
	"strings"
)

// originPolicy validates returnTo / postMessage origins for the
// native providers: only the shared cookie domain (and its
// subdomains) and the configured application/login hosts are allowed.
// This is the anti-open-redirect gate for the login flow.
type originPolicy struct {
	allowed      map[string]bool
	cookieDomain string
}

func newOriginPolicy(cookieDomain string, hosts []string) *originPolicy {
	p := &originPolicy{
		allowed:      map[string]bool{},
		cookieDomain: normalizeHost(cookieDomain),
	}
	if p.cookieDomain != "" {
		p.allowed[p.cookieDomain] = true
	}
	for _, h := range hosts {
		if h = normalizeHost(h); h != "" {
			p.allowed[h] = true
		}
	}
	return p
}

func (p *originPolicy) allowedHost(host string) bool {
	h := normalizeHost(host)
	if h == "" {
		return false
	}
	if p.allowed[h] {
		return true
	}
	return p.cookieDomain != "" &&
		strings.HasSuffix(h, "."+p.cookieDomain)
}

func (p *originPolicy) allowedOrigin(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() {
		return false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return false
	}
	return p.allowedHost(u.Host)
}

func (p *originPolicy) safeReturnTo(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "/"
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "/"
	}
	if u.IsAbs() {
		if (u.Scheme == "http" || u.Scheme == "https") &&
			p.allowedHost(u.Host) {
			return u.String()
		}
		return "/"
	}
	if strings.HasPrefix(raw, "//") || !strings.HasPrefix(raw, "/") {
		return "/"
	}
	return raw
}

func normalizeHost(h string) string {
	h = strings.TrimSpace(strings.ToLower(h))
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	return strings.Trim(h, "[]")
}
