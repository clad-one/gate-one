package proxy

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"cladone/gate-one/internal/core"
	"cladone/gate-one/internal/license"
)

// licenceGuard checks that every host the gateway serves is covered by
// the active licence. The licence carries one token per period; the
// merged `domains` are suffixes (a suffix covers its subdomains), so a
// customer lists `exemple.fr` and `corp.local`, not every host.
//
// Modes (license.enforce):
//   - info (default): log at info level, keep serving;
//   - warn: log as a warning, keep serving;
//   - strict: answer 503 on an uncovered host.
//
// A missing, expired or not-yet-active licence never blocks: evaluation
// (eval) is a commercial state, not a routing error.
type licenceGuard struct {
	mode    string
	domains []string
	state   string

	mu       sync.Mutex
	reported map[string]bool
}

func newLicenceGuard(cfg *core.Config, now time.Time) *licenceGuard {
	if cfg == nil || cfg.License == nil {
		return nil
	}
	st := license.Eval(cfg.License, now)
	mode := license.EnforceMode(cfg.License)
	g := &licenceGuard{
		mode:     mode,
		domains:  st.Domains,
		state:    st.State,
		reported: map[string]bool{},
	}
	if st.State != "registered" {
		// Nothing to check against: eval keeps its previous behaviour
		// (info only, and only once at startup).
		if mode != license.EnforceInfo {
			log.Printf(
				"license: state=%s, host coverage not enforced (%s)",
				st.State, mode)
		}
		return g
	}
	uncovered := license.Uncovered(licensedHosts(cfg), st.Domains)
	for _, host := range uncovered {
		g.report(host)
	}
	if len(uncovered) > 0 && mode == license.EnforceStrict {
		log.Printf(
			"license: %d host(s) outside the licence will answer 503: %s",
			len(uncovered), strings.Join(uncovered, ", "))
	}
	return g
}

// check returns false when the request must be refused (strict mode and
// an uncovered host).
func (g *licenceGuard) check(host string) bool {
	if g == nil || g.state != "registered" {
		return true
	}
	if license.Covered(host, g.domains) {
		return true
	}
	g.report(host)
	return g.mode != license.EnforceStrict
}

// report logs an uncovered host once per process (a SIGHUP reload builds
// a new guard and re-reports, which is what an operator wants to see).
func (g *licenceGuard) report(host string) {
	if g == nil || g.state != "registered" {
		return
	}
	host = strings.ToLower(strings.TrimSpace(host))
	if i := strings.LastIndex(host, ":"); i > 0 && strings.Count(host, ":") == 1 {
		host = host[:i] // strip the port: one report per host
	}
	g.mu.Lock()
	if g.reported[host] {
		g.mu.Unlock()
		return
	}
	g.reported[host] = true
	g.mu.Unlock()

	msg := "license: host %q is not covered by the active licence (%s); " +
		"add the suffix to the licence, or remove the host"
	level := "info"
	if g.mode != license.EnforceInfo {
		level = "warning"
	}
	log.Printf("%s: %s", level, fmt.Sprintf(msg, host, strings.Join(g.domains, ", ")))
}

// licensedHosts collects every public host the configuration can serve:
// route hosts, login bases and cookie domains (default and named
// providers). Loopback hosts are filtered later by license.Covered.
func licensedHosts(cfg *core.Config) []string {
	var hosts []string
	addURLHost := func(raw string) {
		h := hostFromURL(raw)
		if h != "" {
			hosts = append(hosts, h)
		}
	}
	for i := range cfg.Routes {
		r := &cfg.Routes[i]
		if r.Host != "" {
			hosts = append(hosts, r.Host)
		}
		hosts = append(hosts, r.Hosts...)
	}
	providers := append([]*core.AuthProviderConfig{}, cfg.AuthProviders...)
	if cfg.AuthProvider != nil {
		providers = append(providers, cfg.AuthProvider)
	}
	for _, p := range providers {
		addURLHost(p.LoginBaseURL)
		if p.CookieDomain != "" {
			hosts = append(hosts, strings.TrimPrefix(p.CookieDomain, "."))
		}
	}
	for _, g := range cfg.SSOGroups {
		for _, p := range g.Providers {
			addURLHost(p.LoginBaseURL)
			if p.CookieDomain != "" {
				hosts = append(hosts, strings.TrimPrefix(p.CookieDomain, "."))
			}
		}
	}
	return hosts
}

func hostFromURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if i := strings.Index(raw, "://"); i >= 0 {
		raw = raw[i+3:]
	}
	if i := strings.IndexAny(raw, "/?#"); i >= 0 {
		raw = raw[:i]
	}
	return raw
}

func writeLicenceUnavailable(w http.ResponseWriter, host string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusServiceUnavailable)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error": "license_uncovered_host",
		"host":  host,
		"hint":  "this host is not part of the active licence",
	})
}
