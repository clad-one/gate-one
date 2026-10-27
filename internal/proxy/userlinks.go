package proxy

import (
	"fmt"
	"log"
	"net/url"
	"strings"

	"cladone/gate-one/internal/core"
)

// maxMergedUserLinks bounds the final badge link list after merging
// connector-owned links and application links.
const maxMergedUserLinks = 8

// baseUserLinks builds the connector-owned links once per gateway
// load:
//   - authProvider.links.account: the IdP's own console (explicit URL;
//     OIDC defines no standard account URL);
//   - tokenBroker.links.services: the token-broker connections page,
//     only when an exposed route actually delegates (the gateway is
//     the only component that knows this; the connector cannot).
func baseUserLinks(cfg *core.Config, hasDelegated bool) []core.UserLink {
	var out []core.UserLink

	if cfg.AuthProvider != nil && cfg.AuthProvider.Links != nil {
		if l := cfg.AuthProvider.Links.Account; l != nil {
			out = append(out, normalizeUserLink(*l, "Account"))
		}
	}

	if cfg.TokenBroker != nil && cfg.TokenBroker.Links != nil {
		if l := cfg.TokenBroker.Links.Services; l != nil {
			if hasDelegated {
				out = append(out, normalizeUserLink(*l, "Services"))
			} else {
				log.Printf(
					"USERLINKS: tokenBroker.links.services is configured " +
						"but no exposed route delegates — link hidden")
			}
		}
	}

	return out
}

func normalizeUserLink(l core.UserLink, defaultLabel string) core.UserLink {
	l.URL = strings.TrimSpace(l.URL)
	l.Label = strings.TrimSpace(l.Label)
	if l.Label == "" {
		l.Label = defaultLabel
	}
	if l.Target == "" {
		l.Target = "_blank"
	}
	return l
}

// canonicalLinkURL is the dedup key. Absolute http(s) URLs have their
// scheme/host lowercased and an empty path normalized to "/"; relative
// links are compared as-is.
func canonicalLinkURL(raw string) string {
	raw = strings.TrimSpace(raw)
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() {
		return raw
	}
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)
	if u.Path == "" {
		u.Path = "/"
	}
	// A trailing slash is not significant for link dedup (the kept
	// URL is left untouched; only the comparison key is normalized).
	if len(u.Path) > 1 {
		u.Path = strings.TrimSuffix(u.Path, "/")
	}
	return u.String()
}

// mergeUserLinks merges in order: account, services (already filtered
// by hasDelegated), application links. The first URL wins; duplicates
// are dropped. The guard receives the final list and renders it as-is.
func mergeUserLinks(
	base, app []core.UserLink,
) ([]core.UserLink, error) {
	out := make([]core.UserLink, 0, len(base)+len(app))
	seen := make(map[string]bool, len(base)+len(app))

	add := func(l core.UserLink) {
		key := canonicalLinkURL(l.URL)
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, l)
	}
	for _, l := range base {
		add(l)
	}
	for _, l := range app {
		add(normalizeUserLink(l, ""))
	}

	if len(out) > maxMergedUserLinks {
		return nil, fmt.Errorf(
			"userBadge links: %d after merge (max %d)",
			len(out), maxMergedUserLinks)
	}
	return out, nil
}
