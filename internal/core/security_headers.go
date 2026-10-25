package core

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// SecurityHeadersPolicy: platform-wide response hardening, emitted by
// the gateway on EVERY response it serves (proxied or generated:
// health, stats, guard 403, MCP metadata, PWA assets, CSP collector).
//
// All the fields are optional: a declared block applies the secure
// defaults (HSTS 180 days, nosniff, strict-origin-when-cross-origin),
// while each field can be tightened or disabled explicitly. The
// referrer policy is only set when the response does not already
// carry one (a proxified app's stricter policy wins).
type SecurityHeadersPolicy struct {
	// HSTSMaxAge: Strict-Transport-Security max-age in seconds.
	// Absent = 180 days; 0 = header omitted (e.g. a host that must
	// stay reachable in plain HTTP).
	HSTSMaxAge *int `json:"hstsMaxAge,omitempty"`
	// HSTSIncludeSubDomains: add includeSubDomains (only when every
	// subdomain is HTTPS-only — with preload this is permanent).
	HSTSIncludeSubDomains bool `json:"hstsIncludeSubDomains,omitempty"`
	// HSTSPreload: add preload. Requires HSTSIncludeSubDomains.
	HSTSPreload bool `json:"hstsPreload,omitempty"`
	// NoSniff: X-Content-Type-Options: nosniff. Absent = true.
	NoSniff *bool `json:"nosniff,omitempty"`
	// ReferrerPolicy: Referrer-Policy value. Absent =
	// "strict-origin-when-cross-origin"; empty string = header
	// omitted.
	ReferrerPolicy *string `json:"referrerPolicy,omitempty"`
}

const (
	// DefaultHSTSMaxAge: 180 days — long enough to matter, short
	// enough to back out (no preload).
	DefaultHSTSMaxAge = 15552000
	// maxHSTSMaxAge: two years; beyond that a misconfiguration is
	// effectively impossible to undo in browsers that cached it.
	maxHSTSMaxAge = 63072000

	DefaultReferrerPolicy = "strict-origin-when-cross-origin"
)

// referrerPolicies: the values defined by the Referrer Policy spec.
var referrerPolicies = map[string]bool{
	"no-referrer":                     true,
	"no-referrer-when-downgrade":      true,
	"origin":                          true,
	"origin-when-cross-origin":        true,
	"same-origin":                     true,
	"strict-origin":                   true,
	"strict-origin-when-cross-origin": true,
	"unsafe-url":                      true,
}

// HSTS: the Strict-Transport-Security value ("" = header omitted).
func (p *SecurityHeadersPolicy) HSTS() string {
	if p == nil {
		return ""
	}
	age := DefaultHSTSMaxAge
	if p.HSTSMaxAge != nil {
		age = *p.HSTSMaxAge
	}
	if age <= 0 {
		return ""
	}
	v := "max-age=" + strconv.Itoa(age)
	if p.HSTSIncludeSubDomains {
		v += "; includeSubDomains"
	}
	if p.HSTSPreload {
		v += "; preload"
	}
	return v
}

// NoSniffEnabled: X-Content-Type-Options (default on).
func (p *SecurityHeadersPolicy) NoSniffEnabled() bool {
	if p == nil {
		return false
	}
	return p.NoSniff == nil || *p.NoSniff
}

// Referrer: the Referrer-Policy value ("" = header omitted).
func (p *SecurityHeadersPolicy) Referrer() string {
	if p == nil {
		return ""
	}
	if p.ReferrerPolicy == nil {
		return DefaultReferrerPolicy
	}
	return *p.ReferrerPolicy
}

// validateSecurityHeaders: a declared block must be usable as-is.
func validateSecurityHeaders(p *SecurityHeadersPolicy) error {

	if p.HSTSMaxAge != nil {
		if *p.HSTSMaxAge < 0 || *p.HSTSMaxAge > maxHSTSMaxAge {
			return fmt.Errorf(
				"securityHeaders.hstsMaxAge %d (expected 0..%d seconds)",
				*p.HSTSMaxAge, maxHSTSMaxAge)
		}
	}
	if p.HSTSPreload && !p.HSTSIncludeSubDomains {
		return fmt.Errorf(
			"securityHeaders.hstsPreload requires hstsIncludeSubDomains " +
				"(a preload without subdomains is rejected by browsers)")
	}
	if p.ReferrerPolicy != nil {
		v := *p.ReferrerPolicy
		if v != "" && !referrerPolicies[v] {
			return fmt.Errorf(
				"securityHeaders.referrerPolicy %q (expected one of: %s)",
				v, strings.Join(referrerPolicyList(), ", "))
		}
		if strings.ContainsAny(v, "\r\n") {
			return fmt.Errorf(
				"securityHeaders.referrerPolicy: control character")
		}
	}
	return nil
}

func referrerPolicyList() []string {
	out := make([]string, 0, len(referrerPolicies))
	for v := range referrerPolicies {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}
