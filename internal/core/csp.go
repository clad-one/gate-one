package core

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// Content-Security-Policy emitted (or amended) by the gateway.
//
// The gateway is the only component that can do this correctly: a
// strict policy needs a per-response nonce, and the nonce must be
// written into the HTML it already rewrites (guard, PWA, custom
// injections). An edge proxy could add a static header, never a nonce.
//
// Two invariants:
//   - an origin policy is NEVER removed or weakened: the gateway adds
//     its own policy as a SECOND header (browsers enforce all of them,
//     so the effective rule is the strictest) and only APPENDS the
//     hashes of its own injected scripts to the origin's script-src;
//   - the hashes of the scripts the gateway injects are computed at
//     route compile time (guard template, PWA wiring, custom bundle) —
//     no buffering, and they are stable across requests.

// DefaultCSPReportPath: gateway-served collector for CSP violations
// (report-uri). Consumed by the ring buffer, never proxied.
const DefaultCSPReportPath = "/__gate-one_csp/report"

// CSPPolicy: route-level policy.
type CSPPolicy struct {
	// Mode:
	//   "off"   — nothing (the origin's policy, if any, passes as-is);
	//   "merge" — keep the origin policy and only add the hashes of the
	//             gateway's injected scripts (no policy of our own);
	//   "hash"  — emit our policy with the injected scripts' hashes;
	//   "nonce" — emit our policy with a per-response nonce and stamp
	//             the HTML (streaming, O(1) memory).
	Mode string `json:"mode"`

	// ReportOnly: emit Content-Security-Policy-Report-Only instead of
	// the enforcing header (progressive rollout: violations are
	// collected, nothing is blocked).
	ReportOnly bool `json:"reportOnly,omitempty"`

	// Own: the gateway OWNS the policy — the origin's enforced and
	// report-only CSP headers are removed before ours is emitted.
	// This is the only way to avoid a second, independent policy; it
	// is opt-in and never silent (logged at build time). Requires
	// mode nonce or hash and reportOnly=false: stripping the origin's
	// enforcing policy to replace it with a report-only one would
	// remove protection without enforcing anything.
	Own bool `json:"own,omitempty"`

	// ReportTo: path served by the gateway collecting the reports.
	// Default: /__gate-one_csp/report.
	ReportTo string `json:"reportTo,omitempty"`

	// StampScripts: "inline" (default) = only <script> tags WITHOUT a
	// src attribute receive the nonce; "all" = every <script> tag
	// (including external ones — only meaningful with a host allow-list
	// or 'strict-dynamic'). Nonce mode only.
	StampScripts string `json:"stampScripts,omitempty"`

	// Directives: directive name → sources. A source list is accepted
	// as a string ("'self' https://x") or an array. The gateway appends
	// the nonce (nonce mode) and the injected scripts' hashes to
	// script-src, and report-uri when ReportTo is set.
	Directives map[string]DirectiveSources `json:"directives,omitempty"`
}

// DirectiveSources: CSP source list, declared as one string or as an
// array of tokens (both forms are natural in JSON).
type DirectiveSources []string

// UnmarshalJSON accepts "src1 src2" or ["src1", "src2"].
func (d *DirectiveSources) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		*d = DirectiveSources{s}
		return nil
	}
	var list []string
	if err := json.Unmarshal(b, &list); err != nil {
		return fmt.Errorf("expected a string or an array of strings")
	}
	*d = DirectiveSources(list)
	return nil
}

// Path: the collector path (default when absent).
func (c *CSPPolicy) Path() string {
	if c == nil || c.ReportTo == "" {
		return DefaultCSPReportPath
	}
	return c.ReportTo
}

// Nonce: a per-response nonce must be generated and the body stamped.
func (c *CSPPolicy) Nonce() bool { return c != nil && c.Mode == "nonce" }

// Emits: the gateway emits a policy of its own (nonce or hash).
func (c *CSPPolicy) Emits() bool {
	return c != nil && (c.Mode == "nonce" || c.Mode == "hash")
}

// StampsAll: every <script> tag is stamped, external ones included.
func (c *CSPPolicy) StampsAll() bool {
	return c != nil && c.StampScripts == "all"
}

// Header: the response header carrying the policy.
func (c *CSPPolicy) Header() string {
	if c != nil && c.ReportOnly {
		return "Content-Security-Policy-Report-Only"
	}
	return "Content-Security-Policy"
}

// cspDirectiveName: RFC token-ish directive name.
var cspDirectiveName = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9-]{0,63}$`)

// validateCSP: a declared policy must be usable as-is — a typo in the
// mode would otherwise silently disable the protection.
func validateCSP(c *CSPPolicy) error {

	switch c.Mode {
	case "off", "merge", "hash", "nonce":
	default:
		return fmt.Errorf(
			"csp.mode %q (expected \"off\", \"merge\", \"hash\" or \"nonce\")",
			c.Mode)
	}

	if c.ReportOnly && !c.Emits() {
		return fmt.Errorf(
			"csp.reportOnly requires mode \"nonce\" or \"hash\" (mode %q emits no policy)",
			c.Mode)
	}

	if c.Own {
		if c.Mode != "nonce" && c.Mode != "hash" {
			return fmt.Errorf(
				"csp.own requires mode \"nonce\" or \"hash\" " +
					"(it removes the origin policy and emits ours)")
		}
		if c.ReportOnly {
			return fmt.Errorf(
				"csp.own cannot be reportOnly: removing the origin's " +
					"enforcing policy to emit a report-only one would " +
					"remove protection without enforcing anything")
		}
	}

	if c.ReportTo != "" {
		if !strings.HasPrefix(c.ReportTo, "/") ||
			strings.ContainsAny(c.ReportTo, " \t\r\n?#") {
			return fmt.Errorf(
				"csp.reportTo %q (expected a local absolute path, e.g. %s)",
				c.ReportTo, DefaultCSPReportPath)
		}
	}

	switch c.StampScripts {
	case "":
	case "inline", "all":
		if c.Mode != "nonce" {
			return fmt.Errorf(
				"csp.stampScripts %q requires mode \"nonce\"",
				c.StampScripts)
		}
	default:
		return fmt.Errorf(
			"csp.stampScripts %q (expected \"inline\" or \"all\")",
			c.StampScripts)
	}

	for name, sources := range c.Directives {
		if !cspDirectiveName.MatchString(name) {
			return fmt.Errorf("csp.directives: invalid name %q", name)
		}
		if len(sources) == 0 {
			return fmt.Errorf("csp.directives.%s: empty source list", name)
		}
		for _, s := range sources {
			if strings.TrimSpace(s) == "" {
				return fmt.Errorf("csp.directives.%s: empty source", name)
			}
			// A newline here would inject a second header line.
			if strings.ContainsAny(s, "\r\n") {
				return fmt.Errorf(
					"csp.directives.%s: control character in %q",
					name, s)
			}
		}
	}

	return nil
}
