package core

// Cloudflare Turnstile: a PLATFORM-WIDE bot check for form pages.
//
// The block is deliberately top-level rather than per route: the goal
// is to enable it once and have every matching page (including pages
// proxified by Gate One) receive the widget, with the POST verified
// before the backend sees it. Operators keep a single place to change,
// which removes the "forgot the policy on one host" drift. It does NOT
// protect traffic that reaches the application without passing through
// this Gate One instance: network isolation remains the operator's
// responsibility (documented).
//
// There is no plugin here: the verification runs on the request path,
// before the backend, like rateLimit/quota. A plugin must never sit
// there (AC-AUTH-07).

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
	"time"
)

// DefaultTurnstileTokenHeader: the header accepted in addition to the
// form field. Fetch/SPA clients can send the token there; the injected
// script also attaches it to same-origin requests when it can.
const DefaultTurnstileTokenHeader = "X-Turnstile-Response"

// TurnstileFormField is the hidden input Turnstile adds to a form.
const TurnstileFormField = "cf-turnstile-response"

// Turnstile modes.
const (
	// TurnstileModeForms: inject the widget into forms and verify the
	// configured methods (the historical behaviour).
	TurnstileModeForms = "forms"
	// TurnstileModeGate: challenge the first request to a protected
	// path, set a signed clearance cookie, let the following requests
	// through without a new Siteverify call.
	TurnstileModeGate = "gate"
	// TurnstileModeBoth: gate the site AND verify form submissions.
	TurnstileModeBoth = "both"
)

// DefaultTurnstileClearanceTTL is the clearance cookie lifetime (30
// minutes).
const DefaultTurnstileClearanceTTL = 1800

// clearanceKeyLabel: domain separation when the clearance key is
// derived from the Turnstile secret.
const clearanceKeyLabel = "gate-one/turnstile/clearance/v1"

// TurnstileConfig is the top-level "turnstile" block.
type TurnstileConfig struct {
	// Enabled: presence of the block enables it; explicit false
	// disables it (templated configs). Default true.
	Enabled *bool `json:"enabled,omitempty"`

	// Mode selects the protection: "forms" (default), "gate" or
	// "both".
	Mode string `json:"mode,omitempty"`

	// SiteKey is the public widget key (safe in the page).
	SiteKey string `json:"siteKey"`

	// SecretEnv names the environment variable holding the secret
	// key. The secret is never serialized.
	SecretEnv string `json:"secretEnv"`
	Secret    string `json:"-"`

	// Hosts restricts the block to these hosts (exact or *.suffix).
	// Empty = every route.
	Hosts []string `json:"hosts,omitempty"`

	// Paths restricts the block to these paths, with the route.path
	// grammar ("/contact/*", exact path, "/*"). Empty = every path.
	Paths []string `json:"paths,omitempty"`

	// Methods are the request methods verified. Default: POST.
	Methods []string `json:"methods,omitempty"`

	// Forms are CSS selectors of the forms receiving the widget.
	// Empty = every POST form on the page.
	Forms []string `json:"forms,omitempty"`

	// Action is sent with the widget and required in the Siteverify
	// answer (1-32 chars: letters, digits, _ and -).
	Action string `json:"action,omitempty"`

	// Hostname is the expected hostname in the Siteverify answer.
	// Empty = no hostname check (the site key is already bound to its
	// domain list).
	Hostname string `json:"hostname,omitempty"`

	// TokenHeader: header accepted in addition to the form field.
	// Default X-Turnstile-Response.
	TokenHeader string `json:"tokenHeader,omitempty"`

	// ExemptPaths are never gated (gate/both): health, machine
	// endpoints, webhooks. The built-in exemptions (/healthz, /readyz,
	// /__gate-one/*, /favicon.ico, /robots.txt) always apply.
	ExemptPaths []string `json:"exemptPaths,omitempty"`

	// ClearanceTTLSeconds is the lifetime of the gate clearance
	// cookie. Default 1800 (30 minutes).
	ClearanceTTLSeconds int `json:"clearanceTtlSeconds,omitempty"`

	// ClearanceSecretEnv names the environment variable holding the
	// HMAC key signing the clearance cookie. Empty = derived from the
	// Turnstile secret with domain separation (rotating the Turnstile
	// secret then invalidates every clearance).
	ClearanceSecretEnv string `json:"clearanceSecretEnv,omitempty"`
	ClearanceSecret    []byte `json:"-"`

	// Challenge tunes the challenge page/widget (gate/both).
	Challenge *TurnstileChallenge `json:"challenge,omitempty"`

	// Preclearance makes the injected script solve the challenge in
	// the background when a page is served without a clearance
	// (default true in gate/both). The first user action then needs a
	// single backend call.
	Preclearance *bool `json:"preclearance,omitempty"`

	// Endpoint overrides the Siteverify URL (tests only; not part of
	// the public schema).
	Endpoint string `json:"-"`
}

// TurnstileChallenge tunes the challenge page (gate/both).
type TurnstileChallenge struct {
	// Appearance: "always", "execute" or "interaction-only" (Turnstile
	// render option). Default "interaction-only" for gate/both: the
	// widget stays hidden unless Cloudflare requires an interaction.
	Appearance string `json:"appearance,omitempty"`
}

// Active reports whether the block is enabled.
func (t *TurnstileConfig) Active() bool {
	return t != nil && (t.Enabled == nil || *t.Enabled)
}

// FormsEnabled reports whether form widgets are injected and form
// submissions verified.
func (t *TurnstileConfig) FormsEnabled() bool {
	return t != nil && (t.Mode == "" ||
		t.Mode == TurnstileModeForms || t.Mode == TurnstileModeBoth)
}

// GateEnabled reports whether the gate (challenge + clearance cookie)
// is active.
func (t *TurnstileConfig) GateEnabled() bool {
	return t != nil && (t.Mode == TurnstileModeGate ||
		t.Mode == TurnstileModeBoth)
}

// PreclearanceEnabled: background challenge on a served page.
func (t *TurnstileConfig) PreclearanceEnabled() bool {
	if t == nil || !t.GateEnabled() {
		return false
	}
	if t.Preclearance == nil {
		return true
	}
	return *t.Preclearance
}

// ClearanceTTL returns the clearance cookie lifetime.
func (t *TurnstileConfig) ClearanceTTL() time.Duration {
	secs := DefaultTurnstileClearanceTTL
	if t != nil && t.ClearanceTTLSeconds > 0 {
		secs = t.ClearanceTTLSeconds
	}
	return time.Duration(secs) * time.Second
}

// ChallengeAppearance: the Turnstile render appearance of the
// challenge widget.
func (t *TurnstileConfig) ChallengeAppearance() string {
	if t != nil && t.Challenge != nil && t.Challenge.Appearance != "" {
		return t.Challenge.Appearance
	}
	if t != nil && t.GateEnabled() {
		return "interaction-only"
	}
	return "always"
}

// Exempt reports whether path is never gated. The built-in exemptions
// protect probes, the gateway's own endpoints and the SEO files.
func (t *TurnstileConfig) Exempt(path string) bool {
	if path == "" {
		return false
	}
	switch path {
	case "/healthz", "/readyz", "/favicon.ico", "/robots.txt":
		return true
	}
	if strings.HasPrefix(path, "/__gate-one/") {
		return true
	}
	if t == nil {
		return false
	}
	for _, p := range t.ExemptPaths {
		if PathMatches(p, path) {
			return true
		}
	}
	return false
}

// AppliesTo reports whether the block covers (host, path).
func (t *TurnstileConfig) AppliesTo(host, path string) bool {
	return t.Active() && t.MatchesHost(host) && t.MatchesPath(path)
}

var turnstileActionPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,32}$`)

// PathMatches implements the route.path grammar for a standalone
// pattern: "/*" = everything, a trailing "/*" = prefix on a path
// boundary, otherwise an exact path. An empty pattern matches nothing
// (callers use an empty LIST to mean "all").
func PathMatches(pattern, path string) bool {
	if pattern == "" {
		return false
	}
	if pattern == "/*" {
		return true
	}
	if strings.HasSuffix(pattern, "/*") {
		base := strings.TrimSuffix(pattern, "/*")
		return path == base || strings.HasPrefix(path, base+"/")
	}
	return path == pattern
}

// HostMatches implements host patterns: exact (case-insensitive, port
// and trailing dot ignored) or a leading "*." wildcard on a label
// boundary.
func HostMatches(pattern, host string) bool {
	pattern = NormalizeHostPattern(pattern)
	host = NormalizeHostPattern(host)
	if pattern == "" {
		return true
	}
	if host == "" {
		return false
	}
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // ".example.com"
		return strings.HasSuffix(host, suffix) && len(host) > len(suffix)
	}
	return pattern == host
}

// NormalizeHostPattern: lowercase, no port, no trailing dot.
func NormalizeHostPattern(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimSuffix(s, ".")
	if host, _, err := net.SplitHostPort(s); err == nil {
		s = host
	}
	return strings.ToLower(s)
}

// PathsOverlap reports whether two route-path patterns can match the
// same request. Used to avoid installing the widget (and forcing gzip)
// on routes that can never serve a protected page.
func PathsOverlap(a, b string) bool {
	ab, ap := pathPattern(a)
	bb, bp := pathPattern(b)
	if ab == "" || bb == "" {
		return false
	}
	whole := func(base string, prefix bool) bool {
		return prefix && base == "/"
	}
	if whole(ab, ap) || whole(bb, bp) {
		return true
	}
	switch {
	case ap && bp:
		return ab == bb ||
			strings.HasPrefix(ab, bb+"/") ||
			strings.HasPrefix(bb, ab+"/")
	case ap: // a is a prefix, b is exact
		return b == ab || strings.HasPrefix(b, ab+"/")
	case bp:
		return a == bb || strings.HasPrefix(a, bb+"/")
	default:
		return a == b
	}
}

func pathPattern(p string) (string, bool) {
	if p == "" {
		return "", false
	}
	if p == "/*" {
		return "/", true
	}
	if strings.HasSuffix(p, "/*") {
		return strings.TrimSuffix(p, "/*"), true
	}
	return p, false
}

// MatchesHost reports whether the block applies to host.
func (t *TurnstileConfig) MatchesHost(host string) bool {
	if t == nil {
		return false
	}
	if len(t.Hosts) == 0 {
		return true
	}
	for _, p := range t.Hosts {
		if HostMatches(p, host) {
			return true
		}
	}
	return false
}

// MatchesPath reports whether the block applies to path.
func (t *TurnstileConfig) MatchesPath(path string) bool {
	if t == nil {
		return false
	}
	if len(t.Paths) == 0 {
		return true
	}
	for _, p := range t.Paths {
		if PathMatches(p, path) {
			return true
		}
	}
	return false
}

// MatchesMethod reports whether method is verified (default POST).
func (t *TurnstileConfig) MatchesMethod(method string) bool {
	if t == nil {
		return false
	}
	method = strings.ToUpper(strings.TrimSpace(method))
	for _, m := range t.Methods {
		if m == method {
			return true
		}
	}
	return false
}

// TokenHeaderName returns the configured header (default
// X-Turnstile-Response).
func (t *TurnstileConfig) TokenHeaderName() string {
	if t != nil && t.TokenHeader != "" {
		return t.TokenHeader
	}
	return DefaultTurnstileTokenHeader
}

// TurnstileFor returns the block when it applies to (host, path).
func (c *Config) TurnstileFor(host, path string) *TurnstileConfig {
	t := c.Turnstile
	if !t.Active() || !t.MatchesHost(host) || !t.MatchesPath(path) {
		return nil
	}
	return t
}

// resolveTurnstile normalizes and validates the block, and reads the
// secret from the environment (fail-fast: a missing secret refuses
// startup instead of silently disabling the check).
func (c *Config) resolveTurnstile() error {
	t := c.Turnstile
	if t == nil {
		return nil
	}
	if !t.Active() {
		c.Turnstile = nil
		return nil
	}

	t.Mode = strings.ToLower(strings.TrimSpace(t.Mode))
	switch t.Mode {
	case "":
		t.Mode = TurnstileModeForms
	case TurnstileModeForms, TurnstileModeGate, TurnstileModeBoth:
	default:
		return fmt.Errorf(
			"turnstile.mode: %q (expected forms, gate or both)", t.Mode)
	}

	t.SiteKey = strings.TrimSpace(t.SiteKey)
	if t.SiteKey == "" {
		return fmt.Errorf("turnstile: siteKey is required")
	}
	if len(t.SiteKey) > 256 {
		return fmt.Errorf("turnstile: siteKey is too long (max 256)")
	}

	t.SecretEnv = strings.TrimSpace(t.SecretEnv)
	if t.SecretEnv == "" {
		return fmt.Errorf(
			"turnstile: secretEnv is required (the secret is never put in the file)")
	}
	secret, ok := os.LookupEnv(t.SecretEnv)
	if !ok || strings.TrimSpace(secret) == "" {
		return fmt.Errorf(
			"turnstile: environment variable %s is empty", t.SecretEnv)
	}
	t.Secret = strings.TrimSpace(secret)

	hosts := make([]string, 0, len(t.Hosts))
	seenHosts := map[string]bool{}
	for _, raw := range t.Hosts {
		h := NormalizeHostPattern(raw)
		if h == "" {
			return fmt.Errorf("turnstile.hosts: empty host pattern")
		}
		if h == "*." || strings.Count(h, "*") > 1 ||
			(strings.Contains(h, "*") && !strings.HasPrefix(h, "*.")) {
			return fmt.Errorf(
				"turnstile.hosts: %q: only a leading *. wildcard is supported", raw)
		}
		if !seenHosts[h] {
			seenHosts[h] = true
			hosts = append(hosts, h)
		}
	}
	t.Hosts = hosts

	paths := make([]string, 0, len(t.Paths))
	seenPaths := map[string]bool{}
	for _, raw := range t.Paths {
		p := strings.TrimSpace(raw)
		if p == "" || !strings.HasPrefix(p, "/") {
			return fmt.Errorf(
				"turnstile.paths: %q: a path must start with /", raw)
		}
		if strings.ContainsAny(p, "? \t\r\n") {
			return fmt.Errorf(
				"turnstile.paths: %q: no query/whitespace in a path", raw)
		}
		if p != "/*" &&
			(strings.Count(p, "*") > 1 ||
				(strings.Contains(p, "*") && !strings.HasSuffix(p, "/*"))) {
			return fmt.Errorf(
				"turnstile.paths: %q: * is only allowed as a trailing /*", raw)
		}
		if !seenPaths[p] {
			seenPaths[p] = true
			paths = append(paths, p)
		}
	}
	t.Paths = paths

	if len(t.Methods) == 0 {
		t.Methods = []string{"POST"}
	}
	methods := make([]string, 0, len(t.Methods))
	seenMethods := map[string]bool{}
	for _, raw := range t.Methods {
		m := strings.ToUpper(strings.TrimSpace(raw))
		switch m {
		case "POST", "PUT", "PATCH", "DELETE":
		default:
			return fmt.Errorf(
				"turnstile.methods: %q: only POST, PUT, PATCH or DELETE "+
					"can be protected", raw)
		}
		if !seenMethods[m] {
			seenMethods[m] = true
			methods = append(methods, m)
		}
	}
	t.Methods = methods

	if len(t.Forms) > 32 {
		return fmt.Errorf("turnstile.forms: at most 32 selectors")
	}
	forms := make([]string, 0, len(t.Forms))
	for _, raw := range t.Forms {
		f := strings.TrimSpace(raw)
		if f == "" {
			return fmt.Errorf("turnstile.forms: empty selector")
		}
		if len(f) > 256 {
			return fmt.Errorf(
				"turnstile.forms: %q: selector too long (max 256)", raw)
		}
		forms = append(forms, f)
	}
	t.Forms = forms

	t.Action = strings.TrimSpace(t.Action)
	if t.Action != "" && !turnstileActionPattern.MatchString(t.Action) {
		return fmt.Errorf(
			"turnstile.action: %q: 1-32 characters, letters, digits, _ or -",
			t.Action)
	}

	if t.Hostname != "" {
		h := NormalizeHostPattern(t.Hostname)
		if h == "" || strings.Contains(h, "*") {
			return fmt.Errorf(
				"turnstile.hostname: %q: a literal hostname is required",
				t.Hostname)
		}
		t.Hostname = h
	}

	if t.ClearanceTTLSeconds < 0 {
		return fmt.Errorf(
			"turnstile.clearanceTtlSeconds: must be positive")
	}
	if t.ClearanceTTLSeconds == 0 {
		t.ClearanceTTLSeconds = DefaultTurnstileClearanceTTL
	}
	if t.ClearanceTTLSeconds < 60 || t.ClearanceTTLSeconds > 604800 {
		return fmt.Errorf(
			"turnstile.clearanceTtlSeconds: %d (bounds 60-604800)",
			t.ClearanceTTLSeconds)
	}

	t.ClearanceSecretEnv = strings.TrimSpace(t.ClearanceSecretEnv)
	if t.ClearanceSecretEnv != "" {
		secret, ok := os.LookupEnv(t.ClearanceSecretEnv)
		if !ok || strings.TrimSpace(secret) == "" {
			return fmt.Errorf(
				"turnstile: environment variable %s is empty",
				t.ClearanceSecretEnv)
		}
		t.ClearanceSecret = []byte(strings.TrimSpace(secret))
	} else {
		mac := hmac.New(sha256.New, []byte(t.Secret))
		mac.Write([]byte(clearanceKeyLabel))
		t.ClearanceSecret = mac.Sum(nil)
	}

	exempt := make([]string, 0, len(t.ExemptPaths))
	seenExempt := map[string]bool{}
	for _, raw := range t.ExemptPaths {
		p := strings.TrimSpace(raw)
		if p == "" || !strings.HasPrefix(p, "/") {
			return fmt.Errorf(
				"turnstile.exemptPaths: %q: a path must start with /", raw)
		}
		if strings.ContainsAny(p, "? \t\r\n") {
			return fmt.Errorf(
				"turnstile.exemptPaths: %q: no query/whitespace", raw)
		}
		if p != "/*" &&
			(strings.Count(p, "*") > 1 ||
				(strings.Contains(p, "*") && !strings.HasSuffix(p, "/*"))) {
			return fmt.Errorf(
				"turnstile.exemptPaths: %q: * is only allowed as a trailing /*", raw)
		}
		if !seenExempt[p] {
			seenExempt[p] = true
			exempt = append(exempt, p)
		}
	}
	t.ExemptPaths = exempt

	if t.Challenge != nil {
		a := strings.ToLower(strings.TrimSpace(t.Challenge.Appearance))
		switch a {
		case "":
			t.Challenge.Appearance = ""
		case "always", "execute", "interaction-only":
			t.Challenge.Appearance = a
		default:
			return fmt.Errorf(
				"turnstile.challenge.appearance: %q "+
					"(expected always, execute or interaction-only)", a)
		}
	}

	t.TokenHeader = strings.TrimSpace(t.TokenHeader)
	if t.TokenHeader != "" {
		for _, r := range t.TokenHeader {
			switch {
			case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z',
				r >= '0' && r <= '9', r == '-':
			default:
				return fmt.Errorf(
					"turnstile.tokenHeader: %q: invalid header name",
					t.TokenHeader)
			}
		}
	} else {
		t.TokenHeader = DefaultTurnstileTokenHeader
	}

	return nil
}
