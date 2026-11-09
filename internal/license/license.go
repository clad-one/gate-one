// Package license evaluates OFFLINE signed licence tokens.
//
// A token is a compact, Ed25519-signed blob:
//
//	v1.<base64url(JSON claims)>.<base64url(signature)>
//
// The signature covers the decoded JSON payload. Only PUBLIC keys are
// embedded in the gateway (config `license.publicKey`, or a `publicKeys`
// map for rotation); the private key never ships. A token may carry a
// signed `kid` selecting its key in `publicKeys`, so several keys can be
// valid at once during a rotation. An absent, invalid or expired token
// yields the "eval" state (personal/evaluation) — never a hard stop: the
// gateway keeps serving, the guard script only displays a notice.
//
// A customer holds ONE TOKEN PER PERIOD. All of them are loaded: the
// active set (nbf <= now < exp) is merged — domains and features are
// unioned, domainCount and maxReplicas take the maximum — so a renewal
// with a smaller domain count never removes what the current period
// already paid for. The sources are merged as well (precedence is only
// used when the same token is reachable twice): the
// GATE_ONE_LICENSE_TOKEN environment variable, every file of
// `license.tokenDir`, then the deprecated `license.tokenFile`, then
// `license.token`. The directory and files are re-read on every config
// reload (SIGHUP), so dropping a new period file is enough.
package license

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const tokenVersion = "v1"

// TokenEnv adds a token when non-empty (merged with the configured
// sources; a single-token deployment keeps using it as an override).
const TokenEnv = "GATE_ONE_LICENSE_TOKEN"

// Enforcement modes for the configured hosts of a deployment.
const (
	// EnforceInfo logs uncovered hosts at info level (default).
	EnforceInfo = "info"
	// EnforceWarn logs uncovered hosts as warnings.
	EnforceWarn = "warn"
	// EnforceStrict answers 503 on uncovered hosts.
	EnforceStrict = "strict"
)

// Config is the `license` block of api-routes.json.
type Config struct {
	// TokenDir: directory holding one token per period (every regular
	// file is read; conventionally licence-<start>-<end>.txt).
	TokenDir string `json:"tokenDir,omitempty"`
	// Token: an inline signed token (empty = evaluation/personal).
	Token string `json:"token,omitempty"`
	// TokenFile: deprecated single-token file. Prefer TokenDir.
	TokenFile string `json:"tokenFile,omitempty"`
	// PublicKey: base64 Ed25519 public key (raw 32 bytes). Required for
	// a token to be valid (unless PublicKeys is used); it is public by
	// design and safe to commit. Legacy single-key form (tokens without
	// `kid`).
	PublicKey string `json:"publicKey,omitempty"`
	// PublicKeys: kid -> base64 public key. Lets several signing keys be
	// valid at the same time (rotation without invalidating old tokens).
	// A token carries its `kid` in the signed payload; an unknown kid is
	// rejected (no silent fallback).
	PublicKeys map[string]string `json:"publicKeys,omitempty"`
	// URL: optional registration / pricing link shown by the badge.
	URL string `json:"url,omitempty"`
	// Enforce: what to do with a configured host that no active licence
	// covers: info (default), warn, or strict (503).
	Enforce string `json:"enforce,omitempty"`
}

// Claims is the signed payload of one period.
type Claims struct {
	// Kid: id of the signing key (looked up in license.publicKeys).
	Kid   string `json:"kid,omitempty"`
	Sub   string `json:"sub,omitempty"`
	Org   string `json:"org,omitempty"`
	Email string `json:"email,omitempty"`
	Plan  string `json:"plan,omitempty"`
	// Nbf: start of the period (unix seconds). Absent = valid at once.
	Nbf int64 `json:"nbf,omitempty"`
	// Exp: end of the period (unix seconds).
	Exp int64 `json:"exp,omitempty"`
	// DomainCount: billed suffixes for this period.
	DomainCount int `json:"domainCount,omitempty"`
	// Domains: suffixes served during this period (subdomains included).
	Domains []string `json:"domains,omitempty"`
	// MaxReplicas: billed parallelism (replicas) for this period.
	MaxReplicas int      `json:"maxReplicas,omitempty"`
	Features    []string `json:"features,omitempty"`
}

// Status is the merged licence state. It carries what the gateway and
// the plugins need; use ClientStatus before sending anything to a
// browser (org, email, domains and features are not for public pages).
type Status struct {
	State    string   `json:"state"`            // registered | eval
	Reason   string   `json:"reason,omitempty"` // ok|missing|invalid|expired|no-key
	Kid      string   `json:"kid,omitempty"`    // signing key id
	Sub      string   `json:"sub,omitempty"`
	Org      string   `json:"org,omitempty"`
	Email    string   `json:"email,omitempty"`
	Plan     string   `json:"plan,omitempty"`
	Nbf      string   `json:"nbf,omitempty"` // YYYY-MM-DD (UTC)
	Exp      string   `json:"exp,omitempty"` // YYYY-MM-DD (UTC)
	Domains  []string `json:"domains,omitempty"`
	Features []string `json:"features,omitempty"`
	// DomainCount and MaxReplicas are the effective (maximum) billed
	// quantities across the active periods.
	DomainCount int `json:"domainCount,omitempty"`
	MaxReplicas int `json:"maxReplicas,omitempty"`
	// Periods: how many active tokens were merged.
	Periods int `json:"periods,omitempty"`
	// Enforce: the configured host-coverage mode (info|warn|strict).
	Enforce string `json:"enforce,omitempty"`
	URL     string `json:"url,omitempty"`
}

// ClientStatus strips everything a browser has no business seeing.
// The badge only needs the state, the expiry and the registration link.
func ClientStatus(st Status) Status {
	return Status{
		State:  st.State,
		Reason: st.Reason,
		Plan:   st.Plan,
		Exp:    st.Exp,
		URL:    st.URL,
	}
}

// EnforceMode normalizes config.Enforce; anything unknown means info.
func EnforceMode(cfg *Config) string {
	if cfg == nil {
		return EnforceInfo
	}
	switch strings.ToLower(strings.TrimSpace(cfg.Enforce)) {
	case EnforceWarn:
		return EnforceWarn
	case EnforceStrict:
		return EnforceStrict
	default:
		return EnforceInfo
	}
}

// Eval evaluates the licence at `now`. It never fails: an unusable
// configuration simply yields the "eval" state.
func Eval(cfg *Config, now time.Time) Status {
	st := Status{State: "eval", Reason: "missing"}
	if cfg == nil {
		return st
	}
	st.URL = cfg.URL
	st.Enforce = EnforceMode(cfg)
	tokens := resolveTokens(cfg)
	if len(tokens) == 0 {
		return st
	}
	if strings.TrimSpace(cfg.PublicKey) == "" && len(cfg.PublicKeys) == 0 {
		st.Reason = "no-key"
		return st
	}

	var (
		active  []Claims
		expired []Claims
		invalid bool
	)
	for _, token := range tokens {
		claims, err := VerifyWithConfig(cfg, token)
		if err != nil {
			invalid = true
			continue
		}
		if claims.Nbf > 0 && now.Unix() < claims.Nbf {
			continue // a future period: install both files, it starts later
		}
		if claims.Exp > 0 && now.Unix() > claims.Exp {
			expired = append(expired, claims)
			continue
		}
		active = append(active, claims)
	}
	if len(active) == 0 {
		switch {
		case len(expired) > 0:
			// Keep the expired period's identity visible (CLI, support,
			// badge link) but grant nothing: no domains, no features.
			last := expired[0]
			for _, c := range expired[1:] {
				if c.Exp > last.Exp {
					last = c
				}
			}
			st.Reason = "expired"
			st.Org, st.Email, st.Plan = last.Org, last.Email, last.Plan
			if last.Exp > 0 {
				st.Exp = time.Unix(last.Exp, 0).UTC().Format("2006-01-02")
			}
		case invalid:
			st.Reason = "invalid"
		default:
			st.Reason = "missing"
		}
		return st
	}

	merged := merge(active)
	st.State = "registered"
	st.Reason = "ok"
	st.Kid, st.Sub = merged.Kid, merged.Sub
	st.Org, st.Email, st.Plan = merged.Org, merged.Email, merged.Plan
	st.Domains, st.Features = merged.Domains, merged.Features
	st.DomainCount = merged.DomainCount
	st.MaxReplicas = merged.MaxReplicas
	st.Periods = len(active)
	if merged.Nbf > 0 {
		st.Nbf = time.Unix(merged.Nbf, 0).UTC().Format("2006-01-02")
	}
	if merged.Exp > 0 {
		st.Exp = time.Unix(merged.Exp, 0).UTC().Format("2006-01-02")
	}
	return st
}

// merge unions domains and features and takes the maximum of the billed
// quantities. The identity (org, plan, exp) comes from the period that
// ends last, so the badge shows the furthest renewal.
func merge(periods []Claims) Claims {
	out := periods[0]
	for _, c := range periods[1:] {
		if c.Exp > out.Exp {
			out.Kid, out.Sub = c.Kid, c.Sub
			out.Org, out.Email, out.Plan = c.Org, c.Email, c.Plan
			out.Nbf, out.Exp = c.Nbf, c.Exp
		}
		if c.DomainCount > out.DomainCount {
			out.DomainCount = c.DomainCount
		}
		if c.MaxReplicas > out.MaxReplicas {
			out.MaxReplicas = c.MaxReplicas
		}
	}
	seenDomains := map[string]bool{}
	seenFeatures := map[string]bool{}
	out.Domains, out.Features = nil, nil
	for _, c := range periods {
		for _, d := range c.Domains {
			if d = normalizeDomain(d); d == "" || seenDomains[d] {
				continue
			}
			seenDomains[d] = true
			out.Domains = append(out.Domains, d)
		}
		for _, f := range c.Features {
			if f == "" || seenFeatures[f] {
				continue
			}
			seenFeatures[f] = true
			out.Features = append(out.Features, f)
		}
	}
	sort.Strings(out.Domains)
	sort.Strings(out.Features)
	return out
}

// resolveTokens collects every token source: the environment adds one,
// then every file of tokenDir, then the deprecated tokenFile, then the
// inline token. Identical tokens are deduplicated.
func resolveTokens(cfg *Config) []string {
	var tokens []string
	add := func(t string) {
		if t = strings.TrimSpace(t); t != "" {
			tokens = append(tokens, t)
		}
	}
	add(os.Getenv(TokenEnv))
	if dir := strings.TrimSpace(cfg.TokenDir); dir != "" {
		entries, err := os.ReadDir(dir)
		if err == nil {
			var names []string
			for _, e := range entries {
				if e.IsDir() || strings.HasPrefix(e.Name(), ".") {
					continue
				}
				names = append(names, e.Name())
			}
			sort.Strings(names)
			for _, name := range names {
				if b, err := os.ReadFile(filepath.Join(dir, name)); err == nil {
					add(string(b))
				}
			}
		}
	}
	if file := strings.TrimSpace(cfg.TokenFile); file != "" {
		if b, err := os.ReadFile(file); err == nil {
			add(string(b))
		}
	}
	add(cfg.Token)
	return tokens
}

// VerifyWithConfig selects the signing key (by the token's signed `kid`)
// then verifies the signature. Precedence: publicKeys[kid] when the token
// carries a kid (unknown kid = rejected, no silent fallback); otherwise
// the legacy publicKey, or the only configured publicKeys entry.
func VerifyWithConfig(cfg *Config, token string) (Claims, error) {
	var c Claims
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] != tokenVersion {
		return c, errors.New("license: malformed token")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return c, err
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return c, err
	}
	// The kid is read from the (still unverified) payload ONLY to select
	// the key: the signature check below authenticates it. A forged kid
	// can at worst select another of OUR keys, never bypass the check.
	if err := json.Unmarshal(payload, &c); err != nil {
		return c, err
	}
	pub, err := selectKey(cfg, c.Kid)
	if err != nil {
		return c, err
	}
	if !ed25519.Verify(pub, payload, sig) {
		return c, errors.New("license: bad signature")
	}
	return c, nil
}

func selectKey(cfg *Config, kid string) (ed25519.PublicKey, error) {
	if cfg == nil {
		return nil, errors.New("license: no key")
	}
	kid = strings.TrimSpace(kid)
	if kid != "" {
		b64, ok := cfg.PublicKeys[kid]
		if !ok || strings.TrimSpace(b64) == "" {
			return nil, fmt.Errorf("license: unknown kid %q", kid)
		}
		pub, err := decodeKey(b64)
		if err != nil || len(pub) != ed25519.PublicKeySize {
			return nil, errors.New("license: bad public key for kid " + kid)
		}
		return pub, nil
	}
	// No kid: legacy single key, or the only key configured.
	if strings.TrimSpace(cfg.PublicKey) != "" {
		pub, err := decodeKey(cfg.PublicKey)
		if err != nil || len(pub) != ed25519.PublicKeySize {
			return nil, errors.New("license: bad public key")
		}
		return pub, nil
	}
	if len(cfg.PublicKeys) == 1 {
		for k, b64 := range cfg.PublicKeys {
			pub, err := decodeKey(b64)
			if err != nil || len(pub) != ed25519.PublicKeySize {
				return nil, errors.New("license: bad public key for kid " + k)
			}
			return pub, nil
		}
	}
	return nil, errors.New("license: token has no kid and several keys are configured")
}

// Verify checks the signature against ONE explicit public key and returns
// the claims (low-level; Eval uses VerifyWithConfig).
func Verify(pub ed25519.PublicKey, token string) (Claims, error) {
	var c Claims
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] != tokenVersion {
		return c, errors.New("license: malformed token")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return c, err
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return c, err
	}
	if !ed25519.Verify(pub, payload, sig) {
		return c, errors.New("license: bad signature")
	}
	if err := json.Unmarshal(payload, &c); err != nil {
		return c, err
	}
	return c, nil
}

// EncodePublicKey renders a public key for `license.publicKey`.
func EncodePublicKey(pub ed25519.PublicKey) string {
	return base64.RawURLEncoding.EncodeToString(pub)
}

func decodeKey(s string) (ed25519.PublicKey, error) {
	s = strings.TrimSpace(s)
	for _, enc := range []*base64.Encoding{
		base64.RawURLEncoding,
		base64.URLEncoding,
		base64.RawStdEncoding,
		base64.StdEncoding,
	} {
		if b, err := enc.DecodeString(s); err == nil && len(b) == ed25519.PublicKeySize {
			return ed25519.PublicKey(b), nil
		}
	}
	return nil, errors.New("license: bad public key")
}

// Covered reports whether a host belongs to one of the licensed
// suffixes. A suffix covers itself and every subdomain: `exemple.fr`
// covers `exemple.fr` and `app.exemple.fr`. Local and internal names
// behave identically (`corp.local`, `app.intranet`).
func Covered(host string, domains []string) bool {
	host = normalizeHost(host)
	if host == "" {
		return true // no host (unix socket, tests): nothing to check
	}
	if isLoopbackHost(host) {
		return true // development and health probes
	}
	for _, d := range domains {
		d = normalizeDomain(d)
		if d == "" {
			continue
		}
		if host == d || strings.HasSuffix(host, "."+d) {
			return true
		}
	}
	return false
}

// Uncovered returns the hosts that no licensed suffix covers.
func Uncovered(hosts []string, domains []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, h := range hosts {
		h = normalizeHost(h)
		if h == "" || seen[h] {
			continue
		}
		seen[h] = true
		if !Covered(h, domains) {
			out = append(out, h)
		}
	}
	sort.Strings(out)
	return out
}

func normalizeHost(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	if i := strings.LastIndex(host, ":"); i > 0 && !strings.Contains(host[i:], "]") {
		// strip a port, but keep IPv6 brackets intact
		if !strings.Contains(host, ":") || strings.Count(host, ":") == 1 {
			host = host[:i]
		}
	}
	return strings.TrimSuffix(host, ".")
}

func normalizeDomain(d string) string {
	d = strings.ToLower(strings.TrimSpace(d))
	d = strings.TrimPrefix(d, "*.")
	return strings.TrimSuffix(d, ".")
}

func isLoopbackHost(host string) bool {
	switch host {
	case "localhost", "127.0.0.1", "::1", "[::1]":
		return true
	}
	return strings.HasSuffix(host, ".localhost")
}

// HasFeature reports whether a registered licence grants feature. An
// empty feature means "no licence requirement" and is always allowed.
func HasFeature(st Status, feature string) bool {
	if feature == "" {
		return true
	}
	if st.State != "registered" {
		return false
	}
	for _, f := range st.Features {
		if f == feature {
			return true
		}
	}
	return false
}
