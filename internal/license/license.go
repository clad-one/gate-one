// Package license evaluates an OFFLINE signed licence token.
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
// The token may come from (precedence): the GATE_ONE_LICENSE_TOKEN
// environment variable, then `license.tokenFile`, then `license.token`.
// The file/env are re-read on every config reload (SIGHUP), which makes
// renewal possible without editing api-routes.json.
package license

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

const tokenVersion = "v1"

// TokenEnv overrides every other token source when non-empty.
const TokenEnv = "GATE_ONE_LICENSE_TOKEN"

// Config is the `license` block of api-routes.json.
type Config struct {
	// Token: the signed licence token (empty = evaluation/personal).
	Token string `json:"token,omitempty"`
	// TokenFile: path to a file holding the token (mounted secret, easy
	// renewal: replace the file + SIGHUP). Ignored when the env var
	// GATE_ONE_LICENSE_TOKEN is set; falls back to Token when unreadable.
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
}

// Claims is the signed payload. Only non-empty fields are displayed.
type Claims struct {
	// Kid: id of the signing key (looked up in license.publicKeys).
	Kid      string   `json:"kid,omitempty"`
	Sub      string   `json:"sub,omitempty"`
	Org      string   `json:"org,omitempty"`
	Email    string   `json:"email,omitempty"`
	Plan     string   `json:"plan,omitempty"`
	Exp      int64    `json:"exp,omitempty"` // unix seconds
	Domains  []string `json:"domains,omitempty"`
	Features []string `json:"features,omitempty"`
}

// Status is what the guard script receives (JSON).
type Status struct {
	State    string   `json:"state"`            // registered | eval
	Reason   string   `json:"reason,omitempty"` // ok|missing|invalid|expired|no-key
	Kid      string   `json:"kid,omitempty"`    // signing key id
	Org      string   `json:"org,omitempty"`
	Email    string   `json:"email,omitempty"`
	Plan     string   `json:"plan,omitempty"`
	Exp      string   `json:"exp,omitempty"` // YYYY-MM-DD (UTC)
	Domains  []string `json:"domains,omitempty"`
	Features []string `json:"features,omitempty"`
	URL      string   `json:"url,omitempty"`
}

// Eval evaluates the licence at `now`. It never fails: an unusable
// configuration simply yields the "eval" state.
func Eval(cfg *Config, now time.Time) Status {
	st := Status{State: "eval", Reason: "missing"}
	if cfg == nil {
		return st
	}
	st.URL = cfg.URL
	token := resolveToken(cfg)
	if token == "" {
		return st
	}
	if strings.TrimSpace(cfg.PublicKey) == "" && len(cfg.PublicKeys) == 0 {
		st.Reason = "no-key"
		return st
	}
	claims, err := VerifyWithConfig(cfg, token)
	if err != nil {
		st.Reason = "invalid"
		return st
	}
	st.Kid = claims.Kid
	st.Org, st.Email, st.Plan = claims.Org, claims.Email, claims.Plan
	st.Domains, st.Features = claims.Domains, claims.Features
	if claims.Exp > 0 {
		st.Exp = time.Unix(claims.Exp, 0).UTC().Format("2006-01-02")
		if now.Unix() > claims.Exp {
			st.Reason = "expired"
			return st
		}
	}
	st.State = "registered"
	st.Reason = "ok"
	return st
}

// resolveToken applies the precedence env > tokenFile > token. The file
// is re-read on each call (i.e. each config reload): replacing it and
// sending SIGHUP renews the licence without touching api-routes.json.
func resolveToken(cfg *Config) string {
	if v := strings.TrimSpace(os.Getenv(TokenEnv)); v != "" {
		return v
	}
	if cfg != nil && strings.TrimSpace(cfg.TokenFile) != "" {
		if b, err := os.ReadFile(cfg.TokenFile); err == nil {
			if v := strings.TrimSpace(string(b)); v != "" {
				return v
			}
		}
	}
	if cfg != nil {
		return strings.TrimSpace(cfg.Token)
	}
	return ""
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
		for _, b64 := range cfg.PublicKeys {
			pub, err := decodeKey(b64)
			if err != nil || len(pub) != ed25519.PublicKeySize {
				return nil, errors.New("license: bad public key")
			}
			return pub, nil
		}
	}
	if len(cfg.PublicKeys) > 1 {
		return nil, errors.New("license: token has no kid and several keys are configured")
	}
	return nil, errors.New("license: no key")
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
