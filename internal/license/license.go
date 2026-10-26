// Package license evaluates an OFFLINE signed licence token.
//
// A token is a compact, Ed25519-signed blob:
//
//	v1.<base64url(JSON claims)>.<base64url(signature)>
//
// The signature covers the decoded JSON payload. Only the PUBLIC key is
// embedded in the gateway (config `license.publicKey`); the private key
// never ships. An absent, invalid or expired token yields the "eval"
// state (personal/evaluation) — never a hard stop: the gateway keeps
// serving, the guard script only displays a notice.
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
	// a token to be valid; it is public by design and safe to commit.
	PublicKey string `json:"publicKey,omitempty"`
	// URL: optional registration / pricing link shown by the badge.
	URL string `json:"url,omitempty"`
}

// Claims is the signed payload. Only non-empty fields are displayed.
type Claims struct {
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
	if strings.TrimSpace(cfg.PublicKey) == "" {
		st.Reason = "no-key"
		return st
	}
	pub, err := decodeKey(cfg.PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		st.Reason = "no-key"
		return st
	}
	claims, err := Verify(pub, token)
	if err != nil {
		st.Reason = "invalid"
		return st
	}
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

// Verify checks the signature and returns the claims.
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
