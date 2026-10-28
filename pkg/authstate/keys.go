// Package authstate defines the shared Redis key schema used by Gate
// One and the broker. Keeping one encoder avoids subtle cross-service
// mismatches: a revocation written by the broker must be readable by
// every Gate One instance.
package authstate

import (
	"encoding/base64"
	"strings"
)

// DefaultPrefix is the Gate One revocation keyspace.
const DefaultPrefix = "cladone:auth:v1:"

// Prefix normalizes a prefix (trailing colon).
func Prefix(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		p = DefaultPrefix
	}
	if !strings.HasSuffix(p, ":") {
		p += ":"
	}
	return p
}

// Key builds a namespaced key. Issuer and value are base64url-encoded
// so separators in URLs, sids or subs cannot collide.
func Key(prefix, kind, issuer, value string) string {
	enc := func(v string) string {
		return base64.RawURLEncoding.EncodeToString([]byte(v))
	}
	return Prefix(prefix) + kind + ":" + enc(issuer) + ":" + enc(value)
}
