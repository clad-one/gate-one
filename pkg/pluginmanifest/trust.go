package pluginmanifest

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// trustJSON is the JSON form of a local trust store. Keys are raw
// Ed25519 public keys in base64 (standard or raw URL encoding).
type trustJSON struct {
	Keys                map[string]string `json:"keys"`
	AllowedNames        []string          `json:"allowedNames"`
	AllowedDependencies map[string]string `json:"allowedDependencies"`
	RevokedDigests      []string          `json:"revokedDigests"`
	AllowAuth           bool              `json:"allowAuth"`
	CoreVersion         string            `json:"coreVersion"`
}

// LoadTrustStore parses a trust store file. It is provisioned
// out-of-band (signed lock file, embedded key, package manager) — it is
// never fetched from the plugin.
func LoadTrustStore(data []byte) (TrustStore, error) {
	var raw trustJSON
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&raw); err != nil {
		return TrustStore{}, fmt.Errorf("pluginmanifest: trust store: %w", err)
	}
	if len(raw.Keys) == 0 {
		return TrustStore{}, fmt.Errorf(
			"pluginmanifest: trust store: at least one key is required")
	}
	ts := TrustStore{
		Keys:                map[string]ed25519.PublicKey{},
		AllowedNames:        raw.AllowedNames,
		AllowedDependencies: raw.AllowedDependencies,
		RevokedDigests:      map[string]bool{},
		AllowAuth:           raw.AllowAuth,
		CoreVersion:         strings.TrimSpace(raw.CoreVersion),
	}
	for kid, encoded := range raw.Keys {
		key, err := decodeKey(encoded)
		if err != nil {
			return TrustStore{}, fmt.Errorf(
				"pluginmanifest: trust store: key %q: %w", kid, err)
		}
		ts.Keys[kid] = key
	}
	for _, d := range raw.RevokedDigests {
		d = strings.TrimSpace(d)
		if d != "" {
			ts.RevokedDigests[d] = true
		}
	}
	return ts, nil
}

func decodeKey(s string) (ed25519.PublicKey, error) {
	return DecodePublicKey(s)
}

// DecodePublicKey decodes an Ed25519 public key from base64 (raw URL,
// URL, raw standard or standard).
func DecodePublicKey(s string) (ed25519.PublicKey, error) {
	s = strings.TrimSpace(s)
	for _, enc := range []*base64.Encoding{
		base64.RawURLEncoding, base64.URLEncoding,
		base64.RawStdEncoding, base64.StdEncoding,
	} {
		b, err := enc.DecodeString(s)
		if err == nil && len(b) == ed25519.PublicKeySize {
			return ed25519.PublicKey(b), nil
		}
	}
	return nil, fmt.Errorf("invalid Ed25519 public key")
}
