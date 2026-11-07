// Package publisherfeed loads and verifies the publisher feed: a signed
// document listing the components known to fit together (Gate One
// versions, external components, plugins), their version-compatibility
// rules and their revocation status.
//
// The feed only narrows trust (revocations) and advises (compatibility);
// the operator's local trust store stays authoritative.
package publisherfeed

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"cladone/gate-one/pkg/pluginmanifest"
	"cladone/gate-one/pkg/signing"
)

var (
	ErrInvalid      = errors.New("publisherfeed: invalid feed")
	ErrBadSignature = errors.New("publisherfeed: bad signature")
)

// Host is a compatible Gate One release.
type Host struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	HostAPI string `json:"hostAPI,omitempty"`
}

// ExternalComponent is a compatible non-Gate-One component (Redis, an
// IdP, …).
type ExternalComponent struct {
	Name       string `json:"name"`
	Role       string `json:"role,omitempty"`
	Constraint string `json:"constraint,omitempty"`
}

// Plugin is a known plugin release.
type Plugin struct {
	Name         string            `json:"name"`
	Version      string            `json:"version,omitempty"`
	Digest       string            `json:"digest,omitempty"`
	Publisher    string            `json:"publisher,omitempty"`
	Distribution string            `json:"distribution,omitempty"`
	HostAPI      string            `json:"hostAPI,omitempty"`
	Capabilities []string          `json:"capabilities,omitempty"`
	Status       string            `json:"status,omitempty"` // active | deprecated | revoked
	Requires     map[string]string `json:"requires,omitempty"`
}

// Revocation withdraws trust from an artefact digest or a signing key.
type Revocation struct {
	Digest    string `json:"digest,omitempty"`
	KeyID     string `json:"keyId,omitempty"`
	Reason    string `json:"reason,omitempty"`
	Severity  string `json:"severity,omitempty"`
	RevokedAt string `json:"revokedAt,omitempty"`
}

// Feed is the signed publisher document.
type Feed struct {
	SchemaVersion      int                      `json:"schemaVersion"`
	Kind               string                   `json:"kind"`
	Publisher          string                   `json:"publisher,omitempty"`
	GeneratedAt        string                   `json:"generatedAt,omitempty"`
	ValidUntil         string                   `json:"validUntil,omitempty"`
	Hosts              []Host                   `json:"hosts,omitempty"`
	ExternalComponents []ExternalComponent      `json:"externalComponents,omitempty"`
	Plugins            []Plugin                 `json:"plugins,omitempty"`
	Revocations        []Revocation             `json:"revocations,omitempty"`
	Signature          pluginmanifest.Signature `json:"signature"`
}

// Parse decodes a feed, rejecting unknown fields.
func Parse(data []byte) (*Feed, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var f Feed
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if f.SchemaVersion != 1 {
		return nil, fmt.Errorf("%w: schemaVersion must be 1", ErrInvalid)
	}
	if f.Kind != "publisher-feed" {
		return nil, fmt.Errorf("%w: kind must be publisher-feed", ErrInvalid)
	}
	return &f, nil
}

// Verify checks the Ed25519 signature over the JCS canonical form of
// the raw feed JSON (the signature member is removed).
func (f *Feed) Verify(pub ed25519.PublicKey, raw []byte) error {
	if f.Signature.Alg != "ed25519" {
		return fmt.Errorf("%w: alg must be ed25519", ErrBadSignature)
	}
	payload, err := signing.Payload(raw, "")
	if err != nil {
		return err
	}
	sig, err := base64.RawURLEncoding.DecodeString(
		strings.TrimSpace(f.Signature.Value))
	if err != nil || len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("%w: malformed signature", ErrBadSignature)
	}
	if !ed25519.Verify(pub, payload, sig) {
		return ErrBadSignature
	}
	return nil
}

// Expired reports whether the feed is past validUntil.
func (f *Feed) Expired(now time.Time) bool {
	if strings.TrimSpace(f.ValidUntil) == "" {
		return false
	}
	t, err := time.Parse(time.RFC3339, f.ValidUntil)
	if err != nil {
		return false
	}
	return now.After(t)
}

// RevokedDigests is the set of revoked artefact digests.
func (f *Feed) RevokedDigests() map[string]bool {
	out := map[string]bool{}
	for _, r := range f.Revocations {
		if d := strings.TrimSpace(r.Digest); d != "" {
			out[d] = true
		}
	}
	return out
}

// RevokedKeys is the set of revoked signing key ids.
func (f *Feed) RevokedKeys() map[string]bool {
	out := map[string]bool{}
	for _, r := range f.Revocations {
		if k := strings.TrimSpace(r.KeyID); k != "" {
			out[k] = true
		}
	}
	return out
}

// PluginStatus returns the declared status of a plugin release matching
// name (and, when given, version or digest).
func (f *Feed) PluginStatus(name, version, digest string) (string, bool) {
	for _, p := range f.Plugins {
		if p.Name != name {
			continue
		}
		if version != "" && p.Version != "" && p.Version != version {
			continue
		}
		if digest != "" && p.Digest != "" && p.Digest != digest {
			continue
		}
		return p.Status, true
	}
	return "", false
}
