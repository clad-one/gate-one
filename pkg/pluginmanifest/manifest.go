// Package pluginmanifest verifies signed plugin artefacts and their
// declared dependencies against a local trust store. It is the V2
// gate for out-of-process plugins: a signed manifest is not trusted
// unless its signer key, artefact digest and dependency digests are
// present in the signed allow-list.
package pluginmanifest

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"strconv"
	"strings"
)

// Manifest is the canonical plugin manifest. The signature covers the
// canonical JSON with Signature zeroed, plus the artefact digest.
type Manifest struct {
	SchemaVersion  int          `json:"schemaVersion"`
	Kind           string       `json:"kind"` // extension | auth
	Name           string       `json:"name"`
	Version        string       `json:"version"`
	APIVersion     string       `json:"apiVersion"`
	HostAPI        string       `json:"hostAPI"`
	Publisher      string       `json:"publisher,omitempty"`
	KeyID          string       `json:"keyId"`
	Artifact       Artifact     `json:"artifact"`
	Dependencies   []Dependency `json:"dependencies,omitempty"`
	Capabilities   []string     `json:"capabilities,omitempty"`
	LicenseFeature string       `json:"licenseFeature,omitempty"`
	Signature      Signature    `json:"signature"`
}

type Artifact struct {
	Type     string `json:"type"`
	Digest   string `json:"digest"` // sha256:<hex>
	Size     int64  `json:"size,omitempty"`
	Platform string `json:"platform,omitempty"`
}

type Dependency struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Digest  string `json:"digest"`
	Signer  string `json:"signer,omitempty"`
}

type Signature struct {
	Alg   string `json:"alg"` // ed25519
	KeyID string `json:"keyId"`
	Value string `json:"value"` // base64 raw URL
}

// TrustStore is the local allow-list. It must itself be provisioned
// out-of-band (signed lock file, embedded key, package manager).
type TrustStore struct {
	Keys map[string]ed25519.PublicKey
	// AllowedNames accepts exact names or glob patterns (path.Match).
	AllowedNames []string
	// AllowedDependencies maps name -> required digest.
	AllowedDependencies map[string]string
	// RevokedDigests refuses an artefact even with a valid signature.
	RevokedDigests map[string]bool
	// AllowAuth grants the "auth" kind (high-trust modules).
	AllowAuth bool
	// CoreVersion is the host API version, e.g. "1.2.0".
	CoreVersion string
}

var (
	ErrManifestInvalid     = errors.New("pluginmanifest: invalid manifest")
	ErrUntrustedKey        = errors.New("pluginmanifest: untrusted key")
	ErrBadSignature        = errors.New("pluginmanifest: bad signature")
	ErrDigestMismatch      = errors.New("pluginmanifest: artifact digest mismatch")
	ErrRevoked             = errors.New("pluginmanifest: artifact revoked")
	ErrIncompatibleAPI     = errors.New("pluginmanifest: incompatible host API")
	ErrUntrustedDependency = errors.New("pluginmanifest: untrusted dependency")
	ErrAuthKindDenied      = errors.New("pluginmanifest: auth kind not allowed")
)

// Parse decodes a manifest strictly (unknown fields refused).
func Parse(data []byte) (*Manifest, error) {
	var m Manifest
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrManifestInvalid, err)
	}
	return &m, nil
}

// Verify checks the signature, artefact, dependencies, revocation and
// host API compatibility.
func (m *Manifest) Verify(trust TrustStore, artifact []byte) error {
	if m == nil {
		return ErrManifestInvalid
	}
	if m.SchemaVersion != 1 {
		return fmt.Errorf("%w: schemaVersion %d", ErrManifestInvalid, m.SchemaVersion)
	}
	if m.Name == "" || m.Version == "" || m.APIVersion == "" || m.HostAPI == "" {
		return fmt.Errorf("%w: name/version/apiVersion/hostAPI required", ErrManifestInvalid)
	}
	if m.Kind != "" && m.Kind != "extension" && m.Kind != "auth" {
		return fmt.Errorf("%w: kind %q", ErrManifestInvalid, m.Kind)
	}
	if m.Kind == "auth" && !trust.AllowAuth {
		return ErrAuthKindDenied
	}
	if !nameAllowed(trust.AllowedNames, m.Name) {
		return fmt.Errorf("%w: %s", ErrUntrustedKey, m.Name)
	}
	key, ok := trust.Keys[m.KeyID]
	if !ok || len(key) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: %s", ErrUntrustedKey, m.KeyID)
	}
	if m.Signature.Alg != "ed25519" || m.Signature.KeyID != m.KeyID {
		return fmt.Errorf("%w: signature key/alg mismatch", ErrBadSignature)
	}
	if trust.RevokedDigests[m.Artifact.Digest] {
		return ErrRevoked
	}
	if !digestMatches(artifact, m.Artifact.Digest) {
		return ErrDigestMismatch
	}
	if m.Artifact.Size > 0 && int64(len(artifact)) != m.Artifact.Size {
		return fmt.Errorf("%w: size %d != %d",
			ErrDigestMismatch, len(artifact), m.Artifact.Size)
	}
	if !hostAPICompatible(m.HostAPI, trust.CoreVersion) {
		return fmt.Errorf("%w: %s vs %s",
			ErrIncompatibleAPI, m.HostAPI, trust.CoreVersion)
	}
	for _, dep := range m.Dependencies {
		want, ok := trust.AllowedDependencies[dep.Name]
		if !ok || want != dep.Digest {
			return fmt.Errorf("%w: %s@%s", ErrUntrustedDependency, dep.Name, dep.Version)
		}
	}
	payload, err := signingPayload(m)
	if err != nil {
		return err
	}
	sig, err := base64.RawURLEncoding.DecodeString(m.Signature.Value)
	if err != nil || !ed25519.Verify(key, payload, sig) {
		return ErrBadSignature
	}
	return nil
}

// SigningPayload is exported for the signing CLI/tests; it must match
// Verify exactly.
func SigningPayload(m *Manifest) ([]byte, error) { return signingPayload(m) }

func signingPayload(m *Manifest) ([]byte, error) {
	cp := *m
	cp.Signature = Signature{}
	body, err := json.Marshal(cp)
	if err != nil {
		return nil, err
	}
	return append(body, []byte("\n"+m.Artifact.Digest)...), nil
}

// Digest returns the canonical sha256:<hex> form.
func Digest(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func digestMatches(b []byte, want string) bool {
	return strings.EqualFold(Digest(b), strings.TrimSpace(want))
}

func nameAllowed(patterns []string, name string) bool {
	if len(patterns) == 0 {
		return false
	}
	for _, p := range patterns {
		if p == name {
			return true
		}
		if ok, _ := path.Match(p, name); ok {
			return true
		}
	}
	return false
}

func hostAPICompatible(constraint, version string) bool {
	constraint = strings.TrimSpace(constraint)
	if constraint == "" || constraint == "*" {
		return true
	}
	have, ok := parseVersion(version)
	if !ok {
		return false
	}
	for _, part := range strings.Fields(constraint) {
		op := ""
		for _, candidate := range []string{">=", "<=", ">", "<", "="} {
			if strings.HasPrefix(part, candidate) {
				op = candidate
				part = strings.TrimSpace(strings.TrimPrefix(part, candidate))
				break
			}
		}
		if op == "" {
			op = "="
		}
		want, ok := parseVersion(part)
		if !ok {
			return false
		}
		cmp := compareVersion(have, want)
		switch op {
		case ">=":
			if cmp < 0 {
				return false
			}
		case ">":
			if cmp <= 0 {
				return false
			}
		case "<=":
			if cmp > 0 {
				return false
			}
		case "<":
			if cmp >= 0 {
				return false
			}
		case "=":
			if cmp != 0 {
				return false
			}
		}
	}
	return true
}

func parseVersion(v string) ([3]int, bool) {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	parts := strings.Split(v, ".")
	if len(parts) > 3 {
		parts = parts[:3]
	}
	var out [3]int
	for i := 0; i < 3; i++ {
		if i >= len(parts) {
			continue
		}
		n, err := strconv.Atoi(parts[i])
		if err != nil || n < 0 {
			return out, false
		}
		out[i] = n
	}
	return out, true
}

func compareVersion(a, b [3]int) int {
	for i := 0; i < 3; i++ {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}
	return 0
}
