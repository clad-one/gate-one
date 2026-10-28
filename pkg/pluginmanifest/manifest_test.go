package pluginmanifest

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
)

func TestAC_AUTH_16_PluginManifestV2(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	artifact := []byte("plugin-binary-v1")
	dep := []byte("dependency-v1")

	base := Manifest{
		SchemaVersion: 1,
		Kind:          "auth",
		Name:          "com.cladone.mtls",
		Version:       "1.0.0",
		APIVersion:    "v1",
		HostAPI:       ">=1.0 <2.0",
		Publisher:     "Cladone-IT",
		KeyID:         "k1",
		Artifact: Artifact{
			Type: "binary", Digest: Digest(artifact), Size: int64(len(artifact)),
		},
		Dependencies: []Dependency{{
			Name: "com.cladone.crypto", Version: "1.0.0", Digest: Digest(dep),
		}},
		Capabilities:   []string{"auth"},
		LicenseFeature: "mtls",
	}
	trust := TrustStore{
		Keys:         map[string]ed25519.PublicKey{"k1": pub},
		AllowedNames: []string{"com.cladone.*"},
		AllowedDependencies: map[string]string{
			"com.cladone.crypto": Digest(dep),
		},
		AllowAuth:   true,
		CoreVersion: "1.5.0",
	}
	sign := func(m *Manifest) *Manifest {
		payload, err := SigningPayload(m)
		if err != nil {
			t.Fatal(err)
		}
		sig := ed25519.Sign(priv, payload)
		m.Signature = Signature{
			Alg: "ed25519", KeyID: m.KeyID,
			Value: base64.RawURLEncoding.EncodeToString(sig),
		}
		return m
	}

	valid := sign(copyManifest(base))
	if err := valid.Verify(trust, artifact); err != nil {
		t.Fatalf("valid manifest: %v", err)
	}

	t.Run("bad_signature", func(t *testing.T) {
		m := sign(copyManifest(base))
		m.Signature.Value = base64.RawURLEncoding.EncodeToString(
			make([]byte, ed25519.SignatureSize))
		if err := m.Verify(trust, artifact); !errors.Is(err, ErrBadSignature) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("untrusted_key", func(t *testing.T) {
		m := sign(copyManifest(base))
		m.KeyID = "unknown"
		m.Signature.KeyID = "unknown"
		if err := m.Verify(trust, artifact); !errors.Is(err, ErrUntrustedKey) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("digest_mismatch", func(t *testing.T) {
		m := sign(copyManifest(base))
		m.Artifact.Digest = Digest([]byte("other"))
		sign(m)
		if err := m.Verify(trust, artifact); !errors.Is(err, ErrDigestMismatch) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("revoked_digest", func(t *testing.T) {
		m := sign(copyManifest(base))
		tr := trust
		tr.RevokedDigests = map[string]bool{m.Artifact.Digest: true}
		if err := m.Verify(tr, artifact); !errors.Is(err, ErrRevoked) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("incompatible_host_api", func(t *testing.T) {
		m := sign(copyManifest(base))
		m.HostAPI = ">=2.0 <3.0"
		sign(m)
		if err := m.Verify(trust, artifact); !errors.Is(err, ErrIncompatibleAPI) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("untrusted_dependency", func(t *testing.T) {
		m := sign(copyManifest(base))
		m.Dependencies = append(m.Dependencies, Dependency{
			Name: "com.evil.dep", Version: "1.0.0", Digest: "sha256:00",
		})
		sign(m)
		if err := m.Verify(trust, artifact); !errors.Is(err, ErrUntrustedDependency) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("auth_kind_denied", func(t *testing.T) {
		m := sign(copyManifest(base))
		tr := trust
		tr.AllowAuth = false
		if err := m.Verify(tr, artifact); !errors.Is(err, ErrAuthKindDenied) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("untrusted_name", func(t *testing.T) {
		m := sign(copyManifest(base))
		m.Name = "com.evil.plugin"
		sign(m)
		if err := m.Verify(trust, artifact); !errors.Is(err, ErrUntrustedKey) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("size_mismatch", func(t *testing.T) {
		m := sign(copyManifest(base))
		m.Artifact.Size = 999
		sign(m)
		if err := m.Verify(trust, artifact); !errors.Is(err, ErrDigestMismatch) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("strict_json", func(t *testing.T) {
		raw, _ := json.Marshal(map[string]any{
			"schemaVersion": 1, "unknown": true,
		})
		if _, err := Parse(raw); !errors.Is(err, ErrManifestInvalid) {
			t.Fatalf("err = %v", err)
		}
	})
}

func copyManifest(m Manifest) *Manifest {
	cp := m
	cp.Dependencies = append([]Dependency(nil), m.Dependencies...)
	cp.Capabilities = append([]string(nil), m.Capabilities...)
	return &cp
}
