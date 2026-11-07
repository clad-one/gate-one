package pluginmanifest

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"testing"
)

func eventTrust(pub ed25519.PublicKey) TrustStore {
	return TrustStore{
		Keys:         map[string]ed25519.PublicKey{"k1": pub},
		AllowedNames: []string{"com.cladone.*"},
		CoreVersion:  "1.5.0",
		// Let the auth-kind case reach validateEvents (events are still
		// invalid on an auth manifest).
		AllowAuth: true,
	}
}

func signedManifest(t *testing.T, priv ed25519.PrivateKey, m *Manifest) *Manifest {
	t.Helper()
	payload, err := SigningPayload(rawOf(t, m), m.Artifact.Digest)
	if err != nil {
		t.Fatal(err)
	}
	m.Signature = Signature{
		Alg: "ed25519", KeyID: m.KeyID,
		Value: base64.RawURLEncoding.EncodeToString(
			ed25519.Sign(priv, payload)),
	}
	return m
}

func eventManifest() (*Manifest, []byte) {
	artifact := []byte("usage-audit-plugin-v1")
	return &Manifest{
		SchemaVersion: 1,
		Kind:          "extension",
		Name:          "com.cladone.audit",
		Version:       "1.0.0",
		APIVersion:    "v1",
		HostAPI:       ">=1.0 <2.0",
		KeyID:         "k1",
		Artifact: Artifact{
			Type: "binary", Digest: Digest(artifact),
			Size: int64(len(artifact)),
		},
		Capabilities:   []string{"events"},
		LicenseFeature: "audit",
		Events: &EventSubscription{
			Types:       []string{"audit", "error"},
			MaxLagBytes: 5_000_000,
			OnMaxLag:    "block",
			Filters:     &EventFilters{Routes: []string{"/api/*"}, SampleRate: 1},
		},
	}, artifact
}

func TestPluginManifestEventSubscription(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	trust := eventTrust(pub)

	m, artifact := eventManifest()
	signedManifest(t, priv, m)
	if err := m.Verify(trust, rawOf(t, m), artifact); err != nil {
		t.Fatalf("valid event manifest rejected: %v", err)
	}

	// The subscription is part of the signed payload.
	m, artifact = eventManifest()
	signedManifest(t, priv, m)
	m.Events.Types = append(m.Events.Types, "billing")
	if err := m.Verify(trust, rawOf(t, m), artifact); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("mutated subscription: err = %v, want bad signature", err)
	}
}

func TestPluginManifestEventSubscriptionRejected(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	trust := eventTrust(pub)

	cases := []struct {
		name string
		mut  func(*Manifest)
	}{
		{"auth_kind", func(m *Manifest) { m.Kind = "auth" }},
		{"missing_capability", func(m *Manifest) { m.Capabilities = nil }},
		{"unknown_type", func(m *Manifest) {
			m.Events.Types = []string{"nope"}
		}},
		{"empty_types", func(m *Manifest) { m.Events.Types = nil }},
		{"bad_onmaxlag", func(m *Manifest) { m.Events.OnMaxLag = "retry" }},
		{"negative_lag", func(m *Manifest) { m.Events.MaxLagBytes = -1 }},
		{"bad_sample", func(m *Manifest) { m.Events.Filters.SampleRate = 1.5 }},
		{"unknown_capability", func(m *Manifest) {
			m.Capabilities = append(m.Capabilities, "telepathy")
		}},
		{"extension_auth_capability", func(m *Manifest) {
			m.Capabilities = append(m.Capabilities, "auth")
		}},
	}
	for _, c := range cases {
		m, artifact := eventManifest()
		c.mut(m)
		signedManifest(t, priv, m)
		if err := m.Verify(trust, rawOf(t, m), artifact); !errors.Is(err, ErrManifestInvalid) {
			t.Errorf("%s: err = %v, want ErrManifestInvalid", c.name, err)
		}
	}
}
