package publisherfeed

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"cladone/gate-one/pkg/pluginmanifest"
	"cladone/gate-one/pkg/signing"
)

func signFeed(t *testing.T, f *Feed, priv ed25519.PrivateKey) []byte {
	t.Helper()
	raw, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := signing.Payload(raw, "")
	if err != nil {
		t.Fatal(err)
	}
	f.Signature = pluginmanifest.Signature{
		Alg:   "ed25519",
		KeyID: "feed-2026",
		Value: base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, payload)),
	}
	raw, err = json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestFeedVerify(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	raw := signFeed(t, &Feed{
		SchemaVersion: 1,
		Kind:          "publisher-feed",
		Publisher:     "Cladone-IT",
		ValidUntil:    "2027-01-01T00:00:00Z",
		Revocations: []Revocation{
			{Digest: "sha256:aa", Reason: "misbehaviour"},
			{KeyID: "vendor-x", Reason: "key-compromise"},
		},
	}, priv)

	f, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Verify(pub, raw); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !f.RevokedDigests()["sha256:aa"] || !f.RevokedKeys()["vendor-x"] {
		t.Fatal("revocations not exposed")
	}
	if f.Expired(time.Now()) {
		t.Fatal("feed should not be expired")
	}

	// Tampering with the body invalidates the signature.
	bad := []byte(strings.Replace(string(raw), "Cladone-IT", "Evil-IT", 1))
	f2, err := Parse(bad)
	if err != nil {
		t.Fatal(err)
	}
	if err := f2.Verify(pub, bad); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("err = %v, want bad signature", err)
	}
}

func TestFeedParseRejectsUnknown(t *testing.T) {
	if _, err := Parse([]byte(
		`{"schemaVersion":1,"kind":"publisher-feed","bogus":true}`,
	)); err == nil {
		t.Fatal("unknown field must be rejected")
	}
}

func TestPluginStatus(t *testing.T) {
	f := &Feed{Plugins: []Plugin{
		{Name: "com.acme.audit", Version: "1.0.0", Status: "revoked"},
	}}
	if s, ok := f.PluginStatus("com.acme.audit", "1.0.0", ""); !ok || s != "revoked" {
		t.Fatalf("status = %q, ok = %v", s, ok)
	}
	if _, ok := f.PluginStatus("com.acme.other", "", ""); ok {
		t.Fatal("unknown plugin must not match")
	}
}
