package pluginmanifest

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
)

func TestLoadTrustStore(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key := base64.RawURLEncoding.EncodeToString(pub)
	raw := `{
		"keys": {"k1": "` + key + `"},
		"allowedNames": ["com.cladone.*"],
		"allowedDependencies": {"dep": "sha256:abc"},
		"revokedDigests": ["sha256:dead"],
		"allowAuth": false,
		"coreVersion": "1.5.0"
	}`
	ts, err := LoadTrustStore([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if !ts.Keys["k1"].Equal(pub) {
		t.Fatal("key not decoded")
	}
	if !ts.RevokedDigests["sha256:dead"] {
		t.Fatal("revoked digest missing")
	}
	if ts.CoreVersion != "1.5.0" {
		t.Fatalf("coreVersion = %q", ts.CoreVersion)
	}
}

func TestLoadTrustStoreRejects(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want string
	}{
		{"no_keys", `{"coreVersion":"1.0.0"}`, "at least one key"},
		{"bad_key", `{"keys":{"k":"short"},"coreVersion":"1.0.0"}`, "invalid Ed25519"},
		{"unknown_field", `{"keys":{"k":"AAAA"},"nope":true}`, "unknown field"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := LoadTrustStore([]byte(c.raw))
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want %q", err, c.want)
			}
		})
	}
}
