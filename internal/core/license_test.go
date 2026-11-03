package core

import (
	"testing"
	"time"

	"cladone/gate-one/internal/license"
)

// TestLicenseStrictConfig: the `license` block is accepted by the strict
// loader (DisallowUnknownFields) — otherwise a configured licence would
// refuse to load.
func TestLicenseStrictConfig(t *testing.T) {
	pub, priv, err := license.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	tok, err := license.Sign(priv, license.Claims{
		Org: "MYCOMPANY", Exp: time.Now().Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	pubB64 := license.EncodePublicKey(pub)
	data := []byte(`{
		"license": {"token": "` + tok + `", "tokenFile": "/tmp/lic", "publicKey": "` + pubB64 + `", "publicKeys": {"k": "` + pubB64 + `"}, "url": "https://x"},
		"routes": []
	}`)
	var cfg Config
	if err := strictUnmarshal(data, &cfg); err != nil {
		t.Fatalf("strict parse: %v", err)
	}
	if cfg.License == nil || cfg.License.Token != tok {
		t.Fatalf("license not parsed: %+v", cfg.License)
	}
	if cfg.License.PublicKey == "" || cfg.License.URL != "https://x" || cfg.License.TokenFile != "/tmp/lic" {
		t.Fatalf("license fields lost: %+v", cfg.License)
	}
	if cfg.License.PublicKeys["k"] != pubB64 {
		t.Fatalf("publicKeys lost: %+v", cfg.License.PublicKeys)
	}
}
