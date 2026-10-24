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
		Org: "ACME", Exp: time.Now().Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	data := []byte(`{
		"license": {"token": "` + tok + `", "publicKey": "` + license.EncodePublicKey(pub) + `", "url": "https://x"},
		"routes": []
	}`)
	var cfg Config
	if err := strictUnmarshal(data, &cfg); err != nil {
		t.Fatalf("strict parse: %v", err)
	}
	if cfg.License == nil || cfg.License.Token != tok {
		t.Fatalf("license not parsed: %+v", cfg.License)
	}
	if cfg.License.PublicKey == "" || cfg.License.URL != "https://x" {
		t.Fatalf("license fields lost: %+v", cfg.License)
	}
}
