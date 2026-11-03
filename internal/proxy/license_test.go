package proxy

import (
	"encoding/json"
	"testing"
	"time"

	"cladone/gate-one/internal/core"
	"cladone/gate-one/internal/license"
)

// TestLicenseJSONEval: no licence block → eval/missing (the badge shows
// the notice, the gateway still serves).
func TestLicenseJSONEval(t *testing.T) {
	for _, cfg := range []*core.Config{nil, {}} {
		var st license.Status
		if err := json.Unmarshal([]byte(licenseJSON(cfg)), &st); err != nil {
			t.Fatalf("licenseJSON: %v", err)
		}
		if st.State != "eval" || st.Reason != "missing" {
			t.Fatalf("cfg=%+v → %s/%s, want eval/missing", cfg, st.State, st.Reason)
		}
	}
}

// TestLicenseJSONRegistered: a valid signed token surfaces its claims to
// the guard script.
func TestLicenseJSONRegistered(t *testing.T) {
	pub, priv, err := license.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	tok, err := license.Sign(priv, license.Claims{
		Org: "MYCOMPANY", Email: "ops@mycompany.fr", Plan: "pro",
		Exp:     time.Now().Add(time.Hour).Unix(),
		Domains: []string{"mycompany.fr"}, Features: []string{"sso"},
	})
	if err != nil {
		t.Fatal(err)
	}
	cfg := &core.Config{License: &license.Config{
		Token: tok, PublicKey: license.EncodePublicKey(pub),
		URL: "https://example.test/pricing",
	}}
	var st license.Status
	if err := json.Unmarshal([]byte(licenseJSON(cfg)), &st); err != nil {
		t.Fatal(err)
	}
	if st.State != "registered" || st.Org != "MYCOMPANY" || st.Email != "ops@mycompany.fr" {
		t.Fatalf("got %+v, want registered/MYCOMPANY", st)
	}
	if st.URL != "https://example.test/pricing" {
		t.Fatalf("url = %q", st.URL)
	}
}
