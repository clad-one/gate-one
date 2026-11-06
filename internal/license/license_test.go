package license

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// generateKeyForTest and signForTest are test-only. The public package
// keeps only the verifier; licence minting lives in the private vendor
// tooling (`gate-one-vendor`).
func generateKeyForTest() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

func signForTest(priv ed25519.PrivateKey, c Claims) (string, error) {
	payload, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	sig := ed25519.Sign(priv, payload)
	return tokenVersion + "." +
		base64.RawURLEncoding.EncodeToString(payload) + "." +
		base64.RawURLEncoding.EncodeToString(sig), nil
}

func TestEvalMissing(t *testing.T) {
	st := Eval(nil, time.Now())
	if st.State != "eval" || st.Reason != "missing" {
		t.Fatalf("nil config = %+v, want eval/missing", st)
	}
	st = Eval(&Config{}, time.Now())
	if st.State != "eval" || st.Reason != "missing" {
		t.Fatalf("empty config = %+v, want eval/missing", st)
	}
}

func TestEvalRegistered(t *testing.T) {
	pub, priv, err := generateKeyForTest()
	if err != nil {
		t.Fatal(err)
	}
	exp := time.Now().Add(24 * time.Hour).Unix()
	tok, err := signForTest(priv, Claims{
		Sub: "mycompany", Org: "MYCOMPANY", Email: "ops@mycompany.fr", Plan: "pro",
		Exp: exp, Domains: []string{"mycompany.fr"}, Features: []string{"sso"},
	})
	if err != nil {
		t.Fatal(err)
	}
	st := Eval(&Config{Token: tok, PublicKey: EncodePublicKey(pub)}, time.Now())
	if st.State != "registered" || st.Reason != "ok" {
		t.Fatalf("state=%s reason=%s, want registered/ok", st.State, st.Reason)
	}
	if st.Org != "MYCOMPANY" || st.Email != "ops@mycompany.fr" || st.Plan != "pro" {
		t.Fatalf("claims not surfaced: %+v", st)
	}
	if len(st.Domains) != 1 || st.Domains[0] != "mycompany.fr" {
		t.Fatalf("domains = %v", st.Domains)
	}
	if st.Exp == "" {
		t.Fatal("exp not formatted")
	}
}

func TestEvalExpired(t *testing.T) {
	pub, priv, _ := generateKeyForTest()
	tok, _ := signForTest(priv, Claims{Org: "MYCOMPANY", Exp: time.Now().Add(-time.Hour).Unix()})
	st := Eval(&Config{Token: tok, PublicKey: EncodePublicKey(pub)}, time.Now())
	if st.State != "eval" || st.Reason != "expired" {
		t.Fatalf("state=%s reason=%s, want eval/expired", st.State, st.Reason)
	}
	if st.Org != "MYCOMPANY" {
		t.Fatal("expired token should still surface its claims for the UI")
	}
}

func TestEvalTampered(t *testing.T) {
	pub, priv, _ := generateKeyForTest()
	tok, _ := signForTest(priv, Claims{Org: "MYCOMPANY"})
	parts := strings.Split(tok, ".")
	// flip a payload character (keep base64url alphabet valid)
	payload := []byte(parts[1])
	if payload[0] == 'A' {
		payload[0] = 'B'
	} else {
		payload[0] = 'A'
	}
	tampered := parts[0] + "." + string(payload) + "." + parts[2]
	st := Eval(&Config{Token: tampered, PublicKey: EncodePublicKey(pub)}, time.Now())
	if st.State != "eval" || st.Reason != "invalid" {
		t.Fatalf("tampered = %s/%s, want eval/invalid", st.State, st.Reason)
	}
}

func TestEvalWrongKey(t *testing.T) {
	_, priv, _ := generateKeyForTest()
	otherPub, _, _ := generateKeyForTest()
	tok, _ := signForTest(priv, Claims{Org: "MYCOMPANY"})
	st := Eval(&Config{Token: tok, PublicKey: EncodePublicKey(otherPub)}, time.Now())
	if st.State != "eval" || st.Reason != "invalid" {
		t.Fatalf("wrong key = %s/%s, want eval/invalid", st.State, st.Reason)
	}
}

func TestEvalNoKey(t *testing.T) {
	_, priv, _ := generateKeyForTest()
	tok, _ := signForTest(priv, Claims{Org: "MYCOMPANY"})
	st := Eval(&Config{Token: tok}, time.Now())
	if st.State != "eval" || st.Reason != "no-key" {
		t.Fatalf("no key = %s/%s, want eval/no-key", st.State, st.Reason)
	}
}

func TestVerifyRejectsMalformed(t *testing.T) {
	pub, _, _ := generateKeyForTest()
	for _, tok := range []string{"", "v1", "v2.a.b", "v1.%%%.%%%"} {
		if _, err := Verify(pub, tok); err == nil {
			t.Fatalf("Verify(%q) should fail", tok)
		}
	}
}

func TestDecodeKeyAcceptsEncodings(t *testing.T) {
	pub, _, _ := generateKeyForTest()
	for _, s := range []string{
		EncodePublicKey(pub),
		strings.TrimRight(EncodePublicKey(pub), "="),
	} {
		got, err := decodeKey(s)
		if err != nil || !got.Equal(pub) {
			t.Fatalf("decodeKey(%q) failed: %v", s, err)
		}
	}
}

func TestEvalTokenFile(t *testing.T) {
	pub, priv, _ := generateKeyForTest()
	tok, _ := signForTest(priv, Claims{Org: "FILE", Exp: time.Now().Add(time.Hour).Unix()})
	f := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(f, []byte(tok+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	st := Eval(&Config{TokenFile: f, PublicKey: EncodePublicKey(pub)}, time.Now())
	if st.State != "registered" || st.Org != "FILE" {
		t.Fatalf("tokenFile = %s/%s org=%q, want registered/FILE", st.State, st.Reason, st.Org)
	}
}

func TestEvalTokenFileFallsBackToConfig(t *testing.T) {
	pub, priv, _ := generateKeyForTest()
	tok, _ := signForTest(priv, Claims{Org: "CFG", Exp: time.Now().Add(time.Hour).Unix()})
	missing := filepath.Join(t.TempDir(), "absent")
	st := Eval(&Config{
		TokenFile: missing, Token: tok, PublicKey: EncodePublicKey(pub),
	}, time.Now())
	if st.State != "registered" || st.Org != "CFG" {
		t.Fatalf("fallback = %s/%s org=%q, want registered/CFG", st.State, st.Reason, st.Org)
	}
}

func TestEvalEnvOverridesEverything(t *testing.T) {
	pub, priv, _ := generateKeyForTest()
	envTok, _ := signForTest(priv, Claims{Org: "ENV", Exp: time.Now().Add(time.Hour).Unix()})
	cfgTok, _ := signForTest(priv, Claims{Org: "CFG", Exp: time.Now().Add(time.Hour).Unix()})
	t.Setenv(TokenEnv, envTok)

	st := Eval(&Config{
		Token: cfgTok, TokenFile: filepath.Join(t.TempDir(), "absent"),
		PublicKey: EncodePublicKey(pub),
	}, time.Now())
	if st.State != "registered" || st.Org != "ENV" {
		t.Fatalf("env override = %s/%s org=%q, want registered/ENV", st.State, st.Reason, st.Org)
	}
}

func TestEvalMultiKey(t *testing.T) {
	pubA, privA, _ := generateKeyForTest()
	pubB, privB, _ := generateKeyForTest()
	cfg := &Config{PublicKeys: map[string]string{
		"a": EncodePublicKey(pubA),
		"b": EncodePublicKey(pubB),
	}}
	cases := []struct {
		kid  string
		org  string
		priv ed25519.PrivateKey
	}{
		{"a", "ORG-A", privA},
		{"b", "ORG-B", privB},
	}
	for _, tc := range cases {
		tok, _ := signForTest(tc.priv, Claims{
			Kid: tc.kid, Org: tc.org, Exp: time.Now().Add(time.Hour).Unix(),
		})
		cfg.Token = tok
		st := Eval(cfg, time.Now())
		if st.State != "registered" || st.Org != tc.org || st.Kid != tc.kid {
			t.Fatalf("kid %s: state=%s reason=%s org=%q kid=%q, want registered/%s/%s",
				tc.kid, st.State, st.Reason, st.Org, st.Kid, tc.org, tc.kid)
		}
	}
}

func TestEvalUnknownKidRejectedNoFallback(t *testing.T) {
	pub, priv, _ := generateKeyForTest()
	tok, _ := signForTest(priv, Claims{Kid: "c", Org: "X", Exp: time.Now().Add(time.Hour).Unix()})
	cfg := &Config{
		// legacy publicKey AND a key map: an unknown kid must NOT fall
		// back to publicKey (silent fallback would defeat rotation).
		PublicKey:  EncodePublicKey(pub),
		PublicKeys: map[string]string{"a": EncodePublicKey(pub)},
		Token:      tok,
	}
	st := Eval(cfg, time.Now())
	if st.State != "eval" || st.Reason != "invalid" {
		t.Fatalf("unknown kid = %s/%s, want eval/invalid", st.State, st.Reason)
	}
}

func TestEvalNoKidSingleKeyMap(t *testing.T) {
	pub, priv, _ := generateKeyForTest()
	tok, _ := signForTest(priv, Claims{Org: "ONLY", Exp: time.Now().Add(time.Hour).Unix()})
	cfg := &Config{
		PublicKeys: map[string]string{"only": EncodePublicKey(pub)},
		Token:      tok,
	}
	st := Eval(cfg, time.Now())
	if st.State != "registered" || st.Org != "ONLY" {
		t.Fatalf("single key map = %s/%s, want registered/ONLY", st.State, st.Reason)
	}
}

func TestEvalNoKidAmbiguousKeys(t *testing.T) {
	pubA, privA, _ := generateKeyForTest()
	pubB, _, _ := generateKeyForTest()
	tok, _ := signForTest(privA, Claims{Org: "AMB", Exp: time.Now().Add(time.Hour).Unix()})
	cfg := &Config{
		PublicKeys: map[string]string{
			"a": EncodePublicKey(pubA),
			"b": EncodePublicKey(pubB),
		},
		Token: tok,
	}
	st := Eval(cfg, time.Now())
	if st.State != "eval" || st.Reason != "invalid" {
		t.Fatalf("ambiguous keys = %s/%s, want eval/invalid", st.State, st.Reason)
	}
}

// compile-time: ed25519 keys are the expected size
var _ = ed25519.PublicKeySize
