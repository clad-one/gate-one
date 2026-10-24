package license

import (
	"crypto/ed25519"
	"strings"
	"testing"
	"time"
)

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
	pub, priv, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	exp := time.Now().Add(24 * time.Hour).Unix()
	tok, err := Sign(priv, Claims{
		Sub: "acme", Org: "ACME", Email: "ops@acme.fr", Plan: "pro",
		Exp: exp, Domains: []string{"acme.fr"}, Features: []string{"sso"},
	})
	if err != nil {
		t.Fatal(err)
	}
	st := Eval(&Config{Token: tok, PublicKey: EncodePublicKey(pub)}, time.Now())
	if st.State != "registered" || st.Reason != "ok" {
		t.Fatalf("state=%s reason=%s, want registered/ok", st.State, st.Reason)
	}
	if st.Org != "ACME" || st.Email != "ops@acme.fr" || st.Plan != "pro" {
		t.Fatalf("claims not surfaced: %+v", st)
	}
	if len(st.Domains) != 1 || st.Domains[0] != "acme.fr" {
		t.Fatalf("domains = %v", st.Domains)
	}
	if st.Exp == "" {
		t.Fatal("exp not formatted")
	}
}

func TestEvalExpired(t *testing.T) {
	pub, priv, _ := GenerateKey()
	tok, _ := Sign(priv, Claims{Org: "ACME", Exp: time.Now().Add(-time.Hour).Unix()})
	st := Eval(&Config{Token: tok, PublicKey: EncodePublicKey(pub)}, time.Now())
	if st.State != "eval" || st.Reason != "expired" {
		t.Fatalf("state=%s reason=%s, want eval/expired", st.State, st.Reason)
	}
	if st.Org != "ACME" {
		t.Fatal("expired token should still surface its claims for the UI")
	}
}

func TestEvalTampered(t *testing.T) {
	pub, priv, _ := GenerateKey()
	tok, _ := Sign(priv, Claims{Org: "ACME"})
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
	_, priv, _ := GenerateKey()
	otherPub, _, _ := GenerateKey()
	tok, _ := Sign(priv, Claims{Org: "ACME"})
	st := Eval(&Config{Token: tok, PublicKey: EncodePublicKey(otherPub)}, time.Now())
	if st.State != "eval" || st.Reason != "invalid" {
		t.Fatalf("wrong key = %s/%s, want eval/invalid", st.State, st.Reason)
	}
}

func TestEvalNoKey(t *testing.T) {
	_, priv, _ := GenerateKey()
	tok, _ := Sign(priv, Claims{Org: "ACME"})
	st := Eval(&Config{Token: tok}, time.Now())
	if st.State != "eval" || st.Reason != "no-key" {
		t.Fatalf("no key = %s/%s, want eval/no-key", st.State, st.Reason)
	}
}

func TestVerifyRejectsMalformed(t *testing.T) {
	pub, _, _ := GenerateKey()
	for _, tok := range []string{"", "v1", "v2.a.b", "v1.%%%.%%%"} {
		if _, err := Verify(pub, tok); err == nil {
			t.Fatalf("Verify(%q) should fail", tok)
		}
	}
}

func TestDecodeKeyAcceptsEncodings(t *testing.T) {
	pub, _, _ := GenerateKey()
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

// compile-time: ed25519 keys are the expected size
var _ = ed25519.PublicKeySize
