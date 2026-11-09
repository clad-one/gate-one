package license

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeToken(t *testing.T, dir, name string, tok string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(tok+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// one token per period: the active one is used, the future one ignored.
func TestTokenDirFuturePeriodIgnored(t *testing.T) {
	pub, priv, _ := generateKeyForTest()
	now := time.Unix(1_800_000_000, 0)
	dir := t.TempDir()

	cur, _ := signForTest(priv, Claims{
		Org: "A", Exp: now.Add(24 * time.Hour).Unix(),
		Domains: []string{"a.fr"}, DomainCount: 1, MaxReplicas: 1,
	})
	next, _ := signForTest(priv, Claims{
		Org: "A", Nbf: now.Add(48 * time.Hour).Unix(), Exp: now.Add(96 * time.Hour).Unix(),
		Domains: []string{"a.fr"}, DomainCount: 2, MaxReplicas: 3,
	})
	writeToken(t, dir, "licence-1.txt", cur)
	writeToken(t, dir, "licence-2.txt", next)

	st := Eval(&Config{TokenDir: dir, PublicKeys: map[string]string{"": EncodePublicKey(pub)}}, now)
	if st.State != "registered" || st.Periods != 1 {
		t.Fatalf("state=%s periods=%d, want registered/1", st.State, st.Periods)
	}
	if st.DomainCount != 1 || st.MaxReplicas != 1 {
		t.Fatalf("domainCount=%d maxReplicas=%d, want 1/1", st.DomainCount, st.MaxReplicas)
	}
}

// overlapping periods merge: union of domains, max of the billed counts.
func TestTokenDirMergeOverlap(t *testing.T) {
	pub, priv, _ := generateKeyForTest()
	now := time.Unix(1_800_000_000, 0)
	dir := t.TempDir()

	old, _ := signForTest(priv, Claims{
		Org: "A", Exp: now.Add(time.Hour).Unix(),
		Domains: []string{"a.fr", "b.fr"}, DomainCount: 2, MaxReplicas: 1,
	})
	renew, _ := signForTest(priv, Claims{
		Org: "A", Nbf: now.Add(-time.Hour).Unix(), Exp: now.Add(365 * 24 * time.Hour).Unix(),
		Domains: []string{"a.fr", "c.fr"}, DomainCount: 2, MaxReplicas: 4,
	})
	writeToken(t, dir, "licence-old.txt", old)
	writeToken(t, dir, "licence-new.txt", renew)

	st := Eval(&Config{TokenDir: dir, PublicKey: EncodePublicKey(pub)}, now)
	if st.Periods != 2 {
		t.Fatalf("periods=%d, want 2", st.Periods)
	}
	if len(st.Domains) != 3 {
		t.Fatalf("domains=%v, want the union of 3", st.Domains)
	}
	if st.MaxReplicas != 4 {
		t.Fatalf("maxReplicas=%d, want the max 4", st.MaxReplicas)
	}
}

// a renewal starting later applies its (smaller) domain set only from
// its nbf: before that, the current period's domains still cover.
func TestTokenDirReductionAppliesAtNextPeriod(t *testing.T) {
	pub, priv, _ := generateKeyForTest()
	start := time.Unix(1_800_000_000, 0)
	dir := t.TempDir()

	cur, _ := signForTest(priv, Claims{
		Org: "A", Exp: start.Add(24 * time.Hour).Unix(),
		Domains: []string{"a.fr", "b.fr", "c.fr"}, DomainCount: 3,
	})
	next, _ := signForTest(priv, Claims{
		Org: "A", Nbf: start.Add(24 * time.Hour).Unix(), Exp: start.Add(48 * time.Hour).Unix(),
		Domains: []string{"a.fr"}, DomainCount: 1,
	})
	writeToken(t, dir, "licence-1.txt", cur)
	writeToken(t, dir, "licence-2.txt", next)
	cfg := &Config{TokenDir: dir, PublicKey: EncodePublicKey(pub)}

	before := Eval(cfg, start)
	if len(before.Domains) != 3 {
		t.Fatalf("before switch domains=%v, want 3", before.Domains)
	}
	after := Eval(cfg, start.Add(30*time.Hour))
	if len(after.Domains) != 1 || after.Domains[0] != "a.fr" {
		t.Fatalf("after switch domains=%v, want [a.fr]", after.Domains)
	}
}

func TestCovered(t *testing.T) {
	domains := []string{"exemple.fr", "corp.local", "app.intranet"}
	cases := []struct {
		host string
		want bool
	}{
		{"exemple.fr", true},
		{"app.exemple.fr", true},
		{"a.b.exemple.fr", true},
		{"exemple.fr:8443", true},
		{"autre.fr", false},
		{"notexemple.fr", false},
		{"corp.local", true},
		{"x.corp.local", true},
		{"app.intranet", true},
		{"localhost", true},
		{"app.demo.localhost", true},
		{"127.0.0.1", true},
	}
	for _, c := range cases {
		if got := Covered(c.host, domains); got != c.want {
			t.Errorf("Covered(%q) = %v, want %v", c.host, got, c.want)
		}
	}
}

func TestUncovered(t *testing.T) {
	got := Uncovered(
		[]string{"app.exemple.fr", "app.autre.fr", "exemple.fr", "app.autre.fr"},
		[]string{"exemple.fr"})
	if len(got) != 1 || got[0] != "app.autre.fr" {
		t.Fatalf("uncovered = %v, want [app.autre.fr]", got)
	}
}

// ClientStatus must not leak company, email, domains or features to the
// browser (the guard script is public).
func TestClientStatusStripsClaims(t *testing.T) {
	st := Status{
		State: "registered", Reason: "ok", Org: "ACME", Email: "a@acme.fr",
		Domains: []string{"acme.fr"}, Features: []string{"sso"},
		Plan: "pro", Exp: "2027-01-01", URL: "https://licence.example.com",
	}
	c := ClientStatus(st)
	if c.Org != "" || c.Email != "" || len(c.Domains) != 0 || len(c.Features) != 0 {
		t.Fatalf("client status leaks claims: %+v", c)
	}
	if c.State != "registered" || c.Exp != "2027-01-01" || c.Plan != "pro" {
		t.Fatalf("client status lost the useful fields: %+v", c)
	}
}
