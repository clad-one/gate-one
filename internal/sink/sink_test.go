package sink

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"cladone/gate-one/internal/outbox"
)

func keypair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func store(t *testing.T) *outbox.Store {
	t.Helper()
	s, err := outbox.Open(outbox.Config{Dir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestPushAcksAndCommits(t *testing.T) {
	pub, priv := keypair(t)
	var got int
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "Bearer sekret" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			raw, _ := io.ReadAll(r.Body)
			var b Batch
			if err := json.Unmarshal(raw, &b); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			sig, err := base64.RawURLEncoding.DecodeString(b.Signature)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			b.Signature = ""
			payload, _ := json.Marshal(b)
			if !ed25519.Verify(pub, payload, sig) {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			for _, rec := range b.Records {
				sum := sha256.Sum256(rec.Data)
				if "sha256:"+hex.EncodeToString(sum[:]) != rec.Hash {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
			}
			got += len(b.Records)
			w.WriteHeader(http.StatusNoContent)
		}))
	t.Cleanup(srv.Close)

	st := store(t)
	for _, p := range []string{`{"n":1}`, `{"n":2}`, `{"n":3}`} {
		if _, err := st.Append([]byte(p)); err != nil {
			t.Fatal(err)
		}
	}
	p, err := New(st, Config{
		URL: srv.URL, Secret: "sekret", NodeID: "gw-1",
		SigningKey: priv, BatchWait: 5 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	p.Run(ctx)

	if got != 3 {
		t.Fatalf("sink received %d records, want 3", got)
	}
	if st.CommitOffset() != st.Head() {
		t.Fatalf("commit=%d head=%d", st.CommitOffset(), st.Head())
	}
}

func TestExportBundleAndSignature(t *testing.T) {
	pub, priv := keypair(t)
	records := []outbox.Record{
		{Offset: 0, Payload: []byte(`{"n":1}`)},
		{Offset: 12, Payload: []byte(`{"n":2}`)},
	}
	dir := t.TempDir()
	path, err := Export(dir, "gw-1", 7, records, priv)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(path, "bundle-gw-1-000007.jsonl") {
		t.Fatalf("path = %s", path)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) != 2 {
		t.Fatalf("lines = %d", len(lines))
	}
	sigRaw, err := os.ReadFile(path + ".sig")
	if err != nil {
		t.Fatal(err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(string(sigRaw))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	if !ed25519.Verify(pub, sum[:], sig) {
		t.Fatal("bundle signature does not verify")
	}
	man, err := os.ReadFile(filepath.Join(dir, "bundle-gw-1-000007.manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(man, &m); err != nil {
		t.Fatal(err)
	}
	if m["count"] != float64(2) || m["bundleId"] != "bundle-gw-1-000007" {
		t.Fatalf("manifest = %v", m)
	}
}

func TestNoURLExportsWithoutCommitting(t *testing.T) {
	_, priv := keypair(t)
	st := store(t)
	if _, err := st.Append([]byte(`{"n":1}`)); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	p, err := New(st, Config{
		NodeID: "gw-1", SigningKey: priv, ExportDir: dir,
		BatchWait: 5 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Millisecond)
	defer cancel()
	p.Run(ctx)

	if st.CommitOffset() != 0 {
		t.Fatalf("commit = %d, an export must not acknowledge", st.CommitOffset())
	}
	entries, _ := os.ReadDir(dir)
	found := false
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".jsonl") {
			found = true
		}
	}
	if !found {
		t.Fatal("no bundle written")
	}
}

func TestBatchIDDeterministic(t *testing.T) {
	_, priv := keypair(t)
	st := store(t)
	if _, err := st.Append([]byte(`{"n":1}`)); err != nil {
		t.Fatal(err)
	}
	p, err := New(st, Config{URL: "http://x", NodeID: "gw", SigningKey: priv})
	if err != nil {
		t.Fatal(err)
	}
	recs, _, _ := st.Read(0, 10, 0)
	// Same clock: the whole batch (including the signature) is stable.
	p.now = func() time.Time { return time.Unix(1_700_000_000, 0).UTC() }
	a, _ := p.build(recs)
	b, _ := p.build(recs)
	if a.BatchID != b.BatchID {
		t.Fatalf("batch ids differ: %s vs %s", a.BatchID, b.BatchID)
	}
	if a.Signature == "" || a.Signature != b.Signature {
		t.Fatalf("signature not deterministic: %q / %q", a.Signature, b.Signature)
	}
}
