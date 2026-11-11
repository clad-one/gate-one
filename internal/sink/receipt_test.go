package sink

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestReceiptVectorAndVerify(t *testing.T) {
	raw, err := os.ReadFile("testdata/vector.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Seed    string `json:"seed"`
		Public  string `json:"publicKey"`
		Receipt struct {
			BundleID    string     `json:"bundleId"`
			Node        string     `json:"node"`
			Seq         int        `json:"seq"`
			Accepted    int        `json:"accepted"`
			Duplicates  int        `json:"duplicates"`
			FirstOffset int64      `json:"firstOffset"`
			LastOffset  int64      `json:"lastOffset"`
			NextOffset  int64      `json:"nextOffset"`
			Rejected    []Rejected `json:"rejected"`
			Signature   string     `json:"signature"`
		} `json:"receipt"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	seed, _ := base64.RawURLEncoding.DecodeString(v.Seed)
	key := ed25519.NewKeyFromSeed(seed)
	r := Receipt{
		BundleID: v.Receipt.BundleID, Node: v.Receipt.Node, Seq: v.Receipt.Seq,
		Accepted: v.Receipt.Accepted, Duplicates: v.Receipt.Duplicates,
		FirstOffset: v.Receipt.FirstOffset, LastOffset: v.Receipt.LastOffset,
		NextOffset: v.Receipt.NextOffset, Rejected: v.Receipt.Rejected,
	}
	if got := base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, ReceiptPayload(r))); got != v.Receipt.Signature {
		t.Fatalf("receipt signature drift: %s", got)
	}

	doc, _ := json.Marshal(ReceiptDocument{Receipt: r, Signature: v.Receipt.Signature})
	path := filepath.Join(t.TempDir(), "receipt.json")
	if err := os.WriteFile(path, doc, 0o600); err != nil {
		t.Fatal(err)
	}
	pub := key.Public().(ed25519.PublicKey)
	got, err := LoadReceipt(path, pub)
	if err != nil {
		t.Fatal(err)
	}
	if got.NextOffset != 240 || got.Accepted != 2 {
		t.Fatalf("receipt = %+v", got)
	}

	// Tampering with nextOffset must fail: it is signed.
	r.NextOffset = 999
	bad, _ := json.Marshal(ReceiptDocument{Receipt: r, Signature: v.Receipt.Signature})
	if _, err := VerifyReceipt(bad, pub); err == nil {
		t.Fatal("tampered receipt accepted")
	}
}
