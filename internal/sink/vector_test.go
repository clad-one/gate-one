package sink

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
)

// TestSignatureVector pins the exact bytes signed for a batch, so a
// receiver written in another language can be checked against the same
// fixture (services/billing-ingest/test/vector.test.js).
func TestSignatureVector(t *testing.T) {
	raw, err := os.ReadFile("testdata/vector.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Node      string `json:"node"`
		BatchID   string `json:"batchId"`
		Seed      string `json:"seed"`
		Signature string `json:"signature"`
		Records   []struct {
			Offset int64  `json:"offset"`
			Hash   string `json:"hash"`
			Data   string `json:"data"`
		} `json:"records"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	b := Batch{Node: v.Node, BatchID: v.BatchID}
	for _, r := range v.Records {
		b.Records = append(b.Records, Record{
			Offset: r.Offset, Hash: r.Hash, Data: r.Data,
		})
	}
	seed, err := base64.RawURLEncoding.DecodeString(v.Seed)
	if err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(seed)
	got := base64.RawURLEncoding.EncodeToString(
		ed25519.Sign(key, SignaturePayload(b)))
	if got != v.Signature {
		t.Fatalf("signature drift:\n got %s\nwant %s", got, v.Signature)
	}
	// The vector must verify too (it would catch a payload change).
	sig, _ := base64.RawURLEncoding.DecodeString(v.Signature)
	if !ed25519.Verify(key.Public().(ed25519.PublicKey), SignaturePayload(b), sig) {
		t.Fatal("vector signature does not verify")
	}
}
