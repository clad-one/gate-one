// Receipts acknowledge an air-gap bundle. The operator loads one and
// commits the outbox up to NextOffset; without a valid receipt nothing is
// ever committed.
package sink

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Rejected is one record the ingest refused (a purged key).
type Rejected struct {
	Offset int64  `json:"offset"`
	Reason string `json:"reason"`
}

// Receipt is the signed acknowledgement of a bundle.
type Receipt struct {
	BundleID    string     `json:"bundleId"`
	Node        string     `json:"node"`
	Seq         int        `json:"seq"`
	Accepted    int        `json:"accepted"`
	Duplicates  int        `json:"duplicates"`
	FirstOffset int64      `json:"firstOffset"`
	LastOffset  int64      `json:"lastOffset"`
	NextOffset  int64      `json:"nextOffset"`
	Rejected    []Rejected `json:"rejected"`
	IngestedAt  string     `json:"ingestedAt"`
}

// ReceiptDocument is the file an operator carries back.
type ReceiptDocument struct {
	Receipt   Receipt `json:"receipt"`
	Signature string  `json:"signature"`
}

// ReceiptPayload is the signed line format a receiver must produce:
//
//	v1
//	<bundleId>
//	<node>
//	<seq>
//	<accepted>
//	<firstOffset>
//	<lastOffset>
//	<nextOffset>
//	<offset:reason,...>
func ReceiptPayload(r Receipt) []byte {
	rejected := make([]string, 0, len(r.Rejected))
	for _, x := range r.Rejected {
		rejected = append(rejected, fmt.Sprintf("%d:%s", x.Offset, x.Reason))
	}
	lines := []string{
		"v1",
		r.BundleID,
		r.Node,
		strconv.Itoa(r.Seq),
		strconv.Itoa(r.Accepted),
		strconv.FormatInt(r.FirstOffset, 10),
		strconv.FormatInt(r.LastOffset, 10),
		strconv.FormatInt(r.NextOffset, 10),
		strings.Join(rejected, ","),
	}
	return []byte(strings.Join(lines, "\n") + "\n")
}

// LoadReceipt reads, decodes and verifies a receipt file.
func LoadReceipt(path string, pub ed25519.PublicKey) (Receipt, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Receipt{}, err
	}
	return VerifyReceipt(raw, pub)
}

// VerifyReceipt checks the signature of a receipt document.
func VerifyReceipt(raw []byte, pub ed25519.PublicKey) (Receipt, error) {
	var doc ReceiptDocument
	if err := json.Unmarshal(raw, &doc); err != nil {
		return Receipt{}, fmt.Errorf("sink: receipt: %w", err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(
		strings.TrimSpace(doc.Signature))
	if err != nil || len(sig) != ed25519.SignatureSize {
		return Receipt{}, fmt.Errorf("sink: receipt: missing signature")
	}
	if !ed25519.Verify(pub, ReceiptPayload(doc.Receipt), sig) {
		return Receipt{}, fmt.Errorf("sink: receipt: bad signature")
	}
	if doc.Receipt.BundleID == "" || doc.Receipt.Node == "" {
		return Receipt{}, fmt.Errorf("sink: receipt: incomplete")
	}
	if doc.Receipt.NextOffset <= 0 {
		return Receipt{}, fmt.Errorf("sink: receipt: missing nextOffset")
	}
	return doc.Receipt, nil
}
