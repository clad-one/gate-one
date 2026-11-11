// Package sink delivers outbox records to the managed billing endpoint
// (push) or, when the endpoint stays unreachable, to a signed export
// bundle that an operator can carry across an air gap.
//
// A batch carries a per-record hash and one Ed25519 signature over the
// canonical JSON, so the receiver can verify both the transport
// (secret header) and the content (signature, per-record hash).
package sink

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"cladone/gate-one/internal/outbox"
)

// Outbox record framing, mirrored to compute the next offset in a bundle
// manifest (the receiver only sees the last record's start).
const (
	recordHeaderBytes  = 4
	recordTrailerBytes = 4
)

// Config configures the pusher.
type Config struct {
	// URL is the managed ingest endpoint (empty = export only).
	URL string
	// Secret authenticates the call (Bearer).
	Secret string
	// NodeID identifies this producer in every batch.
	NodeID string
	// SigningKey signs each batch (Ed25519).
	SigningKey ed25519.PrivateKey
	// Batch bound: records, bytes, wait.
	BatchRecords int
	BatchBytes   int
	BatchWait    time.Duration
	// ExportDir receives the signed bundles when the push fails.
	ExportDir string
	// ExportAfter is how long the push may fail before a bundle is
	// written. A bundle is never committed: only a receipt does that.
	ExportAfter time.Duration
	// Client overrides the HTTP client (tests).
	Client *http.Client
}

// Record is one delivered entry. Data is the base64url-encoded payload:
// encoding (not embedding) the bytes keeps the per-record hash exact in
// any receiver, with no JSON canonicalisation dependency.
type Record struct {
	Offset int64  `json:"offset"`
	Hash   string `json:"hash"`
	Data   string `json:"data"`
}

// Batch is the signed push body.
type Batch struct {
	Node      string    `json:"node"`
	BatchID   string    `json:"batchId"`
	CreatedAt time.Time `json:"createdAt"`
	Records   []Record  `json:"records"`
	Signature string    `json:"signature"`
}

// Pusher drains the outbox into the sink.
type Pusher struct {
	store    *outbox.Store
	cfg      Config
	http     *http.Client
	now      func() time.Time
	mu       sync.Mutex
	seq      int
	exported int64 // last offset written to a bundle
	close    sync.Once
}

// New validates the configuration and returns a pusher.
func New(store *outbox.Store, cfg Config) (*Pusher, error) {
	if store == nil {
		return nil, fmt.Errorf("sink: nil outbox")
	}
	if cfg.URL == "" && cfg.ExportDir == "" {
		return nil, fmt.Errorf("sink: url or exportDir is required")
	}
	if cfg.SigningKey == nil {
		return nil, fmt.Errorf("sink: signing key is required")
	}
	if strings.TrimSpace(cfg.NodeID) == "" {
		return nil, fmt.Errorf("sink: nodeId is required")
	}
	if cfg.BatchRecords <= 0 {
		cfg.BatchRecords = 500
	}
	if cfg.BatchBytes <= 0 {
		cfg.BatchBytes = 1 << 20
	}
	if cfg.BatchWait <= 0 {
		cfg.BatchWait = time.Second
	}
	if cfg.ExportAfter <= 0 {
		cfg.ExportAfter = 5 * time.Minute
	}
	if cfg.Client == nil {
		cfg.Client = &http.Client{Timeout: 30 * time.Second}
	}
	return &Pusher{store: store, cfg: cfg, http: cfg.Client, now: time.Now}, nil
}

// Run pushes until the context is cancelled.
func (p *Pusher) Run(ctx context.Context) {
	var (
		failing   bool
		failSince time.Time
		backoff   = 200 * time.Millisecond
	)
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(p.cfg.BatchWait):
		}
		records, next, err := p.store.Read(
			p.store.CommitOffset(), p.cfg.BatchRecords, p.cfg.BatchBytes)
		if err != nil {
			log.Printf("sink: read outbox: %v", err)
			continue
		}
		if len(records) == 0 {
			failing = false
			continue
		}
		batch, err := p.build(records)
		if err != nil {
			log.Printf("sink: build batch: %v", err)
			continue
		}
		if p.cfg.URL == "" {
			p.exportOnce(records, next)
			continue
		}
		if err := p.post(ctx, batch); err != nil {
			if !failing {
				failing, failSince = true, p.now()
			}
			if p.now().Sub(failSince) >= p.cfg.ExportAfter {
				p.exportOnce(records, next)
			}
			log.Printf("sink: push: %v (retry in %s)", err, backoff)
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			if backoff < 30*time.Second {
				backoff *= 2
			}
			continue
		}
		if err := p.store.Commit(next); err != nil {
			log.Printf("sink: commit: %v", err)
			continue
		}
		failing = false
		backoff = 200 * time.Millisecond
	}
}

// Close stops nothing (Run is context-driven) but is kept for symmetry.
func (p *Pusher) Close() error {
	p.close.Do(func() {})
	return nil
}

func (p *Pusher) build(records []outbox.Record) (Batch, error) {
	out := make([]Record, 0, len(records))
	for _, r := range records {
		sum := sha256.Sum256(r.Payload)
		out = append(out, Record{
			Offset: r.Offset,
			Hash:   "sha256:" + hex.EncodeToString(sum[:]),
			Data:   base64.RawURLEncoding.EncodeToString(r.Payload),
		})
	}
	b := Batch{
		Node:      p.cfg.NodeID,
		BatchID:   "",
		CreatedAt: p.now().UTC(),
		Records:   out,
	}
	b.BatchID = batchID(b)
	b.Signature = base64.RawURLEncoding.EncodeToString(
		ed25519.Sign(p.cfg.SigningKey, SignaturePayload(b)))
	return b, nil
}

// batchID is derived from the content, never from the clock: a replayed
// window yields the same id, so the receiver can deduplicate it.
func batchID(b Batch) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s|%d|%d|%d", b.Node, len(b.Records),
		b.Records[0].Offset, b.Records[len(b.Records)-1].Offset)
	for _, r := range b.Records {
		fmt.Fprintf(h, "|%d:%s", r.Offset, r.Hash)
	}
	return hex.EncodeToString(h.Sum(nil)[:12])
}

// SignaturePayload is the signed bytes of a batch. It is a line format,
// not canonical JSON: the receiver (any language) rebuilds it trivially,
// with no dependency on a JSON canonicalisation quirk.
//
//	v1
//	<node>
//	<batchId>
//	<offset>:<hash>
//	...
//
// The timestamp is deliberately NOT signed: Go marshals nanoseconds while
// JavaScript truncates to milliseconds, and it adds no integrity (the id
// already covers the content).
func SignaturePayload(b Batch) []byte {
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "v1\n%s\n%s\n", b.Node, b.BatchID)
	for _, r := range b.Records {
		fmt.Fprintf(&buf, "%d:%s\n", r.Offset, r.Hash)
	}
	return buf.Bytes()
}

func (p *Pusher) post(ctx context.Context, b Batch) error {
	raw, err := json.Marshal(b)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(
		ctx, http.MethodPost, p.cfg.URL, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if p.cfg.Secret != "" {
		req.Header.Set("Authorization", "Bearer "+p.cfg.Secret)
	}
	resp, err := p.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	return nil
}

// exportOnce writes at most one bundle for the current outbox window. A
// bundle is never acknowledged by writing it: only a receipt commits.
func (p *Pusher) exportOnce(records []outbox.Record, next int64) {
	p.mu.Lock()
	if next <= p.exported || p.cfg.ExportDir == "" {
		p.mu.Unlock()
		return
	}
	p.exported = next
	p.seq++
	seq := p.seq
	p.mu.Unlock()

	path, err := Export(p.cfg.ExportDir, p.cfg.NodeID, seq, records, p.cfg.SigningKey)
	if err != nil {
		log.Printf("sink: export: %v", err)
		return
	}
	log.Printf("sink: exported %d record(s) to %s (no receipt yet)", len(records), path)
}

// Export writes bundle-<node>-<seq>.jsonl, its signature and a manifest.
// It returns the bundle path.
func Export(
	dir, node string, seq int, records []outbox.Record, key ed25519.PrivateKey,
) (string, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	base := fmt.Sprintf("bundle-%s-%06d", node, seq)
	path := filepath.Join(dir, base+".jsonl")

	var buf bytes.Buffer
	for _, r := range records {
		sum := sha256.Sum256(r.Payload)
		line := struct {
			Offset int64  `json:"offset"`
			Hash   string `json:"hash"`
			Data   string `json:"data"`
		}{r.Offset, "sha256:" + hex.EncodeToString(sum[:]),
			base64.RawURLEncoding.EncodeToString(r.Payload)}
		raw, err := json.Marshal(line)
		if err != nil {
			return "", err
		}
		buf.Write(raw)
		buf.WriteByte('\n')
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		return "", err
	}
	sum := sha256.Sum256(buf.Bytes())
	sig := ed25519.Sign(key, sum[:])
	if err := os.WriteFile(path+".sig",
		[]byte(base64.RawURLEncoding.EncodeToString(sig)), 0o600); err != nil {
		return "", err
	}
	last := records[len(records)-1]
	next := last.Offset + recordHeaderBytes + int64(len(last.Payload)) + recordTrailerBytes
	manifest := struct {
		BundleID string `json:"bundleId"`
		Node     string `json:"node"`
		Seq      int    `json:"seq"`
		Count    int    `json:"count"`
		First    int64  `json:"firstOffset"`
		Last     int64  `json:"lastOffset"`
		Next     int64  `json:"nextOffset"`
		SHA256   string `json:"sha256"`
	}{base, node, seq, len(records), records[0].Offset,
		last.Offset, next, hex.EncodeToString(sum[:])}
	raw, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(dir, base+".manifest.json"),
		append(raw, '\n'), 0o600); err != nil {
		return "", err
	}
	return path, nil
}
