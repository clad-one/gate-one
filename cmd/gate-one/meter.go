package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"cladone/gate-one/internal/core"
	"cladone/gate-one/internal/metering"
	"cladone/gate-one/internal/outbox"
	"cladone/gate-one/pkg/pluginmanifest"
)

// runMeter is the offline audit CLI of the metering chain.
//
//	gate-one meter verify -config api-routes.json
//	gate-one meter export -config api-routes.json -out audit.json
//	gate-one meter check  -file audit.json -publicKey <b64>
//
// verify replays the pricing of every retained outbox record against the
// configured tariffs. export writes a signed snapshot for offline audit;
// check verifies that snapshot without the gateway, the database or the
// network.
func runMeter(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr,
			"usage: gate-one meter verify|export|check "+
				"-config api-routes.json [-file audit.json] [-publicKey b64]")
		return 2
	}
	sub := args[0]
	fs := flag.NewFlagSet("meter "+sub, flag.ContinueOnError)
	configPath := fs.String("config", "api-routes.json", "routes file path")
	file := fs.String("file", "", "signed audit file (check)")
	publicKey := fs.String("publicKey", "", "base64 Ed25519 key (check)")
	out := fs.String("out", "-", "output file (- = stdout) (export)")
	format := fs.String("format", "json", "json|csv (export)")
	strict := fs.Bool("strict", false,
		"fail when a record cannot be recomputed (plugin pricing)")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}

	switch sub {
	case "verify", "export":
		cfg, err := core.Load(*configPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "meter:", err)
			return 1
		}
		box, err := openOutbox(cfg)
		if err != nil {
			fmt.Fprintln(os.Stderr, "meter:", err)
			return 1
		}
		defer func() { _ = box.Close() }()
		records, err := readRetained(box)
		if err != nil {
			fmt.Fprintln(os.Stderr, "meter:", err)
			return 1
		}
		if len(records) == 0 {
			fmt.Println("meter: no retained record in the outbox")
			return 0
		}
		if sub == "verify" {
			return verifyRecords(cfg, records, *strict)
		}
		key, err := sinkKey(cfg)
		if err != nil {
			fmt.Fprintln(os.Stderr, "meter:", err)
			return 1
		}
		return exportRecords(cfg, box, records, key, *format, *out)

	case "check":
		if *file == "" || *publicKey == "" {
			fmt.Fprintln(os.Stderr, "meter check: -file and -publicKey are required")
			return 2
		}
		pub, err := pluginmanifest.DecodePublicKey(*publicKey)
		if err != nil {
			fmt.Fprintln(os.Stderr, "meter check:", err)
			return 1
		}
		return checkAudit(*file, pub)

	default:
		fmt.Fprintf(os.Stderr, "meter: unknown subcommand %q\n", sub)
		return 2
	}
}

// meterRecord is the settled payload written by the proxy. It mirrors the
// emitter; unknown fields are ignored so old records stay verifiable.
type meterRecord struct {
	SchemaVersion  int               `json:"schemaVersion"`
	Tenant         string            `json:"tenant"`
	Metric         string            `json:"metric"`
	Quantity       int64             `json:"quantity"`
	Scale          int               `json:"scale"`
	Dimensions     map[string]string `json:"dimensions,omitempty"`
	IdempotencyKey string            `json:"idempotencyKey"`
	At             time.Time         `json:"at"`
	AmountMicro    int64             `json:"amountMicro"`
	Currency       string            `json:"currency"`
	PriceVersion   string            `json:"priceVersion"`
	EngineVersion  string            `json:"engineVersion"`
	InputsHash     string            `json:"inputsHash"`
	Settlement     string            `json:"settlement"`
}

// readRetained reads the whole retained window in bounded batches.
func readRetained(box *outbox.Store) ([]outbox.Record, error) {
	var all []outbox.Record
	cursor := int64(0)
	for {
		records, next, err := box.Read(cursor, 500, 0)
		if err != nil {
			return nil, err
		}
		if len(records) == 0 {
			return all, nil
		}
		all = append(all, records...)
		if next <= cursor {
			return all, nil
		}
		cursor = next
	}
}

// verifyRecords replays the price of each record. Declarative records are
// recomputed from the named tariff version, which is clock-independent;
// plugin decisions cannot be recomputed (the plugin may use live inputs),
// so they are counted as opaque unless -strict is set.
func verifyRecords(cfg *core.Config, records []outbox.Record, strict bool) int {
	reg := cfg.Usage.Metering
	ok, opaque, mismatches := 0, 0, 0
	seen := map[string]string{}
	for _, r := range records {
		var rec meterRecord
		if err := json.Unmarshal(r.Payload, &rec); err != nil {
			fmt.Printf("  offset %d: invalid payload: %v\n", r.Offset, err)
			mismatches++
			continue
		}
		if rec.AmountMicro < 0 {
			fmt.Printf("  offset %d: negative amount %d\n", r.Offset, rec.AmountMicro)
			mismatches++
			continue
		}
		key := rec.Tenant + "\x00" + rec.Metric + "\x00" + rec.IdempotencyKey
		if prev, dup := seen[key]; dup {
			fmt.Printf("  offset %d: duplicate of offset %s (%s/%s)\n",
				r.Offset, prev, rec.Tenant, rec.Metric)
			mismatches++
			continue
		}
		seen[key] = strconv.FormatInt(r.Offset, 10)

		if reg == nil || !strings.HasPrefix(rec.EngineVersion, "declarative") {
			opaque++
			continue
		}
		decision, err := reg.RateWithVersion(metering.Measure{
			Tenant:      rec.Tenant,
			Metric:      rec.Metric,
			Quantity:    rec.Quantity,
			Dimensions:  rec.Dimensions,
			Idempotency: rec.IdempotencyKey,
			At:          rec.At,
		}, rec.PriceVersion)
		if err != nil {
			fmt.Printf("  offset %d: %s/%s: %v\n",
				r.Offset, rec.Tenant, rec.Metric, err)
			mismatches++
			continue
		}
		if decision.AmountMicro != rec.AmountMicro ||
			decision.Currency != rec.Currency {
			fmt.Printf(
				"  offset %d: %s/%s: recorded %d %s, recomputed %d %s (%s)\n",
				r.Offset, rec.Tenant, rec.Metric,
				rec.AmountMicro, rec.Currency,
				decision.AmountMicro, decision.Currency, rec.PriceVersion)
			mismatches++
			continue
		}
		ok++
	}
	fmt.Printf("meter verify: %d record(s), %d recomputed, %d opaque, %d mismatch(es)\n",
		len(records), ok, opaque, mismatches)
	if strict && opaque > 0 {
		fmt.Printf("meter verify: -strict: %d record(s) not recomputable\n", opaque)
		return 1
	}
	if mismatches > 0 {
		return 1
	}
	return 0
}

// auditLine is one record in the signed snapshot (and in an air-gap
// bundle, so the same verifier reads both).
type auditLine struct {
	Offset int64  `json:"offset"`
	Hash   string `json:"hash"`
	Data   string `json:"data"`
}

// auditDocument is the export envelope. The signature covers
// auditPayload, a line format: no JSON canonicalisation is needed.
type auditDocument struct {
	SchemaVersion int         `json:"schemaVersion"`
	Node          string      `json:"node"`
	ExportedAt    time.Time   `json:"exportedAt"`
	FirstOffset   int64       `json:"firstOffset"`
	Head          int64       `json:"head"`
	Count         int         `json:"count"`
	SHA256        string      `json:"sha256"`
	Signature     string      `json:"signature"`
	Records       []auditLine `json:"records"`
}

func auditPayload(d auditDocument) []byte {
	lines := []string{
		"v1",
		d.Node,
		strconv.FormatInt(d.FirstOffset, 10),
		strconv.FormatInt(d.Head, 10),
		strconv.Itoa(d.Count),
		d.SHA256,
	}
	return []byte(strings.Join(lines, "\n") + "\n")
}

// auditBody is the canonical record body that SHA256 digests.
func auditBody(lines []auditLine) ([]byte, string, error) {
	var buf bytes.Buffer
	for _, l := range lines {
		raw, err := json.Marshal(l)
		if err != nil {
			return nil, "", err
		}
		buf.Write(raw)
		buf.WriteByte('\n')
	}
	sum := sha256.Sum256(buf.Bytes())
	return buf.Bytes(), hex.EncodeToString(sum[:]), nil
}

func exportRecords(
	cfg *core.Config, box *outbox.Store, records []outbox.Record,
	key ed25519.PrivateKey, format, out string,
) int {
	lines := make([]auditLine, 0, len(records))
	total := int64(0)
	for _, r := range records {
		sum := sha256.Sum256(r.Payload)
		lines = append(lines, auditLine{
			Offset: r.Offset,
			Hash:   "sha256:" + hex.EncodeToString(sum[:]),
			Data:   base64.RawURLEncoding.EncodeToString(r.Payload),
		})
		total += int64(len(r.Payload))
	}
	doc := auditDocument{
		SchemaVersion: 1,
		Node:          cfg.Usage.NodeID,
		ExportedAt:    time.Now().UTC(),
		FirstOffset:   lines[0].Offset,
		Head:          box.Head(),
		Count:         len(lines),
		Records:       lines,
	}
	_, doc.SHA256, _ = auditBody(lines)
	doc.Signature = base64.RawURLEncoding.EncodeToString(
		ed25519.Sign(key, auditPayload(doc)))

	var (
		raw []byte
		err error
	)
	switch format {
	case "json":
		raw, err = json.MarshalIndent(doc, "", "  ")
		raw = append(raw, '\n')
	case "csv":
		raw, err = csvBody(records)
	default:
		fmt.Fprintf(os.Stderr, "meter export: unknown format %q\n", format)
		return 2
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "meter export:", err)
		return 1
	}
	if out == "" || out == "-" {
		_, _ = os.Stdout.Write(raw)
		return 0
	}
	if err := os.WriteFile(out, raw, 0o600); err != nil {
		fmt.Fprintln(os.Stderr, "meter export:", err)
		return 1
	}
	if format == "csv" {
		fmt.Fprintln(os.Stderr,
			"meter export: csv is a human extract and is not signed; "+
				"use -format json for an auditable snapshot")
	}
	fmt.Fprintf(os.Stderr,
		"meter export: %d record(s), %d byte(s) of payload, %s (%s)\n",
		len(records), total, out, format)
	return 0
}

func csvBody(records []outbox.Record) ([]byte, error) {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	header := []string{
		"offset", "tenant", "metric", "quantity", "scale", "amountMicro",
		"currency", "priceVersion", "engineVersion", "settlement",
		"idempotencyKey", "at",
	}
	if err := w.Write(header); err != nil {
		return nil, err
	}
	for _, r := range records {
		var rec meterRecord
		if err := json.Unmarshal(r.Payload, &rec); err != nil {
			return nil, fmt.Errorf("offset %d: %w", r.Offset, err)
		}
		if err := w.Write([]string{
			strconv.FormatInt(r.Offset, 10), rec.Tenant, rec.Metric,
			strconv.FormatInt(rec.Quantity, 10), strconv.Itoa(rec.Scale),
			strconv.FormatInt(rec.AmountMicro, 10), rec.Currency,
			rec.PriceVersion, rec.EngineVersion, rec.Settlement,
			rec.IdempotencyKey, rec.At.UTC().Format(time.RFC3339Nano),
		}); err != nil {
			return nil, err
		}
	}
	w.Flush()
	return buf.Bytes(), w.Error()
}

// checkAudit verifies a JSON snapshot with no local state: the signature,
// then every record hash, then the body digest. It also reports the
// amount per (tenant, metric, currency, price version).
func checkAudit(path string, pub ed25519.PublicKey) int {
	raw, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "meter check:", err)
		return 1
	}
	var doc auditDocument
	if err := json.Unmarshal(raw, &doc); err != nil {
		fmt.Fprintln(os.Stderr, "meter check:", err)
		return 1
	}
	if doc.SchemaVersion != 1 {
		fmt.Fprintf(os.Stderr, "meter check: unsupported schema %d\n",
			doc.SchemaVersion)
		return 1
	}
	sig, err := base64.RawURLEncoding.DecodeString(doc.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		fmt.Fprintln(os.Stderr, "meter check: missing or malformed signature")
		return 1
	}
	if !ed25519.Verify(pub, auditPayload(doc), sig) {
		fmt.Fprintln(os.Stderr, "meter check: bad signature")
		return 1
	}
	_, digest, err := auditBody(doc.Records)
	if err != nil {
		fmt.Fprintln(os.Stderr, "meter check:", err)
		return 1
	}
	if digest != doc.SHA256 {
		fmt.Fprintf(os.Stderr,
			"meter check: body digest %s does not match the envelope (%s)\n",
			digest, doc.SHA256)
		return 1
	}
	bad := 0
	type key struct{ tenant, metric, currency, version string }
	sums := map[key]int64{}
	for _, l := range doc.Records {
		payload, err := base64.RawURLEncoding.DecodeString(l.Data)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  offset %d: invalid base64 data\n", l.Offset)
			bad++
			continue
		}
		sum := sha256.Sum256(payload)
		if got := "sha256:" + hex.EncodeToString(sum[:]); got != l.Hash {
			fmt.Fprintf(os.Stderr, "  offset %d: hash %s, want %s\n",
				l.Offset, got, l.Hash)
			bad++
			continue
		}
		var rec meterRecord
		if err := json.Unmarshal(payload, &rec); err != nil {
			fmt.Fprintf(os.Stderr, "  offset %d: invalid payload\n", l.Offset)
			bad++
			continue
		}
		k := key{rec.Tenant, rec.Metric, rec.Currency, rec.PriceVersion}
		sums[k] += rec.AmountMicro
	}
	if bad > 0 {
		fmt.Printf("meter check: %d bad record(s)\n", bad)
		return 1
	}
	fmt.Printf("meter check: signature and %d record hash(es) OK, node %s, "+
		"offsets %d..%d\n", len(doc.Records), doc.Node,
		doc.FirstOffset, doc.Head)
	keys := make([]key, 0, len(sums))
	for k := range sums {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		return a.tenant+a.metric+a.version < b.tenant+b.metric+b.version
	})
	for _, k := range keys {
		fmt.Printf("  %s/%s %d µ%s (%.2f %s, version %s)\n",
			k.tenant, k.metric, sums[k], k.currency,
			float64(sums[k])/1e6, k.currency, k.version)
	}
	return 0
}

// sinkKey decodes the configured signing seed (base64url, 32 bytes).
func sinkKey(cfg *core.Config) (ed25519.PrivateKey, error) {
	if cfg.Usage == nil || len(cfg.Usage.SinkSigningSeed) == 0 {
		return nil, fmt.Errorf("usage.sink.signingKeyEnv is not configured")
	}
	seed, err := base64.RawURLEncoding.DecodeString(
		string(cfg.Usage.SinkSigningSeed))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf(
			"usage.sink.signingKeyEnv: expected a base64url 32-byte seed")
	}
	return ed25519.NewKeyFromSeed(seed), nil
}
