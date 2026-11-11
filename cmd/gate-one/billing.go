package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"cladone/gate-one/internal/core"
	"cladone/gate-one/internal/outbox"
	"cladone/gate-one/internal/sink"
	"cladone/gate-one/pkg/pluginmanifest"
)

// runBilling is the operator CLI of the billing outbox.
//
//	gate-one billing pending -config api-routes.json
//	gate-one billing ack     -config api-routes.json -receipt receipt.json
func runBilling(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr,
			"usage: gate-one billing pending|ack -config api-routes.json [-receipt file]")
		return 2
	}
	sub := args[0]
	fs := flag.NewFlagSet("billing "+sub, flag.ContinueOnError)
	configPath := fs.String("config", "api-routes.json", "routes file path")
	receiptPath := fs.String("receipt", "", "signed receipt file (ack)")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}

	cfg, err := core.Load(*configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "billing:", err)
		return 1
	}
	box, err := openOutbox(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "billing:", err)
		return 1
	}
	defer func() { _ = box.Close() }()

	switch sub {
	case "pending":
		records, bytes, oldest, dropped := box.Stats()
		age := "-"
		if !oldest.IsZero() {
			age = time.Since(oldest).Round(time.Second).String()
		}
		fmt.Printf(
			"outbox %s\n  pending: %d record(s), %d byte(s), oldest %s\n"+
				"  head: %d  committed: %d  dropped: %d\n",
			cfg.Usage.Outbox.Dir, records, bytes, age,
			box.Head(), box.CommitOffset(), dropped)
		return 0

	case "ack":
		if *receiptPath == "" {
			fmt.Fprintln(os.Stderr, "billing ack: -receipt is required")
			return 2
		}
		pubB64 := ""
		if cfg.Usage.Sink != nil {
			pubB64 = cfg.Usage.Sink.ReceiptPublicKey
		}
		if pubB64 == "" {
			fmt.Fprintln(os.Stderr,
				"billing ack: usage.sink.receiptPublicKey is not configured")
			return 1
		}
		pub, err := pluginmanifest.DecodePublicKey(pubB64)
		if err != nil {
			fmt.Fprintln(os.Stderr, "billing ack:", err)
			return 1
		}
		receipt, err := sink.LoadReceipt(*receiptPath, pub)
		if err != nil {
			fmt.Fprintln(os.Stderr, "billing ack:", err)
			return 1
		}
		if err := box.Commit(receipt.NextOffset); err != nil {
			fmt.Fprintln(os.Stderr, "billing ack:", err)
			return 1
		}
		fmt.Printf(
			"bundle %s: %d accepted, %d duplicate(s), %d rejected; "+
				"committed to %d\n",
			receipt.BundleID, receipt.Accepted, receipt.Duplicates,
			len(receipt.Rejected), receipt.NextOffset)
		for _, r := range receipt.Rejected {
			fmt.Printf("  rejected offset %d: %s\n", r.Offset, r.Reason)
		}
		return 0

	default:
		fmt.Fprintf(os.Stderr, "billing: unknown subcommand %q\n", sub)
		return 2
	}
}

// openOutbox opens the configured outbox (the directory must exist or be
// creatable; the gateway normally owns it).
func openOutbox(cfg *core.Config) (*outbox.Store, error) {
	if cfg.Usage == nil || cfg.Usage.Outbox == nil {
		return nil, fmt.Errorf("usage.outbox is not configured")
	}
	maxAge, err := time.ParseDuration(cfg.Usage.Outbox.MaxAge)
	if err != nil {
		return nil, fmt.Errorf("usage.outbox.maxAge: %w", err)
	}
	return outbox.Open(outbox.Config{
		Dir:        cfg.Usage.Outbox.Dir,
		MaxAge:     maxAge,
		MaxBytes:   cfg.Usage.Outbox.MaxBytes,
		MaxRecords: cfg.Usage.Outbox.MaxRecords,
		OnFull:     cfg.Usage.Outbox.OnFull,
	})
}
