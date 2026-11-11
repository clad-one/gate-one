package main

import (
	"crypto/ed25519"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"cladone/gate-one/internal/credit"
)

// runAllowance mints a signed spending allowance (airgap profile). The
// managed side issues it; the operator's gateway verifies it with
// usage.allowancePublicKey.
//
//	gate-one allowance -key issuer.key -tenant company -amount-micro 5000000 \
//	    -expires 2027-01-01T00:00:00Z -out allowance.json
func runAllowance(args []string) int {
	fs := flag.NewFlagSet("allowance", flag.ContinueOnError)
	keyPath := fs.String("key", "", "private key file from `gate-one keygen`")
	tenant := fs.String("tenant", "", "tenant covered by the allowance")
	metric := fs.String("metric", "*", "metric covered (* = all)")
	amount := fs.Int64("amount-micro", 0, "allowance in micro-units of the currency")
	currency := fs.String("currency", "EUR", "billing currency")
	period := fs.String("period", "", "label of the covered period (optional)")
	expires := fs.String("expires", "", "expiry (RFC 3339, e.g. 2027-01-01T00:00:00Z)")
	out := fs.String("out", "-", "output file (- = stdout)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *keyPath == "" || *tenant == "" || *amount <= 0 || *expires == "" {
		fmt.Fprintln(os.Stderr,
			"allowance: -key, -tenant, -amount-micro and -expires are required")
		return 2
	}
	exp, err := time.Parse(time.RFC3339, *expires)
	if err != nil {
		fmt.Fprintln(os.Stderr, "allowance: -expires:", err)
		return 1
	}
	k, err := loadKeyFile(*keyPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "allowance:", err)
		return 1
	}
	priv, err := seedOf(k)
	if err != nil {
		fmt.Fprintln(os.Stderr, "allowance:", err)
		return 1
	}
	a := credit.Allowance{
		Tenant:         *tenant,
		Metric:         *metric,
		AllowanceMicro: *amount,
		Currency:       *currency,
		Period:         *period,
		ExpiresAt:      exp.UTC(),
	}
	signed, err := credit.SignAllowance(a, ed25519.PrivateKey(priv))
	if err != nil {
		fmt.Fprintln(os.Stderr, "allowance:", err)
		return 1
	}
	raw, err := json.MarshalIndent(signed, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, "allowance:", err)
		return 1
	}
	raw = append(raw, '\n')
	if *out == "" || *out == "-" {
		_, _ = os.Stdout.Write(raw)
		return 0
	}
	if err := os.WriteFile(*out, raw, 0o600); err != nil {
		fmt.Fprintln(os.Stderr, "allowance:", err)
		return 1
	}
	fmt.Fprintf(os.Stderr,
		"allowance written: %s (tenant %s, %d µ%s, expires %s)\n",
		*out, *tenant, *amount, *currency, exp.UTC().Format(time.RFC3339))
	return 0
}
