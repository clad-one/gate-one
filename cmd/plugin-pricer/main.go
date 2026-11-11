// Command plugin-pricer is a reference signed pricing plugin. It prices a
// usage metric at a flat per-unit rate and signs the decision, so the
// gateway can verify an amount it did not compute.
//
//	gate-one keygen -out pricer.key -keyId pricer-2026
//	export PRICER_PLUGIN_SECRET=...     # not used: the signature is the proof
//	go run ./cmd/plugin-pricer -addr :9300 -key pricer.key \
//	    -micro-per-unit 12 -currency EUR
//
// The matching gateway configuration:
//
//	"usage": {
//	  "pricingPlugins": {"llm-pricer": {
//	     "url": "http://pricer:9300",
//	     "publicKey": "<base64url public key of pricer.key>"}},
//	  "metrics": {"llm.tokens": {
//	     "unit": "token", "scale": 0, "pricing": "plugin",
//	     "pricingPlugin": "llm-pricer", "fallback": "llm.tokens.ceiling"}}
//	}
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"time"

	"cladone/gate-one/internal/metering"
	"cladone/gate-one/internal/pricingplugin"
)

type keyFile struct {
	KeyID     string `json:"keyId"`
	Seed      string `json:"seed"`
	PublicKey string `json:"publicKey"`
}

type priceRequest struct {
	Tenant     string            `json:"tenant"`
	Metric     string            `json:"metric"`
	Quantity   int64             `json:"quantity"`
	Scale      int               `json:"scale"`
	Dimensions map[string]string `json:"dimensions,omitempty"`
	At         time.Time         `json:"at"`
	RequestID  string            `json:"requestId,omitempty"`
}

type priceResponse struct {
	AmountMicro   int64  `json:"amountMicro"`
	Currency      string `json:"currency"`
	PriceVersion  string `json:"priceVersion"`
	EngineVersion string `json:"engineVersion"`
	InputsHash    string `json:"inputsHash"`
	Signature     string `json:"signature"`
}

func main() {
	addr := flag.String("addr", ":9300", "listen address")
	keyPath := flag.String("key", "", "private key file from `gate-one keygen`")
	microPerUnit := flag.Int64("micro-per-unit", 12, "price per unit, in micro-units")
	currency := flag.String("currency", "EUR", "billing currency")
	version := flag.String("version", "pricer-v1", "price version")
	flag.Parse()
	if *keyPath == "" {
		log.Fatal("plugin-pricer: -key is required")
	}
	seed, err := loadSeed(*keyPath)
	if err != nil {
		log.Fatal(err)
	}
	priv := ed25519.NewKeyFromSeed(seed)

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/price", func(w http.ResponseWriter, r *http.Request) {
		var req priceRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		amount, err := rate(req.Quantity, *microPerUnit, req.Scale)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		sum := sha256.Sum256([]byte(fmt.Sprintf(
			"%s|%s|%d|%d|%s", req.Tenant, req.Metric, req.Quantity, amount, *version)))
		d := metering.Decision{
			AmountMicro:   amount,
			Currency:      *currency,
			PriceVersion:  *version,
			EngineVersion: "pricer@v1",
			InputsHash:    "sha256:" + hex.EncodeToString(sum[:]),
		}
		d.Signature = ed25519.Sign(priv, pricingplugin.DecisionPayload(d))
		resp := priceResponse{
			AmountMicro: d.AmountMicro, Currency: d.Currency,
			PriceVersion: d.PriceVersion, EngineVersion: d.EngineVersion,
			InputsHash: d.InputsHash,
			Signature:  base64.RawURLEncoding.EncodeToString(d.Signature),
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})
	log.Printf("plugin-pricer listening on %s (%d µ%s/unit, version %s)",
		*addr, *microPerUnit, *currency, *version)
	log.Fatal(http.ListenAndServe(*addr, mux))
}

// rate computes quantity*microPerUnit/10^scale, rounded half-up.
func rate(quantity, microPerUnit int64, scale int) (int64, error) {
	if quantity < 0 || microPerUnit < 0 {
		return 0, fmt.Errorf("negative operand")
	}
	num := new(big.Int).Mul(big.NewInt(quantity), big.NewInt(microPerUnit))
	pow, err := metering.Pow10(scale)
	if err != nil {
		return 0, err
	}
	den := big.NewInt(pow)
	q, r := new(big.Int), new(big.Int)
	q.QuoRem(num, den, r)
	if r.Sign() > 0 && new(big.Int).Lsh(r, 1).Cmp(den) >= 0 {
		q.Add(q, big.NewInt(1))
	}
	if !q.IsInt64() {
		return 0, fmt.Errorf("overflow")
	}
	return q.Int64(), nil
}

func loadSeed(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var k keyFile
	if err := json.Unmarshal(raw, &k); err != nil {
		return nil, err
	}
	seed, err := base64.RawURLEncoding.DecodeString(k.Seed)
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("plugin-pricer: invalid seed")
	}
	return seed, nil
}
