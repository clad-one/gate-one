package proxy

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"cladone/gate-one/internal/metering"
	"cladone/gate-one/internal/pricingplugin"
)

// pricedConfig is meteredConfig with a plugin-priced metric and a
// declarative fallback.
func pricedConfig(
	t *testing.T, allowancePath, allowancePub, licToken, licPub, backend, pluginURL string,
) string {
	t.Helper()
	t.Setenv("TEST_SUBJECT_SECRET", "s")
	t.Setenv("TEST_PLUGIN_SECRET", "p")
	t.Setenv("TEST_SINK_KEY", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	return fmt.Sprintf(`{
		"license": {"token": %q, "publicKey": %q},
		"authProvider": {"type": "dev",
			"loginBaseUrl": "http://login.dev.test:3000", "cookieDomain": "dev.test"},
		"usage": {
			"dir": %q, "nodeId": "gw-1",
			"subjectSecretEnv": "TEST_SUBJECT_SECRET",
			"pluginSecretEnv": "TEST_PLUGIN_SECRET",
			"budgetBytes": 1048576,
			"types": {"billing": {"shareBytes": 1048576, "fsync": "none"}},
			"plugins": [{"name": "audit", "url": "http://127.0.0.1:1", "types": ["billing"]}],
			"profile": "airgap",
			"allowanceFile": %q,
			"allowancePublicKey": %q,
			"sink": {"exportDir": %q, "signingKeyEnv": "TEST_SINK_KEY",
				"receiptPublicKey": "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg",
				"batchWaitMs": 5000},
			"metrics": {
				"llm.tokens": {"unit": "token", "scale": 0, "maxDimensions": 1,
					"dimensions": {"model": {"type": "string", "maxLength": 32}},
					"pricing": "plugin", "pricingPlugin": "pricer",
					"fallback": "llm.tokens.ceiling"}
			},
			"tariffs": {
				"llm.tokens.ceiling": {"metric": "llm.tokens",
					"version": "llm.tokens.ceiling", "currency": "EUR",
					"effectiveFrom": "2026-01-01T00:00:00Z",
					"charges": [{"model": "unit", "amountMicro": 8000}]}
			},
			"pricingPlugins": {"pricer": {"url": %q,
				"publicKey": "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg",
				"timeoutMs": 50}}
		},
		"routes": [{
			"host": "app.test", "path": "/*", "backend": %q, "metric": "llm.tokens"
		}]
	}`, licToken, licPub, t.TempDir(), allowancePath, allowancePub,
		filepath.Join(t.TempDir(), "export"), pluginURL, backend)
}

func lastRecord(t *testing.T, gw *Gateway) map[string]any {
	t.Helper()
	recs, _, err := gw.billing.box.Read(0, 100, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) == 0 {
		t.Fatal("no record in the outbox")
	}
	var payload map[string]any
	if err := json.Unmarshal(recs[len(recs)-1].Payload, &payload); err != nil {
		t.Fatal(err)
	}
	return payload
}

func TestPluginPricingFallsBackWhenDown(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
	t.Cleanup(backend.Close)

	dir := t.TempDir()
	allowancePath, allowancePub := writeAllowance(t, dir, 100000)
	lic, licPub := licenseToken(t, "billing-byo")
	cfg := loadForTest(t, pricedConfig(
		t, allowancePath, allowancePub, lic, licPub, backend.URL, "http://127.0.0.1:1"))
	gw, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer gw.Close()

	r := httptest.NewRequest(http.MethodGet, "http://app.test/x", nil)
	r.Host = "app.test"
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, r)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	payload := lastRecord(t, gw)
	if payload["amountMicro"] != float64(8000) {
		t.Fatalf("amount = %v, want the declarative ceiling 8000", payload["amountMicro"])
	}
	if payload["priceVersion"] != "llm.tokens.ceiling" {
		t.Fatalf("priceVersion = %v", payload["priceVersion"])
	}
}

func TestPluginPricingUsesSignedDecision(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
	t.Cleanup(backend.Close)

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// A real pricer would sign its own decision; reuse the reference
	// plugin's payload format via the exported helper.
	pricer := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			d := metering.Decision{
				AmountMicro: 4200, Currency: "EUR", PriceVersion: "pricer-v1",
				EngineVersion: "pricer@v1", InputsHash: "sha256:aa",
			}
			d.Signature = ed25519.Sign(priv, pricingplugin.DecisionPayload(d))
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"amountMicro": d.AmountMicro, "currency": d.Currency,
				"priceVersion": d.PriceVersion, "engineVersion": d.EngineVersion,
				"inputsHash": d.InputsHash,
				"signature":  base64.RawURLEncoding.EncodeToString(d.Signature),
			})
		}))
	t.Cleanup(pricer.Close)

	dir := t.TempDir()
	allowancePath, allowancePub := writeAllowance(t, dir, 100000)
	lic, licPub := licenseToken(t, "billing-byo")
	raw := pricedConfig(t, allowancePath, allowancePub, lic, licPub, backend.URL, pricer.URL)
	// Point the plugin's configured key at this test's public key.
	raw = strings.Replace(raw,
		`"publicKey": "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg"`,
		`"publicKey": "`+base64.RawURLEncoding.EncodeToString(pub)+`"`, 1)
	cfg := loadForTest(t, raw)
	gw, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer gw.Close()

	r := httptest.NewRequest(http.MethodGet, "http://app.test/x", nil)
	r.Host = "app.test"
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, r)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	payload := lastRecord(t, gw)
	if payload["amountMicro"] != float64(4200) {
		t.Fatalf("amount = %v, want the plugin's 4200", payload["amountMicro"])
	}
	if payload["priceVersion"] != "pricer-v1" {
		t.Fatalf("priceVersion = %v", payload["priceVersion"])
	}
}
