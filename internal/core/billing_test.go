package core

import (
	"strings"
	"testing"
	"time"
)

// billingConfig builds a minimal usage block with one metric, one tariff
// and a route bound to that metric.
func billingConfig() string {
	return `{
		"authProvider": {
			"type": "dev",
			"loginBaseUrl": "http://login.dev.test:3000",
			"cookieDomain": "dev.test"
		},
		"usage": {
			"dir": "usage-wal",
			"nodeId": "gw-1",
			"subjectSecretEnv": "TEST_SUBJECT_SECRET",
			"pluginSecretEnv": "TEST_PLUGIN_SECRET",
			"budgetBytes": 1000000,
			"types": {"billing": {"shareBytes": 1000000, "fsync": "none"}},
			"plugins": [{"name": "audit", "url": "http://127.0.0.1:9100", "types": ["billing"]}],
			"sink": {"url": "http://127.0.0.1:1", "exportDir": "usage-export",
				"signingKeyEnv": "TEST_SINK_KEY",
				"receiptPublicKey": "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg"},
			"metrics": {
				"api.request": {
					"unit": "request", "scale": 0, "maxDimensions": 1,
					"dimensions": {"route": {"type": "string", "maxLength": 64}}
				}
			},
			"tariffs": {
				"api.request.v1": {
					"metric": "api.request", "version": "api.request.v1",
					"currency": "EUR", "effectiveFrom": "2026-01-01T00:00:00Z",
					"charges": [{"model": "unit", "amountMicro": 1200}]
				}
			}
		},
		"routes": [{
			"host": "app.dev.test", "path": "/*", "frontend": true,
			"backend": "http://127.0.0.1:1", "auth": {},
			"metric": "api.request"
		}]
	}`
}

func loadBillingRaw(t *testing.T, raw string) (*Config, error) {
	t.Helper()
	t.Setenv("TEST_SUBJECT_SECRET", "s")
	t.Setenv("TEST_PLUGIN_SECRET", "p")
	t.Setenv("TEST_SINK_KEY", testSinkSeed)
	return loadAuthTest(t, raw)
}

// testSinkSeed is a base64url 32-byte Ed25519 seed (all zeros).
const testSinkSeed = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

func TestBillingConfigValid(t *testing.T) {
	cfg, err := loadBillingRaw(t, billingConfig())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Usage.Metering == nil {
		t.Fatal("metering registry not built")
	}
	if _, ok := cfg.Usage.Metering.Metric("api.request"); !ok {
		t.Fatal("metric not registered")
	}
	at, _ := time.Parse(time.RFC3339, "2026-03-01T00:00:00Z")
	if _, ok := cfg.Usage.Metering.TariffInEffect("api.request", at); !ok {
		t.Fatal("tariff not in effect")
	}
	if cfg.Routes[0].Metric != "api.request" {
		t.Fatalf("route metric = %q", cfg.Routes[0].Metric)
	}
}

func TestBillingConfigRejects(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(string) string
		wantErr string
	}{
		{
			"profile",
			func(s string) string {
				return strings.Replace(s, `"plugins":`,
					`"profile": "cloud", "plugins":`, 1)
			},
			"must be online or airgap",
		},
		{
			"scale",
			func(s string) string {
				return strings.Replace(s,
					`"unit": "request", "scale": 0`,
					`"unit": "request", "scale": 4`, 1)
			},
			"scale must be 0, 3 or 6",
		},
		{
			"plugin fallback unknown",
			func(s string) string {
				return strings.Replace(s,
					`"unit": "request", "scale": 0`,
					`"unit": "request", "scale": 0, "pricing": "plugin", "fallback": "nope"`, 1)
			},
			"fallback",
		},
		{
			"filter on undeclared dimension",
			func(s string) string {
				return strings.Replace(s,
					`"charges": [{"model": "unit", "amountMicro": 1200}]`,
					`"charges": [{"model": "unit", "amountMicro": 1200, "filter": {"nope": ["x"]}}]`, 1)
			},
			"undeclared dimension",
		},
		{
			"airgap without allowance",
			func(s string) string {
				return strings.Replace(s, `"plugins":`,
					`"profile": "airgap", "plugins":`, 1)
			},
			"allowanceFile",
		},
		{
			"tariff for unknown metric",
			func(s string) string {
				return strings.Replace(s,
					`"metric": "api.request"`, `"metric": "ghost"`, 1)
			},
			"unknown metric",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := loadBillingRaw(t, c.mutate(billingConfig()))
			if err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Fatalf("err = %v, want %q", err, c.wantErr)
			}
		})
	}
}
