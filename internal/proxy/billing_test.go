package proxy

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"cladone/gate-one/internal/credit"
)

func writeAllowance(t *testing.T, dir string, amount int64) (string, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	a, err := credit.SignAllowance(credit.Allowance{
		Tenant: "default", Metric: "*", AllowanceMicro: amount,
		Currency: "EUR", ExpiresAt: time.Now().Add(time.Hour),
	}, priv)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "allowance.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path, base64.RawURLEncoding.EncodeToString(pub)
}

func meteredConfig(t *testing.T, allowancePath, pubKey, backend string) string {
	t.Helper()
	t.Setenv("TEST_SUBJECT_SECRET", "s")
	t.Setenv("TEST_PLUGIN_SECRET", "p")
	return fmt.Sprintf(`{
		"authProvider": {
			"type": "dev",
			"loginBaseUrl": "http://login.dev.test:3000",
			"cookieDomain": "dev.test"
		},
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
			"metrics": {
				"api.request": {"unit": "request", "scale": 0, "maxDimensions": 1,
					"dimensions": {"route": {"type": "string", "maxLength": 64}}}
			},
			"tariffs": {
				"api.request.v1": {"metric": "api.request", "version": "api.request.v1",
					"currency": "EUR", "effectiveFrom": "2026-01-01T00:00:00Z",
					"charges": [{"model": "unit", "amountMicro": 1200}]}
			}
		},
		"routes": [{
			"host": "app.test", "path": "/*", "backend": %q, "metric": "api.request"
		}]
	}`, t.TempDir(), allowancePath, pubKey, backend)
}

func TestMeteredAdmissionAndExhaustion(t *testing.T) {
	var hits atomic.Int32
	backend := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			hits.Add(1)
			w.WriteHeader(http.StatusOK)
		}))
	t.Cleanup(backend.Close)

	dir := t.TempDir()
	allowancePath, pub := writeAllowance(t, dir, 2500) // 2 requêtes à 1200
	cfg := loadForTest(t, meteredConfig(t, allowancePath, pub, backend.URL))
	gw, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer gw.Close()

	req := func() int {
		r := httptest.NewRequest(http.MethodGet, "http://app.test/x", nil)
		r.Host = "app.test"
		rec := httptest.NewRecorder()
		gw.ServeHTTP(rec, r)
		return rec.Code
	}

	if code := req(); code != http.StatusOK {
		t.Fatalf("first = %d", code)
	}
	if code := req(); code != http.StatusOK {
		t.Fatalf("second = %d", code)
	}
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "http://app.test/x", nil)
	r.Host = "app.test"
	gw.ServeHTTP(rec, r)
	if rec.Code != http.StatusPaymentRequired {
		t.Fatalf("third = %d, want 402", rec.Code)
	}
	if hits.Load() != 2 {
		t.Fatalf("backend calls = %d, want 2", hits.Load())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["error"] != "insufficient_allowance" {
		t.Fatalf("error = %v", body["error"])
	}
}

func TestMeteredServerErrorIsReleased(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
	t.Cleanup(backend.Close)

	dir := t.TempDir()
	allowancePath, pub := writeAllowance(t, dir, 1200) // une seule requête
	cfg := loadForTest(t, meteredConfig(t, allowancePath, pub, backend.URL))
	gw, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer gw.Close()

	do := func() int {
		r := httptest.NewRequest(http.MethodGet, "http://app.test/x", nil)
		r.Host = "app.test"
		rec := httptest.NewRecorder()
		gw.ServeHTTP(rec, r)
		return rec.Code
	}
	// Le backend échoue : la réservation est libérée.
	if code := do(); code != http.StatusInternalServerError {
		t.Fatalf("first = %d", code)
	}
	// Une seconde requête doit donc encore être autorisée.
	if code := do(); code != http.StatusInternalServerError {
		t.Fatalf("second = %d (reservation not released?)", code)
	}
}
