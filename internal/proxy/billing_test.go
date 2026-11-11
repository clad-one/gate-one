package proxy

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"cladone/gate-one/internal/credit"
)

// licenseToken mints a signed licence token carrying the given features.
func licenseToken(t *testing.T, features ...string) (token, pub string) {
	t.Helper()
	pubKey, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	claims := map[string]any{
		"org": "test", "email": "t@test", "plan": "owner",
		"exp":      time.Now().Add(time.Hour).Unix(),
		"domains":  []string{"app.test"},
		"features": features,
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(priv, payload)
	enc := base64.RawURLEncoding.EncodeToString
	return "v1." + enc(payload) + "." + enc(sig), enc(pubKey)
}

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

func meteredConfig(
	t *testing.T, allowancePath, pubKey, backend, licToken, licPub string,
) string {
	t.Helper()
	t.Setenv("TEST_SUBJECT_SECRET", "s")
	t.Setenv("TEST_PLUGIN_SECRET", "p")
	t.Setenv("TEST_SINK_KEY", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	return fmt.Sprintf(`{
		"license": {"token": %q, "publicKey": %q},
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
			"sink": {"exportDir": %q, "signingKeyEnv": "TEST_SINK_KEY",
				"receiptPublicKey": "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg",
				"batchWaitMs": 10, "exportAfterSeconds": 1},
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
	}`, licToken, licPub, t.TempDir(), filepath.Join(t.TempDir(), "export"),
		allowancePath, pubKey, backend)
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
	lic, licPub := licenseToken(t, "billing-byo")
	cfg := loadForTest(t, meteredConfig(t, allowancePath, pub, backend.URL, lic, licPub))
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
	lic, licPub := licenseToken(t, "billing-byo")
	cfg := loadForTest(t, meteredConfig(t, allowancePath, pub, backend.URL, lic, licPub))
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

func TestAirgapRequiresBYOLicense(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
	t.Cleanup(backend.Close)

	dir := t.TempDir()
	allowancePath, pub := writeAllowance(t, dir, 1200)
	lic, licPub := licenseToken(t) // no features
	cfg := loadForTest(t, meteredConfig(t, allowancePath, pub, backend.URL, lic, licPub))
	if _, err := New(cfg); err == nil ||
		!strings.Contains(err.Error(), "billing-byo") {
		t.Fatalf("err = %v, want a billing-byo refusal", err)
	}
}

func TestMeteredRecordReachesSink(t *testing.T) {
	var mu sync.Mutex
	var payloads []string
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			raw, _ := io.ReadAll(r.Body)
			mu.Lock()
			payloads = append(payloads, string(raw))
			mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
		}))
	t.Cleanup(srv.Close)

	backend := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
	t.Cleanup(backend.Close)

	dir := t.TempDir()
	allowancePath, pub := writeAllowance(t, dir, 5000)
	lic, licPub := licenseToken(t, "billing-byo")
	raw := meteredConfig(t, allowancePath, pub, backend.URL, lic, licPub)
	// Point the sink at the fake server.
	raw = strings.Replace(raw,
		`"sink": {"exportDir":`,
		`"sink": {"url": "`+srv.URL+`", "exportDir":`, 1)
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

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := len(payloads)
		mu.Unlock()
		if n > 0 && gw.billing.box.CommitOffset() == gw.billing.box.Head() {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(payloads) == 0 {
		t.Fatal("sink received nothing")
	}
	var batch struct {
		Records []struct {
			Data string `json:"data"`
		} `json:"records"`
	}
	if err := json.Unmarshal([]byte(payloads[0]), &batch); err != nil {
		t.Fatalf("batch: %v", err)
	}
	if len(batch.Records) == 0 {
		t.Fatal("empty batch")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(batch.Records[0].Data)
	if err != nil {
		t.Fatal(err)
	}
	record := string(decoded)
	if !strings.Contains(record, `"metric":"api.request"`) ||
		!strings.Contains(record, `"settlement":"settled"`) ||
		!strings.Contains(record, `"amountMicro":1200`) {
		t.Fatalf("record = %s", record)
	}
}
