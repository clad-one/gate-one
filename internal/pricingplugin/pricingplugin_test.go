package pricingplugin

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"cladone/gate-one/internal/metering"
)

func sign(t *testing.T, priv ed25519.PrivateKey, d metering.Decision) string {
	t.Helper()
	return base64.RawURLEncoding.EncodeToString(
		ed25519.Sign(priv, DecisionPayload(d)))
}

func server(t *testing.T, handler func(metering.Decision) (int, []byte)) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			hits.Add(1)
			var req struct {
				Quantity int64 `json:"quantity"`
				Scale    int   `json:"scale"`
			}
			_ = json.NewDecoder(r.Body).Decode(&req)
			code, body := handler(metering.Decision{
				AmountMicro:   req.Quantity * 12,
				Currency:      "EUR",
				PriceVersion:  "pricer-v1",
				EngineVersion: "pricer@v1",
				InputsHash:    "sha256:aa",
			})
			w.WriteHeader(code)
			_, _ = w.Write(body)
		}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

func client(t *testing.T, url string, pub ed25519.PublicKey, timeout time.Duration, failures int) *Client {
	t.Helper()
	c, err := New(Config{
		Name: "pricer", URL: url, Public: pub,
		Timeout: timeout, Failures: failures, Cooldown: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func measure() metering.Measure {
	return metering.Measure{
		Tenant: "company", Metric: "llm.tokens", Quantity: 1000,
		Idempotency: "k1", At: time.Now(),
	}
}

func TestPriceSignedDecision(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	srv, hits := server(t, func(d metering.Decision) (int, []byte) {
		doc := map[string]any{
			"amountMicro": d.AmountMicro, "currency": d.Currency,
			"priceVersion": d.PriceVersion, "engineVersion": d.EngineVersion,
			"inputsHash": d.InputsHash, "signature": sign(t, priv, d),
		}
		raw, _ := json.Marshal(doc)
		return http.StatusOK, raw
	})
	c := client(t, srv.URL, pub, time.Second, 3)
	d, err := c.Price(context.Background(), measure(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if d.AmountMicro != 12000 || d.Currency != "EUR" {
		t.Fatalf("decision = %+v", d)
	}
	if hits.Load() != 1 {
		t.Fatalf("hits = %d", hits.Load())
	}
}

func TestPriceRejectsBadSignature(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	srv, _ := server(t, func(d metering.Decision) (int, []byte) {
		doc := map[string]any{
			"amountMicro": d.AmountMicro, "currency": d.Currency,
			"priceVersion": d.PriceVersion, "engineVersion": d.EngineVersion,
			"inputsHash": d.InputsHash, "signature": sign(t, priv, d),
		}
		raw, _ := json.Marshal(doc)
		return http.StatusOK, raw
	})
	c := client(t, srv.URL, otherPub, time.Second, 3)
	if _, err := c.Price(context.Background(), measure(), 0); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("err = %v, want ErrBadSignature", err)
	}
}

func TestPriceRejectsNegativeAmount(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	srv, _ := server(t, func(d metering.Decision) (int, []byte) {
		d.AmountMicro = -1
		doc := map[string]any{
			"amountMicro": d.AmountMicro, "currency": d.Currency,
			"priceVersion": d.PriceVersion, "engineVersion": d.EngineVersion,
			"inputsHash": d.InputsHash, "signature": sign(t, priv, d),
		}
		raw, _ := json.Marshal(doc)
		return http.StatusOK, raw
	})
	c := client(t, srv.URL, pub, time.Second, 3)
	if _, err := c.Price(context.Background(), measure(), 0); !errors.Is(err, ErrInvalidDecision) {
		t.Fatalf("err = %v, want ErrInvalidDecision", err)
	}
}

func TestPriceTimeout(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(200 * time.Millisecond)
		}))
	t.Cleanup(srv.Close)
	c := client(t, srv.URL, pub, 20*time.Millisecond, 3)
	if _, err := c.Price(context.Background(), measure(), 0); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v, want ErrUnavailable", err)
	}
}

func TestCircuitBreakerOpens(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	srv, hits := server(t, func(metering.Decision) (int, []byte) {
		return http.StatusInternalServerError, nil
	})
	c := client(t, srv.URL, pub, time.Second, 2)
	for i := 0; i < 2; i++ {
		if _, err := c.Price(context.Background(), measure(), 0); err == nil {
			t.Fatal("expected an error")
		}
	}
	// The breaker is open: no further call reaches the server.
	if _, err := c.Price(context.Background(), measure(), 0); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v", err)
	}
	if hits.Load() != 2 {
		t.Fatalf("hits = %d, want 2 (breaker should short-circuit)", hits.Load())
	}
}
