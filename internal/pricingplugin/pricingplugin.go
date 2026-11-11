// Package pricingplugin calls a signed, out-of-process pricing service
// for the metrics whose price cannot be expressed by the declarative
// table (per-request quotes, negotiated rates, cost + live FX).
//
// The plugin never sees a balance or a settlement: it is a pure function
// from a measure to a decision. Its answer is signed, so the gateway can
// verify what it did not compute. Any failure (timeout, bad signature,
// negative amount, circuit open) falls back to a declarative tariff.
package pricingplugin

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"cladone/gate-one/internal/metering"
)

var (
	// ErrUnavailable means the plugin could not answer (network, 5xx).
	ErrUnavailable = errors.New("pricingplugin: unavailable")
	// ErrBadSignature means the decision was not signed by the plugin.
	ErrBadSignature = errors.New("pricingplugin: bad signature")
	// ErrInvalidDecision means the answer is structurally wrong.
	ErrInvalidDecision = errors.New("pricingplugin: invalid decision")
)

// Config targets one pricing plugin.
type Config struct {
	Name    string
	URL     string
	Public  ed25519.PublicKey
	Timeout time.Duration
	// Breaker: open after Failures consecutive errors, for Cooldown.
	Failures int
	Cooldown time.Duration
	Client   *http.Client
}

// Client calls one plugin, with a circuit breaker.
type Client struct {
	cfg Config
	mu  sync.Mutex
	// failures and openedAt implement the breaker.
	failures int
	openedAt time.Time
	now      func() time.Time
}

// New validates a config and builds a client.
func New(cfg Config) (*Client, error) {
	if strings.TrimSpace(cfg.URL) == "" {
		return nil, fmt.Errorf("pricingplugin: %s: url is required", cfg.Name)
	}
	if len(cfg.Public) != ed25519.PublicKeySize {
		return nil, fmt.Errorf(
			"pricingplugin: %s: public key is required", cfg.Name)
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 50 * time.Millisecond
	}
	if cfg.Failures <= 0 {
		cfg.Failures = 3
	}
	if cfg.Cooldown <= 0 {
		cfg.Cooldown = 30 * time.Second
	}
	if cfg.Client == nil {
		cfg.Client = &http.Client{Timeout: cfg.Timeout}
	}
	return &Client{cfg: cfg, now: time.Now}, nil
}

// Name is the plugin name (logs, errors).
func (c *Client) Name() string { return c.cfg.Name }

// Price asks the plugin for a decision.
func (c *Client) Price(
	ctx context.Context, m metering.Measure, scale int,
) (metering.Decision, error) {
	if c.open() {
		return metering.Decision{}, fmt.Errorf(
			"%w: %s: circuit open", ErrUnavailable, c.cfg.Name)
	}
	body, err := json.Marshal(priceRequest{
		Tenant: m.Tenant, Metric: m.Metric, Quantity: m.Quantity,
		Scale: scale, Dimensions: m.Dimensions,
		At: m.At, RequestID: m.RequestID,
	})
	if err != nil {
		return metering.Decision{}, err
	}
	reqCtx, cancel := context.WithTimeout(ctx, c.cfg.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(
		reqCtx, http.MethodPost,
		strings.TrimRight(c.cfg.URL, "/")+"/price",
		bytes.NewReader(body))
	if err != nil {
		return metering.Decision{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.cfg.Client.Do(req)
	if err != nil {
		c.fail()
		return metering.Decision{}, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		c.fail()
		return metering.Decision{}, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	if resp.StatusCode != http.StatusOK {
		c.fail()
		return metering.Decision{}, fmt.Errorf(
			"%w: %s: status %d", ErrUnavailable, c.cfg.Name, resp.StatusCode)
	}
	decision, err := VerifyDecision(raw, c.cfg.Public)
	if err != nil {
		c.fail()
		return metering.Decision{}, err
	}
	c.succeed()
	return decision, nil
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

// decisionDocument is the plugin's answer. Signature covers
// DecisionPayload.
type decisionDocument struct {
	AmountMicro   int64  `json:"amountMicro"`
	Currency      string `json:"currency"`
	PriceVersion  string `json:"priceVersion"`
	EngineVersion string `json:"engineVersion"`
	InputsHash    string `json:"inputsHash"`
	Signature     string `json:"signature"`
}

// DecisionPayload is the signed line format:
//
//	v1
//	<amountMicro>
//	<currency>
//	<priceVersion>
//	<engineVersion>
//	<inputsHash>
func DecisionPayload(d metering.Decision) []byte {
	lines := []string{
		"v1",
		strconv.FormatInt(d.AmountMicro, 10),
		d.Currency,
		d.PriceVersion,
		d.EngineVersion,
		d.InputsHash,
	}
	return []byte(strings.Join(lines, "\n") + "\n")
}

// VerifyDecision parses and verifies a signed decision.
func VerifyDecision(
	raw []byte, pub ed25519.PublicKey,
) (metering.Decision, error) {
	var doc decisionDocument
	if err := json.Unmarshal(raw, &doc); err != nil {
		return metering.Decision{}, fmt.Errorf("%w: %v", ErrInvalidDecision, err)
	}
	d := metering.Decision{
		AmountMicro:   doc.AmountMicro,
		Currency:      doc.Currency,
		PriceVersion:  doc.PriceVersion,
		EngineVersion: doc.EngineVersion,
		InputsHash:    doc.InputsHash,
	}
	if d.AmountMicro < 0 {
		return metering.Decision{}, fmt.Errorf(
			"%w: negative amount", ErrInvalidDecision)
	}
	if len(strings.TrimSpace(d.Currency)) != 3 ||
		d.PriceVersion == "" || d.EngineVersion == "" {
		return metering.Decision{}, fmt.Errorf(
			"%w: incomplete decision", ErrInvalidDecision)
	}
	sig, err := base64.RawURLEncoding.DecodeString(
		strings.TrimSpace(doc.Signature))
	if err != nil || len(sig) != ed25519.SignatureSize {
		return metering.Decision{}, ErrBadSignature
	}
	if !ed25519.Verify(pub, DecisionPayload(d), sig) {
		return metering.Decision{}, ErrBadSignature
	}
	return d, nil
}

func (c *Client) open() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.openedAt.IsZero() {
		return false
	}
	if c.now().Sub(c.openedAt) >= c.cfg.Cooldown {
		c.openedAt = time.Time{}
		c.failures = 0
		return false
	}
	return true
}

func (c *Client) fail() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.failures++
	if c.failures >= c.cfg.Failures && c.openedAt.IsZero() {
		c.openedAt = c.now()
	}
}

func (c *Client) succeed() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.failures = 0
	c.openedAt = time.Time{}
}
