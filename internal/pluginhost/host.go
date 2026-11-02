// Package pluginhost delivers usage events from the local WAL to
// out-of-process extension plugins over HTTP/JSON. The host is a
// consumer: it never mutates a request, never decides authentication,
// and a slow or unavailable plugin only fills the WAL (the proxy then
// applies the 503/backpressure policy).
package pluginhost

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"path"
	"strings"
	"sync"
	"time"

	"cladone/gate-one/internal/usagewal"
	"cladone/gate-one/pkg/usage"
)

// Plugin is an out-of-process event consumer.
type Plugin struct {
	Name           string
	URL            string
	Types          []usage.EventType
	Filters        *Filters
	MaxLagBytes    int64
	OnMaxLag       string // "block" (default) or "drop"
	LicenseFeature string
	ManifestName   string
	ManifestVer    string
}

// Filters narrows the events delivered to a plugin. Empty = all.
type Filters struct {
	Routes        []string
	Tenants       []string
	Methods       []string
	StatusClasses []string
}

// Config configures the host.
type Config struct {
	WAL    *usagewal.Store
	Secret []byte // HMAC key for the signed assertion (required)
	// Allow gates licenseFeature; nil allows everything.
	Allow  func(feature string) bool
	Client *http.Client
	Now    func() time.Time
	Logger *log.Logger
}

// Host delivers events to registered plugins.
type Host struct {
	cfg     Config
	mu      sync.Mutex
	stop    chan struct{}
	wg      sync.WaitGroup
	plugins map[string]*Plugin
	healthy map[string]bool
	closed  bool
}

// New creates a host. Register starts delivery.
func New(cfg Config) (*Host, error) {
	if cfg.WAL == nil {
		return nil, fmt.Errorf("pluginhost: wal is required")
	}
	if len(cfg.Secret) == 0 {
		return nil, fmt.Errorf("pluginhost: assertion secret is required")
	}
	if cfg.Client == nil {
		cfg.Client = &http.Client{Timeout: 5 * time.Second}
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Logger == nil {
		cfg.Logger = log.Default()
	}
	return &Host{
		cfg:     cfg,
		stop:    make(chan struct{}),
		plugins: map[string]*Plugin{},
		healthy: map[string]bool{},
	}, nil
}

// Register validates a plugin and starts one delivery loop per
// subscribed event type.
func (h *Host) Register(p Plugin) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return fmt.Errorf("pluginhost: closed")
	}
	if strings.TrimSpace(p.Name) == "" {
		return fmt.Errorf("pluginhost: plugin name is required")
	}
	if strings.TrimSpace(p.URL) == "" {
		return fmt.Errorf("pluginhost: %s: url is required", p.Name)
	}
	if len(p.Types) == 0 {
		return fmt.Errorf("pluginhost: %s: at least one event type", p.Name)
	}
	if _, ok := h.plugins[p.Name]; ok {
		return fmt.Errorf("pluginhost: duplicate plugin %q", p.Name)
	}
	if p.LicenseFeature != "" && h.cfg.Allow != nil &&
		!h.cfg.Allow(p.LicenseFeature) {
		return fmt.Errorf("pluginhost: %s requires feature %q",
			p.Name, p.LicenseFeature)
	}
	switch p.OnMaxLag {
	case "", "block", "drop":
	default:
		return fmt.Errorf("pluginhost: %s: onMaxLag must be block or drop",
			p.Name)
	}
	for _, typ := range p.Types {
		if !usage.ValidEventType(typ) {
			return fmt.Errorf("pluginhost: %s: unknown event type %q",
				p.Name, typ)
		}
		if _, err := h.cfg.WAL.Register(typ, p.Name); err != nil {
			return fmt.Errorf("pluginhost: %s/%s: %w", p.Name, typ, err)
		}
	}
	cp := p
	h.plugins[p.Name] = &cp
	h.healthy[p.Name] = true
	for _, typ := range p.Types {
		h.wg.Add(1)
		go h.deliver(p.Name, typ)
	}
	return nil
}

// Close stops delivery. The WAL is owned by the caller and is not
// closed here.
func (h *Host) Close() error {
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return nil
	}
	h.closed = true
	close(h.stop)
	h.mu.Unlock()
	h.wg.Wait()
	return nil
}

// Healthy reports the last health probe result.
func (h *Host) Healthy(name string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.healthy[name]
}

func (h *Host) deliver(name string, typ usage.EventType) {
	defer h.wg.Done()
	backoff := 50 * time.Millisecond
	for {
		select {
		case <-h.stop:
			return
		default:
		}
		h.mu.Lock()
		p := h.plugins[name]
		h.mu.Unlock()
		if p == nil {
			return
		}

		// Backpressure policy: a subscriber beyond its lag budget either
		// blocks (the proxy's 503 applies) or is dropped to the lag limit.
		if p.MaxLagBytes > 0 {
			if lag, err := h.cfg.WAL.Lag(typ, name); err == nil &&
				lag > p.MaxLagBytes && p.OnMaxLag == "drop" {
				if _, err := h.cfg.WAL.DropSubscriber(
					typ, name, p.MaxLagBytes,
				); err != nil {
					h.cfg.Logger.Printf(
						"pluginhost: %s/%s: drop: %v", name, typ, err)
				}
			}
		}

		recs, err := h.cfg.WAL.Read(typ, name, 1<<20)
		if err != nil {
			h.cfg.Logger.Printf("pluginhost: %s/%s: read: %v",
				name, typ, err)
			time.Sleep(backoff)
			continue
		}
		if len(recs) == 0 {
			time.Sleep(backoff)
			if backoff < 300*time.Millisecond {
				backoff *= 2
			}
			continue
		}
		batch := make([]usagewal.Record, 0, len(recs))
		for _, r := range recs {
			if p.Filters.matches(r.Event) {
				batch = append(batch, r)
			}
		}
		if len(batch) > 0 {
			if err := h.post(p, batch); err != nil {
				h.setHealthy(name, false)
				h.cfg.Logger.Printf("pluginhost: %s/%s: post: %v",
					name, typ, err)
				time.Sleep(backoff)
				if backoff < 2*time.Second {
					backoff *= 2
				}
				continue
			}
			h.setHealthy(name, true)
		}
		// The batch (including filtered-out records) is acknowledged:
		// the plugin has processed every record it asked for.
		if err := h.cfg.WAL.Ack(typ, name, recs[len(recs)-1].Next); err != nil {
			h.cfg.Logger.Printf("pluginhost: %s/%s: ack: %v",
				name, typ, err)
			time.Sleep(backoff)
			continue
		}
		backoff = 50 * time.Millisecond
	}
}

func (h *Host) setHealthy(name string, ok bool) {
	h.mu.Lock()
	h.healthy[name] = ok
	h.mu.Unlock()
}

type envelope struct {
	Offset int64       `json:"offset"`
	Event  usage.Event `json:"event"`
}

func (h *Host) post(p *Plugin, batch []usagewal.Record) error {
	body := make([]envelope, len(batch))
	for i, r := range batch {
		body[i] = envelope{Offset: r.Offset, Event: r.Event}
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(
		ctx, http.MethodPost, strings.TrimRight(p.URL, "/")+"/events",
		bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Gate-One-Assertion", h.assertion(p, len(raw)))
	resp, err := h.cfg.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	return nil
}

// assertion signs the plugin audience, an expiry and a digest of the
// body. The plugin rejects anything not signed by the host.
func (h *Host) assertion(p *Plugin, bodyLen int) string {
	exp := h.cfg.Now().Add(30 * time.Second).Unix()
	payload := fmt.Sprintf("%s\n%d\n%d", p.Name, exp, bodyLen)
	mac := hmac.New(sha256.New, h.cfg.Secret)
	mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." +
		base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// VerifyAssertion is the plugin-side helper used by the sample/tests.
func VerifyAssertion(secret []byte, header, pluginName string, bodyLen int, now time.Time) error {
	parts := strings.Split(header, ".")
	if len(parts) != 2 {
		return fmt.Errorf("pluginhost: malformed assertion")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return fmt.Errorf("pluginhost: assertion payload: %w", err)
	}
	want, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return fmt.Errorf("pluginhost: assertion mac: %w", err)
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write(payload)
	if !hmac.Equal(want, mac.Sum(nil)) {
		return fmt.Errorf("pluginhost: bad assertion")
	}
	fields := strings.Split(string(payload), "\n")
	if len(fields) != 3 || fields[0] != pluginName {
		return fmt.Errorf("pluginhost: assertion audience")
	}
	var exp int64
	if _, err := fmt.Sscanf(fields[1], "%d", &exp); err != nil {
		return fmt.Errorf("pluginhost: assertion expiry")
	}
	if now.Unix() > exp {
		return fmt.Errorf("pluginhost: assertion expired")
	}
	var size int
	if _, err := fmt.Sscanf(fields[2], "%d", &size); err != nil {
		return fmt.Errorf("pluginhost: assertion size")
	}
	if size != bodyLen {
		return fmt.Errorf("pluginhost: assertion body size")
	}
	return nil
}

func (f *Filters) matches(ev usage.Event) bool {
	if f == nil {
		return true
	}
	if len(f.Tenants) > 0 && !matchAny(f.Tenants, ev.Tenant) {
		return false
	}
	if len(f.Methods) > 0 &&
		!matchAnyFold(f.Methods, ev.Method) {
		return false
	}
	if len(f.Routes) > 0 && !matchRoute(f.Routes, ev.Route) {
		return false
	}
	if len(f.StatusClasses) > 0 &&
		!matchStatus(f.StatusClasses, ev.Status) {
		return false
	}
	return true
}

func matchAny(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

func matchAnyFold(list []string, v string) bool {
	for _, s := range list {
		if strings.EqualFold(s, v) {
			return true
		}
	}
	return false
}

func matchRoute(patterns []string, route string) bool {
	for _, p := range patterns {
		if p == route {
			return true
		}
		if ok, _ := path.Match(p, route); ok {
			return true
		}
		if strings.HasSuffix(p, "*") &&
			strings.HasPrefix(route, strings.TrimSuffix(p, "*")) {
			return true
		}
	}
	return false
}

func matchStatus(classes []string, status int) bool {
	for _, c := range classes {
		if len(c) != 3 || c[1:] != "xx" {
			continue
		}
		if c[0] == byte('0'+status/100) {
			return true
		}
	}
	return false
}
