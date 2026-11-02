package pluginhost

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"cladone/gate-one/internal/usagewal"
	"cladone/gate-one/pkg/usage"
)

var testNow = time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)

func testWAL(t *testing.T) *usagewal.Store {
	t.Helper()
	s, err := usagewal.Open(usagewal.Config{
		Dir:         t.TempDir(),
		BudgetBytes: 1 << 20,
		Types: map[usage.EventType]usagewal.TypeConfig{
			usage.TypeAudit: {ShareBytes: 1 << 20, Fsync: usagewal.FsyncNone},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func testEvent(tenant string, n int) *usage.Event {
	return &usage.Event{
		SchemaVersion: usage.SchemaVersion,
		Type:          usage.TypeAudit,
		Timestamp:     testNow,
		InstanceID:    "gw-1",
		Epoch:         "epoch-1",
		Tenant:        tenant,
		SubjectID:     "v1.abc",
		Route:         "/api/process_stream",
		Method:        "POST",
		Status:        200,
		Units:         1,
		UnitType:      usage.UnitRequest,
		RequestID:     "req-" + tenant,
	}
}

func appendEvent(t *testing.T, w *usagewal.Store, tenant string, n int) {
	t.Helper()
	tk, err := w.Reserve(usage.TypeAudit, 4096)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Append(tk, testEvent(tenant, n)); err != nil {
		t.Fatal(err)
	}
}

// fakePlugin verifies the signed assertion and records events.
type fakePlugin struct {
	t       *testing.T
	secret  []byte
	name    string
	fail    atomic.Bool
	mu      sync.Mutex
	events  []usage.Event
	badAuth atomic.Int64
}

func (p *fakePlugin) srv() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/events", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if err := VerifyAssertion(
			p.secret, r.Header.Get("X-Gate-One-Assertion"),
			p.name, len(body), testNow,
		); err != nil {
			p.badAuth.Add(1)
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		if p.fail.Load() {
			http.Error(w, "nope", http.StatusInternalServerError)
			return
		}
		var batch []envelope
		if err := json.Unmarshal(body, &batch); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		p.mu.Lock()
		for _, e := range batch {
			p.events = append(p.events, e.Event)
		}
		p.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	})
	return httptest.NewServer(mux)
}

func (p *fakePlugin) received() []usage.Event {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]usage.Event(nil), p.events...)
}

func waitFor(t *testing.T, what string, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for %s", what)
}

func TestHostDeliversAndAcks(t *testing.T) {
	w := testWAL(t)
	secret := []byte("0123456789abcdef0123456789abcdef")
	fp := &fakePlugin{t: t, secret: secret, name: "audit"}
	srv := fp.srv()
	defer srv.Close()

	h, err := New(Config{
		WAL: w, Secret: secret,
		Now:    func() time.Time { return testNow },
		Logger: log.New(io.Discard, "", 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	if err := h.Register(Plugin{
		Name: "audit", URL: srv.URL,
		Types:   []usage.EventType{usage.TypeAudit},
		Filters: &Filters{Tenants: []string{"acme"}},
	}); err != nil {
		t.Fatal(err)
	}

	appendEvent(t, w, "acme", 0)
	appendEvent(t, w, "contoso", 1)
	appendEvent(t, w, "acme", 2)

	waitFor(t, "two events", func() bool { return len(fp.received()) == 2 })
	for _, ev := range fp.received() {
		if ev.Tenant != "acme" {
			t.Fatalf("delivered tenant %q, want acme", ev.Tenant)
		}
	}
	tail, _ := w.Tail(usage.TypeAudit)
	waitFor(t, "ack", func() bool {
		cur, err := w.Cursor(usage.TypeAudit, "audit")
		return err == nil && cur == tail
	})
	if fp.badAuth.Load() != 0 {
		t.Fatalf("bad assertions: %d", fp.badAuth.Load())
	}
	if !h.Healthy("audit") {
		t.Fatal("plugin not healthy")
	}
}

func TestHostRetriesWhilePluginFails(t *testing.T) {
	w := testWAL(t)
	secret := []byte("0123456789abcdef0123456789abcdef")
	fp := &fakePlugin{t: t, secret: secret, name: "audit"}
	fp.fail.Store(true)
	srv := fp.srv()
	defer srv.Close()

	h, err := New(Config{
		WAL: w, Secret: secret,
		Now:    func() time.Time { return testNow },
		Logger: log.New(io.Discard, "", 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	if err := h.Register(Plugin{
		Name: "audit", URL: srv.URL,
		Types: []usage.EventType{usage.TypeAudit},
	}); err != nil {
		t.Fatal(err)
	}
	appendEvent(t, w, "acme", 0)
	time.Sleep(200 * time.Millisecond)
	cur, _ := w.Cursor(usage.TypeAudit, "audit")
	if cur != 0 {
		t.Fatalf("cursor advanced while plugin failing: %d", cur)
	}
	fp.fail.Store(false)
	waitFor(t, "delivery after recovery", func() bool {
		return len(fp.received()) == 1
	})
}

func TestHostLicenseGate(t *testing.T) {
	w := testWAL(t)
	h, err := New(Config{
		WAL:    w,
		Secret: []byte("k"),
		Allow:  func(string) bool { return false },
		Logger: log.New(io.Discard, "", 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	err = h.Register(Plugin{
		Name: "audit", URL: "http://127.0.0.1:1",
		Types:          []usage.EventType{usage.TypeAudit},
		LicenseFeature: "audit",
	})
	if err == nil {
		t.Fatal("license-gated plugin accepted")
	}
}

func TestHostDropByLag(t *testing.T) {
	w := testWAL(t)
	secret := []byte("0123456789abcdef0123456789abcdef")
	fp := &fakePlugin{t: t, secret: secret, name: "audit"}
	fp.fail.Store(true)
	srv := fp.srv()
	defer srv.Close()

	h, err := New(Config{
		WAL: w, Secret: secret,
		Now:    func() time.Time { return testNow },
		Logger: log.New(io.Discard, "", 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	if err := h.Register(Plugin{
		Name: "audit", URL: srv.URL,
		Types:       []usage.EventType{usage.TypeAudit},
		MaxLagBytes: 200,
		OnMaxLag:    "drop",
	}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		appendEvent(t, w, "acme", i)
	}
	waitFor(t, "lag within budget", func() bool {
		lag, err := w.Lag(usage.TypeAudit, "audit")
		return err == nil && lag <= 200
	})
	cur, err := w.Cursor(usage.TypeAudit, "audit")
	if err != nil || cur == 0 {
		t.Fatalf("cursor not moved by drop: %d, %v", cur, err)
	}
}
