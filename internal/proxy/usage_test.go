package proxy

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"cladone/gate-one/internal/core"
	"cladone/gate-one/internal/pluginhost"
	"cladone/gate-one/pkg/usage"
)

type usageBatch struct {
	Offset int64       `json:"offset"`
	Event  usage.Event `json:"event"`
}

type usagePlugin struct {
	mu     sync.Mutex
	events []usage.Event
	secret []byte
}

func (p *usagePlugin) server(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/events", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if err := pluginhost.VerifyAssertion(
			p.secret, r.Header.Get("X-Gate-One-Assertion"),
			"audit", len(body), time.Now(),
		); err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		var batch []usageBatch
		if err := json.Unmarshal(body, &batch); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		p.mu.Lock()
		for _, b := range batch {
			p.events = append(p.events, b.Event)
		}
		p.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	})
	return httptest.NewServer(mux)
}

func (p *usagePlugin) received() []usage.Event {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]usage.Event(nil), p.events...)
}

func testUsageRuntime(
	t *testing.T, pluginURL string, share int64,
) *usageRuntime {
	t.Helper()
	cfg := &core.UsageConfig{
		Dir:         t.TempDir(),
		NodeID:      "gw-1",
		BudgetBytes: 1 << 20,
		Types: map[string]core.UsageTypeConfig{
			"error": {ShareBytes: share, Fsync: "none"},
		},
		Plugins: []core.UsagePluginConfig{{
			Name: "audit", URL: pluginURL, Types: []string{"error"},
		}},
		SubjectSecret: []byte("subject-secret"),
		PluginSecret:  []byte("0123456789abcdef0123456789abcdef"),
	}
	u, err := newUsageRuntime(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = u.close() })
	return u
}

func testUsageRoute() *core.Route {
	return &core.Route{
		Host: "app.test", Path: "/*", Frontend: true,
		Auth: &core.AuthPolicy{},
	}
}

func TestUsageRuntimeEmitsErrorEvent(t *testing.T) {
	pl := &usagePlugin{secret: []byte("0123456789abcdef0123456789abcdef")}
	srv := pl.server(t)
	defer srv.Close()
	u := testUsageRuntime(t, srv.URL, 1<<20)

	route := testUsageRoute()
	ctx := &RequestContext{Host: "app.test", Path: "/private", Method: "GET"}
	adm, full := u.admit(route, ctx, nil)
	if full != "" || adm == nil {
		t.Fatalf("admit = %v, %q", adm, full)
	}
	u.emit(adm, route, ctx, nil, http.StatusUnauthorized,
		5*time.Millisecond, 12, "req-1")

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		got := pl.received()
		if len(got) == 1 {
			ev := got[0]
			if ev.Type != usage.TypeError || ev.Status != 401 {
				t.Fatalf("event = %+v", ev)
			}
			if ev.RequestID != "req-1" || ev.InstanceID != "gw-1" {
				t.Fatalf("event ids = %+v", ev)
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("plugin did not receive the error event")
}

func TestUsageRuntimeAdmissionFull(t *testing.T) {
	pl := &usagePlugin{secret: []byte("0123456789abcdef0123456789abcdef")}
	srv := pl.server(t)
	defer srv.Close()
	u := testUsageRuntime(t, srv.URL, usageMaxRecordBytes)

	route := testUsageRoute()
	ctx := &RequestContext{Host: "app.test", Path: "/private", Method: "GET"}
	if _, full := u.admit(route, ctx, nil); full != "" {
		t.Fatalf("first admission = %q", full)
	}
	if _, full := u.admit(route, ctx, nil); full != usage.TypeError {
		t.Fatalf("second admission = %q, want error", full)
	}
}

func TestUsageUnavailableWriter(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Accept", "*/*")
	rec := httptest.NewRecorder()
	writeUsageUnavailable(rec, req, true, usage.TypeError)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("content-type = %q", got)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Fatal("missing Retry-After")
	}
	if body := rec.Body.String(); body == "" ||
		!json.Valid([]byte(body)) {
		t.Fatalf("body = %q", body)
	}

	nav := httptest.NewRequest(http.MethodGet, "/x", nil)
	nav.Header.Set("Sec-Fetch-Dest", "document")
	nav.Header.Set("Accept", "text/html")
	rec2 := httptest.NewRecorder()
	writeUsageUnavailable(rec2, nav, true, usage.TypeError)
	if rec2.Code != http.StatusServiceUnavailable {
		t.Fatalf("navigation status = %d", rec2.Code)
	}
	if got := rec2.Header().Get("Content-Type"); got !=
		"text/html; charset=utf-8" {
		t.Fatalf("navigation content-type = %q", got)
	}
}
