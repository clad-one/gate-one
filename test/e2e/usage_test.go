//go:build e2e

package e2e

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"cladone/gate-one/internal/pluginhost"
	"cladone/gate-one/pkg/usage"
)

// e2eUsagePlugin is a minimal usage-event consumer: it verifies the
// host's signed assertion and records every event it receives.
type e2eUsagePlugin struct {
	mu     sync.Mutex
	events []usage.Event
}

func (p *e2eUsagePlugin) server(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/events", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if err := pluginhost.VerifyAssertion(
			[]byte(e2ePluginSecret), r.Header.Get("X-Gate-One-Assertion"),
			e2ePluginName, len(body), time.Now(),
		); err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		var batch []struct {
			Offset int64       `json:"offset"`
			Event  usage.Event `json:"event"`
		}
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

func (p *e2eUsagePlugin) received() []usage.Event {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]usage.Event(nil), p.events...)
}

// TestE2E_Usage_MultiNode proves the usage bus is per replica through
// the full stack: two Gate One instances, each with its own WAL dir and
// nodeId, deliver their events to one plugin tagged with their own
// instanceId, while a route that opts out ("usage": false) stays silent.
func TestE2E_Usage_MultiNode(t *testing.T) {
	pl := &e2eUsagePlugin{}
	srv := pl.server(t)
	defer srv.Close()

	s := newStack(t, stackOptions{usagePluginURL: srv.URL})

	// app.mycompany.test is served by gw-1, app2.mycompany.test by gw-2.
	get := func(host, path string) {
		t.Helper()
		resp, err := s.noRedirect.Get("https://" + host + path)
		if err != nil {
			t.Fatalf("GET %s%s: %v", host, path, err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	get("app.mycompany.test", "/from-node1")
	get("app2.mycompany.test", "/from-node2")
	// The opt-out route is served by gw-1 but must not reach the bus.
	get("quiet.mycompany.test", "/quiet")

	var got []usage.Event
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		got = pl.received()
		nodes := map[string]bool{}
		for _, ev := range got {
			nodes[ev.InstanceID] = true
		}
		if nodes["gw-1"] && nodes["gw-2"] {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	byNode := map[string][]string{}
	for _, ev := range got {
		byNode[ev.InstanceID] = append(byNode[ev.InstanceID], ev.Route)
		if ev.Route == "/quiet" {
			t.Fatalf("opt-out route emitted an event: %+v", ev)
		}
	}
	if len(byNode["gw-1"]) != 1 || byNode["gw-1"][0] != "/from-node1" {
		t.Fatalf("gw-1 events = %v, want [/from-node1]", byNode["gw-1"])
	}
	if len(byNode["gw-2"]) != 1 || byNode["gw-2"][0] != "/from-node2" {
		t.Fatalf("gw-2 events = %v, want [/from-node2]", byNode["gw-2"])
	}
}
