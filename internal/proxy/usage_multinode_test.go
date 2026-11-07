package proxy

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"cladone/gate-one/internal/core"
	"cladone/gate-one/pkg/usage"
)

// usageGatewayNodeConfig is usageGatewayConfig for ONE node of a
// multi-replica deployment: its own WAL dir and nodeId, plus an
// ordinary route and one that opts out of the bus ("usage": false).
func usageGatewayNodeConfig(
	t *testing.T, walDir, nodeID, pluginURL string, share int64,
) *core.Config {
	t.Helper()
	t.Setenv("TEST_SUBJECT_SECRET", "subject-secret")
	t.Setenv("TEST_PLUGIN_SECRET", "0123456789abcdef0123456789abcdef")
	raw := fmt.Sprintf(`{
		"authProvider": {
			"type": "dev",
			"loginBaseUrl": "http://login.dev.test:3000",
			"cookieDomain": "dev.test"
		},
		"usage": {
			"dir": %q,
			"nodeId": %q,
			"subjectSecretEnv": "TEST_SUBJECT_SECRET",
			"pluginSecretEnv": "TEST_PLUGIN_SECRET",
			"budgetBytes": %d,
			"types": {"error": {"shareBytes": %d, "fsync": "none"}},
			"plugins": [{
				"name": "audit", "url": %q, "types": ["error"]
			}]
		},
		"routes": [
			{"host": "app.dev.test", "path": "/*", "frontend": true,
			 "backend": "http://127.0.0.1:1", "auth": {}},
			{"host": "quiet.dev.test", "path": "/*", "frontend": true,
			 "backend": "http://127.0.0.1:1", "auth": {}, "usage": false}
		]
	}`, walDir, nodeID, share, share, pluginURL)
	path := filepath.Join(t.TempDir(), "routes.json")
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := core.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func newUsageNodeGateway(
	t *testing.T, nodeID, pluginURL string, share int64,
) *Gateway {
	t.Helper()
	cfg := usageGatewayNodeConfig(t, t.TempDir(), nodeID, pluginURL, share)
	gw, err := New(cfg, WithListenAddr("127.0.0.1:0"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = gw.Close() })
	return gw
}

func serveNode(gw *Gateway, host, path string) int {
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, anonymousFetch(host, path))
	return rec.Code
}

// TestUsageMultiNodeDeliversBothAndOptOut proves that two replicas with
// their OWN WAL dirs and nodeIds both deliver their events to a shared
// plugin, each tagged with its own instanceId, while a route that opts
// out ("usage": false) produces no event on either node.
func TestUsageMultiNodeDeliversBothAndOptOut(t *testing.T) {
	pl := &usagePlugin{secret: []byte("0123456789abcdef0123456789abcdef")}
	srv := pl.server(t)
	defer srv.Close()

	gw1 := newUsageNodeGateway(t, "gw-1", srv.URL, 1<<20)
	gw2 := newUsageNodeGateway(t, "gw-2", srv.URL, 1<<20)

	if code := serveNode(gw1, "app.dev.test", "/node1"); code != http.StatusUnauthorized {
		t.Fatalf("gw1 app status = %d, want 401", code)
	}
	if code := serveNode(gw2, "app.dev.test", "/node2"); code != http.StatusUnauthorized {
		t.Fatalf("gw2 app status = %d, want 401", code)
	}
	// Opt-out routes are served normally but must not reach the bus.
	if code := serveNode(gw1, "quiet.dev.test", "/quiet1"); code != http.StatusUnauthorized {
		t.Fatalf("gw1 quiet status = %d, want 401", code)
	}
	if code := serveNode(gw2, "quiet.dev.test", "/quiet2"); code != http.StatusUnauthorized {
		t.Fatalf("gw2 quiet status = %d, want 401", code)
	}

	var got []usage.Event
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		got = pl.received()
		if len(got) >= 2 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	if len(got) != 2 {
		t.Fatalf("plugin received %d events, want exactly 2 (opt-out leaked?): %+v",
			len(got), got)
	}
	nodes := map[string]string{} // instanceId -> route
	for _, ev := range got {
		nodes[ev.InstanceID] = ev.Route
		if ev.Route == "/quiet1" || ev.Route == "/quiet2" {
			t.Fatalf("opt-out route emitted an event: %+v", ev)
		}
		if ev.Host != "app.dev.test" {
			t.Fatalf("host = %q, want app.dev.test", ev.Host)
		}
	}
	if nodes["gw-1"] != "/node1" || nodes["gw-2"] != "/node2" {
		t.Fatalf("per-node delivery wrong: %+v", nodes)
	}
}

// TestUsageMultiNodeFullShareIsolated proves the WAL is per node: a node
// whose durable share is full answers 503, while the other node keeps
// serving — a saturated bus on one replica never spills onto the other.
func TestUsageMultiNodeFullShareIsolated(t *testing.T) {
	pl := &usagePlugin{secret: []byte("0123456789abcdef0123456789abcdef")}
	pl.fail.Store(true) // never acknowledge: the WAL stays full
	srv := pl.server(t)
	defer srv.Close()

	// gw-1: room for a single record, so the second request is refused.
	gw1 := newUsageNodeGateway(t, "gw-1", srv.URL, usageMaxRecordBytes)
	// gw-2: a large share, unaffected by gw-1's saturation.
	gw2 := newUsageNodeGateway(t, "gw-2", srv.URL, 1<<20)

	if code := serveNode(gw1, "app.dev.test", "/first"); code != http.StatusUnauthorized {
		t.Fatalf("gw1 first status = %d, want 401", code)
	}
	if code := serveNode(gw1, "app.dev.test", "/second"); code != http.StatusServiceUnavailable {
		t.Fatalf("gw1 second status = %d, want 503 (share full)", code)
	}
	if code := serveNode(gw2, "app.dev.test", "/other"); code != http.StatusUnauthorized {
		t.Fatalf("gw2 status = %d, want 401 (isolated from gw-1)", code)
	}
}
