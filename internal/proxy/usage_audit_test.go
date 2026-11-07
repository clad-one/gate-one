package proxy

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"cladone/gate-one/internal/core"
	"cladone/gate-one/pkg/usage"
)

func usageAuditConfig(
	t *testing.T, walDir, pluginURL string, share int64,
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
			"nodeId": "gw-audit",
			"subjectSecretEnv": "TEST_SUBJECT_SECRET",
			"pluginSecretEnv": "TEST_PLUGIN_SECRET",
			"budgetBytes": %d,
			"types": {"audit": {"shareBytes": %d, "fsync": "none"}},
			"plugins": [{"name": "audit", "url": %q, "types": ["audit"]}]
		},
		"routes": [{
			"host": "app.dev.test", "path": "/*", "frontend": true,
			"backend": "http://127.0.0.1:1", "auth": {}
		}]
	}`, walDir, share, share, pluginURL)
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

// TestUsageAuditLifecycle: loading a plugin records audit/plugin_load,
// and an explicit reload audit event is delivered with its action,
// status and detail.
func TestUsageAuditLifecycle(t *testing.T) {
	pl := &usagePlugin{secret: []byte("0123456789abcdef0123456789abcdef")}
	srv := pl.server(t)
	defer srv.Close()

	gw, err := New(usageAuditConfig(t, t.TempDir(), srv.URL, 1<<20))
	if err != nil {
		t.Fatal(err)
	}
	defer gw.Close()

	gw.auditEvent("reload", "config reloaded", http.StatusOK)

	var got []usage.Event
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		got = pl.received()
		if len(got) >= 2 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	byAction := map[string]usage.Event{}
	for _, ev := range got {
		if ev.Type != usage.TypeAudit {
			t.Fatalf("type = %q, want audit", ev.Type)
		}
		byAction[ev.Action] = ev
	}
	if ev, ok := byAction["plugin_load"]; !ok || ev.Detail != "audit" {
		t.Fatalf("plugin_load = %+v (all: %+v)", ev, got)
	}
	if ev, ok := byAction["reload"]; !ok || ev.Status != http.StatusOK ||
		ev.Detail != "config reloaded" {
		t.Fatalf("reload = %+v (all: %+v)", ev, got)
	}
}

// TestUsageAuditBestEffortOnFullWAL: a full audit share must never block
// or fail the operation it records — the event is dropped instead.
func TestUsageAuditBestEffortOnFullWAL(t *testing.T) {
	pl := &usagePlugin{secret: []byte("0123456789abcdef0123456789abcdef")}
	pl.fail.Store(true) // never acknowledge, so the WAL stays full
	srv := pl.server(t)
	defer srv.Close()

	// A single-record share: the startup plugin_load fills it.
	gw, err := New(usageAuditConfig(t, t.TempDir(), srv.URL, usageMaxRecordBytes))
	if err != nil {
		t.Fatal(err)
	}
	defer gw.Close()

	done := make(chan struct{})
	go func() {
		gw.auditEvent("reload", "", http.StatusOK)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("auditEvent blocked on a full WAL")
	}
}
