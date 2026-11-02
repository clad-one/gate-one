package proxy

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"cladone/gate-one/internal/core"
)

func usageGatewayConfig(
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
			"nodeId": "gw-test",
			"subjectSecretEnv": "TEST_SUBJECT_SECRET",
			"pluginSecretEnv": "TEST_PLUGIN_SECRET",
			"budgetBytes": %d,
			"types": {"error": {"shareBytes": %d, "fsync": "none"}},
			"plugins": [{
				"name": "audit", "url": %q, "types": ["error"]
			}]
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

func anonymousFetch(host, path string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "http://"+host+path, nil)
	req.Host = host
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Accept", "*/*")
	return req
}

func TestUsageGatewayEmitsErrorEvent(t *testing.T) {
	pl := &usagePlugin{secret: []byte("0123456789abcdef0123456789abcdef")}
	srv := pl.server(t)
	defer srv.Close()
	cfg := usageGatewayConfig(t, t.TempDir(), srv.URL, 1<<20)
	gw, err := New(cfg, WithListenAddr("127.0.0.1:0"))
	if err != nil {
		t.Fatal(err)
	}
	defer gw.Close()

	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, anonymousFetch("app.dev.test", "/private"))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		got := pl.received()
		if len(got) == 1 {
			ev := got[0]
			if ev.Type != "error" || ev.Status != 401 {
				t.Fatalf("event = %+v", ev)
			}
			if ev.Route != "/private" || ev.Method != "GET" {
				t.Fatalf("route/method = %q/%q", ev.Route, ev.Method)
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("gateway did not emit the error event")
}

func TestUsageGatewayFullShareReturns503(t *testing.T) {
	pl := &usagePlugin{
		secret: []byte("0123456789abcdef0123456789abcdef"),
		name:   "audit",
	}
	pl.fail.Store(true)
	srv := pl.server(t)
	defer srv.Close()
	cfg := usageGatewayConfig(t, t.TempDir(), srv.URL, usageMaxRecordBytes)
	gw, err := New(cfg, WithListenAddr("127.0.0.1:0"))
	if err != nil {
		t.Fatal(err)
	}
	defer gw.Close()

	rec1 := httptest.NewRecorder()
	gw.ServeHTTP(rec1, anonymousFetch("app.dev.test", "/first"))
	if rec1.Code != http.StatusUnauthorized {
		t.Fatalf("first status = %d, want 401", rec1.Code)
	}
	rec2 := httptest.NewRecorder()
	gw.ServeHTTP(rec2, anonymousFetch("app.dev.test", "/second"))
	if rec2.Code != http.StatusServiceUnavailable {
		t.Fatalf("second status = %d, want 503", rec2.Code)
	}
	if rec2.Header().Get("Retry-After") == "" {
		t.Fatal("missing Retry-After")
	}
	if !strings.Contains(rec2.Body.String(), "usage_unavailable") {
		t.Fatalf("body = %q", rec2.Body.String())
	}
	// Health endpoints bypass the usage admission.
	health := httptest.NewRecorder()
	gw.ServeHTTP(health, anonymousFetch("app.dev.test", "/healthz"))
	if health.Code != http.StatusOK {
		t.Fatalf("healthz = %d, want 200", health.Code)
	}
}
