package proxy

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"cladone/gate-one/internal/core"
	"cladone/gate-one/pkg/usage"
)

func billingConfig(
	t *testing.T, walDir, pluginURL, backendURL, captureJSON string,
) *core.Config {
	t.Helper()
	t.Setenv("TEST_SUBJECT_SECRET", "subject-secret")
	t.Setenv("TEST_PLUGIN_SECRET", "0123456789abcdef0123456789abcdef")
	capture := ""
	if captureJSON != "" {
		capture = `"capture": ` + captureJSON + `,`
	}
	raw := fmt.Sprintf(`{
		"authProvider": {
			"type": "dev",
			"loginBaseUrl": "http://login.dev.test:3000",
			"cookieDomain": "dev.test"
		},
		"usage": {
			"dir": %q,
			"nodeId": "gw-bill",
			"subjectSecretEnv": "TEST_SUBJECT_SECRET",
			"pluginSecretEnv": "TEST_PLUGIN_SECRET",
			"budgetBytes": 1048576,
			"types": {"billing": {"shareBytes": 1048576, "fsync": "none"}},
			%s
			"plugins": [{"name": "audit", "url": %q, "types": ["billing"]}]
		},
		"routes": [
			{"host": "app.dev.test", "path": "/*", "backend": %q},
			{"host": "other.dev.test", "path": "/*", "backend": %q}
		]
	}`, walDir, capture, pluginURL, backendURL, backendURL)
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

func billingBackend(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Gate-One-Units", "1240")
			w.Header().Set("X-Gate-One-Unit", "token")
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, "ok")
		}))
	t.Cleanup(srv.Close)
	return srv
}

func waitEvents(t *testing.T, pl *usagePlugin, n int) []usage.Event {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		got := pl.received()
		if len(got) >= n {
			return got
		}
		time.Sleep(20 * time.Millisecond)
	}
	return pl.received()
}

// TestBillingFromBackendHeader: the backend's units/unit-type reach the
// billing event and the internal headers never leak to the client.
func TestBillingFromBackendHeader(t *testing.T) {
	pl := &usagePlugin{secret: []byte("0123456789abcdef0123456789abcdef")}
	pluginSrv := pl.server(t)
	defer pluginSrv.Close()
	backend := billingBackend(t)

	gw, err := New(billingConfig(t, t.TempDir(), pluginSrv.URL, backend.URL, ""))
	if err != nil {
		t.Fatal(err)
	}
	defer gw.Close()

	req := httptest.NewRequest(http.MethodGet, "http://app.dev.test/bill", nil)
	req.Host = "app.dev.test"
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if got := rec.Header().Get("X-Gate-One-Units"); got != "" {
		t.Fatalf("billing header leaked to client: %q", got)
	}

	got := waitEvents(t, pl, 1)
	if len(got) != 1 {
		t.Fatalf("events = %+v", got)
	}
	ev := got[0]
	if ev.Type != usage.TypeBilling || ev.Units != 1240 ||
		ev.UnitType != usage.UnitToken {
		t.Fatalf("billing event = %+v", ev)
	}
	if ev.Host != "app.dev.test" {
		t.Fatalf("host = %q", ev.Host)
	}
}

// TestBillingCaptureAttrs: allow-listed query/body fields are copied,
// sensitive ones skipped, and capture is scoped to its host.
func TestBillingCaptureAttrs(t *testing.T) {
	pl := &usagePlugin{secret: []byte("0123456789abcdef0123456789abcdef")}
	pluginSrv := pl.server(t)
	defer pluginSrv.Close()
	backend := billingBackend(t)

	capture := `[{
		"hosts": ["app.dev.test"],
		"routes": ["/bill"],
		"methods": ["POST"],
		"types": ["billing"],
		"query": ["coupes", "token"],
		"body": {"paths": ["$.coupes", "$.model", "$.password"]},
		"maxAttrsBytes": 1024
	}]`
	gw, err := New(billingConfig(t, t.TempDir(), pluginSrv.URL, backend.URL, capture))
	if err != nil {
		t.Fatal(err)
	}
	defer gw.Close()

	send := func(host string) {
		req := httptest.NewRequest(http.MethodPost,
			"http://"+host+"/bill?coupes=true&token=sekret",
			strings.NewReader(`{"coupes":true,"model":"gpt-4","password":"hunter2"}`))
		req.Host = host
		req.Header.Set("Content-Type", "application/json")
		gw.ServeHTTP(httptest.NewRecorder(), req)
	}
	send("app.dev.test")
	send("other.dev.test")

	got := waitEvents(t, pl, 2)
	byHost := map[string]usage.Event{}
	for _, ev := range got {
		byHost[ev.Host] = ev
	}
	app := byHost["app.dev.test"]
	if app.Attrs["q.coupes"] != "true" {
		t.Fatalf("app attrs = %+v", app.Attrs)
	}
	if app.Attrs["b.coupes"] != "true" || app.Attrs["b.model"] != "gpt-4" {
		t.Fatalf("body attrs = %+v", app.Attrs)
	}
	for k := range app.Attrs {
		if strings.Contains(k, "token") || strings.Contains(k, "password") {
			t.Fatalf("sensitive attr kept: %q", k)
		}
	}
	// The capture rule is scoped to app.dev.test: no attrs on other.
	if len(byHost["other.dev.test"].Attrs) != 0 {
		t.Fatalf("capture leaked to other host: %+v",
			byHost["other.dev.test"].Attrs)
	}
}

func TestCapAttrs(t *testing.T) {
	in := map[string]string{}
	for i := 0; i < 20; i++ {
		in[fmt.Sprintf("k%02d", i)] = strings.Repeat("x", 300)
	}
	out, truncated := capAttrs(in, 512)
	if !truncated {
		t.Fatal("expected truncated")
	}
	if len(out) > maxAttrsPerEvent {
		t.Fatalf("kept %d keys, max %d", len(out), maxAttrsPerEvent)
	}
	total := 0
	for k, v := range out {
		if len(k) > maxAttrKeyBytes || len(v) > maxAttrValueBytes {
			t.Fatalf("oversized attr %q=%q", k, v)
		}
		total += len(k) + len(v)
	}
	if total > 512 {
		t.Fatalf("total %d > 512", total)
	}
}

func TestIsSensitiveName(t *testing.T) {
	for _, n := range []string{"token", "access_token", "password", "API_KEY", "Authorization", "cookie", "session_id"} {
		if !isSensitiveName(n) {
			t.Errorf("%q should be sensitive", n)
		}
	}
	for _, n := range []string{"coupes", "model", "lang", "q"} {
		if isSensitiveName(n) {
			t.Errorf("%q should not be sensitive", n)
		}
	}
}
