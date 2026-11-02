package proxy

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"cladone/gate-one/internal/authn"
	"cladone/gate-one/internal/core"
	"cladone/gate-one/internal/pluginhost"
	"cladone/gate-one/pkg/pluginmanifest"
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
	name   string
	fail   atomic.Bool
}

func (p *usagePlugin) server(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/events", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		name := p.name
		if name == "" {
			name = "audit"
		}
		if err := pluginhost.VerifyAssertion(
			p.secret, r.Header.Get("X-Gate-One-Assertion"),
			name, len(body), time.Now(),
		); err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		if p.fail.Load() {
			http.Error(w, "nope", http.StatusInternalServerError)
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
		BudgetBytes: 2 * share,
		Types: map[string]core.UsageTypeConfig{
			"error": {ShareBytes: share, Fsync: "none"},
			"auth":  {ShareBytes: share, Fsync: "none"},
		},
		Plugins: []core.UsagePluginConfig{{
			Name: "audit", URL: pluginURL, Types: []string{"error", "auth"},
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

func TestUsageRuntimeAuthEvent(t *testing.T) {
	pl := &usagePlugin{secret: []byte("0123456789abcdef0123456789abcdef")}
	srv := pl.server(t)
	defer srv.Close()
	u := testUsageRuntime(t, srv.URL, 1<<20)

	if err := u.authEvent(
		"acme", "https://issuer.test",
		authn.AuthEvent{
			Action: "login", Result: "ok",
			UserID: "sub-1", SessionID: "sid-1",
		},
	); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		got := pl.received()
		if len(got) == 1 {
			ev := got[0]
			if ev.Type != usage.TypeAuth || ev.Action != "login" ||
				ev.SessionID != "sid-1" || ev.Status != 200 {
				t.Fatalf("event = %+v", ev)
			}
			if ev.SubjectID == "" ||
				!strings.HasPrefix(ev.SubjectID, "v1.") {
				t.Fatalf("subjectId = %q", ev.SubjectID)
			}
			if ev.Tenant != "acme" {
				t.Fatalf("tenant = %q", ev.Tenant)
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("plugin did not receive the auth event")
}

func writeSignedPlugin(
	t *testing.T, dir string,
) (manifestPath, artifactPath, trustPath string, trust pluginmanifest.TrustStore) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	artifact := []byte("audit-plugin-binary-v1")
	artifactPath = filepath.Join(dir, "audit-plugin")
	if err := os.WriteFile(artifactPath, artifact, 0o700); err != nil {
		t.Fatal(err)
	}
	m := &pluginmanifest.Manifest{
		SchemaVersion: 1,
		Kind:          "extension",
		Name:          "com.cladone.audit",
		Version:       "1.0.0",
		APIVersion:    "v1",
		HostAPI:       ">=1.0 <2.0",
		KeyID:         "k1",
		Artifact: pluginmanifest.Artifact{
			Type: "binary", Digest: pluginmanifest.Digest(artifact),
			Size: int64(len(artifact)),
		},
		Capabilities: []string{"events"},
		Events: &pluginmanifest.EventSubscription{
			Types:    []string{"auth"},
			OnMaxLag: "block",
		},
	}
	payload, err := pluginmanifest.SigningPayload(m)
	if err != nil {
		t.Fatal(err)
	}
	m.Signature = pluginmanifest.Signature{
		Alg: "ed25519", KeyID: "k1",
		Value: base64.RawURLEncoding.EncodeToString(
			ed25519.Sign(priv, payload)),
	}
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	manifestPath = filepath.Join(dir, "audit.json")
	if err := os.WriteFile(manifestPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	key := base64.RawURLEncoding.EncodeToString(pub)
	trustJSON := `{"keys":{"k1":"` + key + `"},` +
		`"allowedNames":["com.cladone.*"],"coreVersion":"1.5.0"}`
	trustPath = filepath.Join(dir, "trust.json")
	if err := os.WriteFile(trustPath, []byte(trustJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	trust, err = pluginmanifest.LoadTrustStore([]byte(trustJSON))
	if err != nil {
		t.Fatal(err)
	}
	return manifestPath, artifactPath, trustPath, trust
}

func TestUsageRuntimeSignedManifest(t *testing.T) {
	dir := t.TempDir()
	manifestPath, artifactPath, _, trust := writeSignedPlugin(t, dir)
	pl := &usagePlugin{
		secret: []byte("0123456789abcdef0123456789abcdef"),
		name:   "com.cladone.audit",
	}
	srv := pl.server(t)
	defer srv.Close()
	cfg := &core.UsageConfig{
		Dir: t.TempDir(), NodeID: "gw-1", BudgetBytes: 1 << 20,
		Types: map[string]core.UsageTypeConfig{
			"auth": {ShareBytes: 1 << 20, Fsync: "none"},
		},
		Plugins: []core.UsagePluginConfig{{
			Name: "com.cladone.audit", URL: srv.URL,
			Manifest: manifestPath, Artifact: artifactPath,
		}},
		SubjectSecret: []byte("subject-secret"),
		PluginSecret:  []byte("0123456789abcdef0123456789abcdef"),
		Trust:         trust,
	}
	u, err := newUsageRuntime(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer u.close()
	if err := u.authEvent("acme", "https://issuer.test",
		authn.AuthEvent{Action: "login", Result: "ok", UserID: "sub-1"}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if len(pl.received()) == 1 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("signed plugin did not receive the auth event")
}

func TestUsageRuntimeSignedManifestDigestMismatch(t *testing.T) {
	dir := t.TempDir()
	manifestPath, artifactPath, _, trust := writeSignedPlugin(t, dir)
	if err := os.WriteFile(artifactPath, []byte("tampered"), 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := &core.UsageConfig{
		Dir: t.TempDir(), NodeID: "gw-1", BudgetBytes: 1 << 20,
		Types: map[string]core.UsageTypeConfig{
			"auth": {ShareBytes: 1 << 20, Fsync: "none"},
		},
		Plugins: []core.UsagePluginConfig{{
			Name: "com.cladone.audit", URL: "http://127.0.0.1:1",
			Manifest: manifestPath, Artifact: artifactPath,
		}},
		SubjectSecret: []byte("subject-secret"),
		PluginSecret:  []byte("0123456789abcdef0123456789abcdef"),
		Trust:         trust,
	}
	if _, err := newUsageRuntime(cfg, nil); err == nil {
		t.Fatal("tampered artifact accepted")
	}
}
