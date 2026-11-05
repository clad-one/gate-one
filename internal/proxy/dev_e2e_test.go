package proxy

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cladone/gate-one/internal/core"
)

func devGateway(t *testing.T, backendURL string) *Gateway {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "routes.json")
	cfgJSON := `{
		"authProvider": {
			"type": "dev",
			"loginBaseUrl": "http://login.dev.test:3000",
			"cookieDomain": "dev.test"
		},
		"routes": [{
			"host": "app.dev.test", "path": "/*", "frontend": true,
			"backend": "` + backendURL + `", "auth": {}
		}]
	}`
	if err := os.WriteFile(path, []byte(cfgJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := core.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	gw, err := New(cfg, WithListenAddr("127.0.0.1:0"))
	if err != nil {
		t.Fatal(err)
	}
	clearAuthCache()
	return gw
}

func TestDevProviderEndToEnd(t *testing.T) {
	var seenUser string
	backend := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			seenUser = r.Header.Get("X-Username")
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte("<html><body>hello</body></html>"))
		},
	))
	t.Cleanup(backend.Close)

	gw := devGateway(t, backend.URL)

	// 1. Anonymous navigation → login host.
	req := httptest.NewRequest(http.MethodGet, "http://app.dev.test/", nil)
	req.Host = "app.dev.test"
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("anonymous = %d, want 302", rec.Code)
	}
	loc := rec.Header().Get("Location")
	if !strings.HasPrefix(loc, "http://login.dev.test:3000/login?returnTo=") {
		t.Fatalf("Location = %q, want the dev login host", loc)
	}

	// 2. The login page is served on the dedicated host (not proxied).
	loginPath := strings.TrimPrefix(loc, "http://login.dev.test:3000")
	req = httptest.NewRequest(http.MethodGet, "http://login.dev.test:3000"+loginPath, nil)
	req.Host = "login.dev.test:3000"
	rec = httptest.NewRecorder()
	gw.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET login = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "Connexion de développement") {
		t.Fatalf("login page not served: %s", rec.Body.String())
	}
	var csrf string
	for _, c := range rec.Result().Cookies() {
		if c.Name == "gate_one_dev_csrf" {
			csrf = c.Value
		}
	}
	if csrf == "" {
		t.Fatal("csrf cookie missing")
	}

	// 3. POST credentials → session cookie + redirect back.
	form := url.Values{
		"username": {"bob"},
		"password": {"bob"},
		"csrf":     {csrf},
		"returnTo": {"http://app.dev.test/"},
	}
	req = httptest.NewRequest(
		http.MethodPost, "http://login.dev.test:3000/login",
		strings.NewReader(form.Encode()),
	)
	req.Host = "login.dev.test:3000"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "gate_one_dev_csrf", Value: csrf})
	rec = httptest.NewRecorder()
	gw.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("POST login = %d, want 302: %s", rec.Code, rec.Body.String())
	}
	var session string
	for _, c := range rec.Result().Cookies() {
		if c.Name == "gate_one_dev_session" {
			session = c.Value
		}
	}
	if session == "" {
		t.Fatal("session cookie missing")
	}

	// 4. The application sees the identity supplied by the dev IdP.
	req = httptest.NewRequest(http.MethodGet, "http://app.dev.test/", nil)
	req.Host = "app.dev.test"
	req.AddCookie(&http.Cookie{Name: "gate_one_dev_session", Value: session})
	rec = httptest.NewRecorder()
	gw.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("authenticated = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if seenUser != "bob" {
		t.Errorf("backend X-Username = %q, want bob", seenUser)
	}
}

func TestDevRefusesNonLoopback(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {},
	))
	t.Cleanup(backend.Close)

	dir := t.TempDir()
	path := filepath.Join(dir, "routes.json")
	cfgJSON := `{
		"authProvider": {
			"type": "dev",
			"loginBaseUrl": "http://login.dev.test:3000",
			"cookieDomain": "dev.test"
		},
		"routes": [{
			"host": "app.dev.test", "path": "/*", "frontend": true,
			"backend": "` + backend.URL + `", "auth": {}
		}]
	}`
	if err := os.WriteFile(path, []byte(cfgJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := core.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := New(cfg, WithListenAddr("0.0.0.0:3000")); err == nil ||
		!strings.Contains(err.Error(), "loopback-only") {
		t.Fatalf("err = %v, want loopback-only refusal", err)
	}
}

func TestDevLoginHostCanAlsoServeApplication(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte("<html><body>app</body></html>"))
		},
	))
	t.Cleanup(backend.Close)

	dir := t.TempDir()
	path := filepath.Join(dir, "routes.json")
	cfgJSON := `{
		"authProvider": {
			"type": "dev",
			"loginBaseUrl": "http://app.dev.test:3000",
			"cookieDomain": "dev.test"
		},
		"routes": [{
			"host": "app.dev.test", "path": "/*", "frontend": true,
			"backend": "` + backend.URL + `"
		}]
	}`
	if err := os.WriteFile(path, []byte(cfgJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := core.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	gw, err := New(cfg, WithListenAddr("127.0.0.1:0"))
	if err != nil {
		t.Fatal(err)
	}
	defer gw.Close()
	clearAuthCache()

	for _, tc := range []struct {
		path string
		want string
	}{
		{"/", "app"},
		{"/page", "app"},
		{"/login", "Connexion de développement"},
		{"/health", `"provider":"dev"`},
	} {
		req := httptest.NewRequest(
			http.MethodGet, "http://app.dev.test:3000"+tc.path, nil)
		req.Host = "app.dev.test:3000"
		rec := httptest.NewRecorder()
		gw.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s = %d: %s", tc.path, rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), tc.want) {
			t.Fatalf("%s body = %q, want %q",
				tc.path, rec.Body.String(), tc.want)
		}
	}
}

func TestLoginHostUsesProviderDefaultApp(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("app"))
		},
	))
	t.Cleanup(backend.Close)

	dir := t.TempDir()
	path := filepath.Join(dir, "routes.json")
	cfgJSON := `{
		"defaultAppUrl": "https://global.dev.test/",
		"authProvider": {
			"type": "dev",
			"loginBaseUrl": "http://login.dev.test:3000",
			"cookieDomain": "dev.test",
			"defaultAppUrl": "http://app.dev.test/"
		},
		"routes": [{
			"host": "app.dev.test", "path": "/*", "frontend": true,
			"backend": "` + backend.URL + `"
		}]
	}`
	if err := os.WriteFile(path, []byte(cfgJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := core.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	gw, err := New(cfg, WithListenAddr("127.0.0.1:0"))
	if err != nil {
		t.Fatal(err)
	}
	defer gw.Close()
	clearAuthCache()

	req := httptest.NewRequest(
		http.MethodGet, "http://login.dev.test:3000/", nil)
	req.Host = "login.dev.test:3000"
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Location"); got != "http://app.dev.test/" {
		t.Fatalf("Location = %q, want provider default app", got)
	}
}
