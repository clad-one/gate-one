package proxy

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"cladone/gate-one/internal/core"
)

// turnstileTestGateway builds a gateway whose route has no auth (a
// public form page) and a matching Turnstile block.
func turnstileTestGateway(
	t *testing.T,
	backend string,
	turnstileJSON string,
	routeExtra string,
) *Gateway {
	t.Helper()
	t.Setenv("TEST_TURNSTILE_SECRET", "turnstile-secret")
	raw := `{
		"turnstile": ` + turnstileJSON + `,
		"authProvider": {
			"type": "dev",
			"loginBaseUrl": "http://login.dev.test:3000",
			"cookieDomain": "dev.test"
		},
		"routes": [{
			"host": "app.dev.test", "path": "/*", "frontend": true,
			"backend": "` + backend + `"` + routeExtra + `
		}]
	}`
	path := filepath.Join(t.TempDir(), "routes.json")
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
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
	t.Cleanup(func() { _ = gw.Close() })
	return gw
}

// turnstileSiteverify returns a fake Siteverify endpoint. Tokens:
// "good" succeeds, "expired" fails with timeout-or-duplicate, "boom"
// answers 500.
func turnstileSiteverify(t *testing.T, hostname, action string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			_ = r.ParseForm()
			token := r.Form.Get("response")
			if r.Form.Get("secret") != "turnstile-secret" {
				t.Errorf("secret = %q", r.Form.Get("secret"))
			}
			w.Header().Set("Content-Type", "application/json")
			switch token {
			case "good":
				fmt.Fprintf(w,
					`{"success":true,"hostname":%q,"action":%q}`,
					hostname, action)
			case "expired":
				io.WriteString(w,
					`{"success":false,"error-codes":["timeout-or-duplicate"]}`)
			case "wronghost":
				io.WriteString(w,
					`{"success":true,"hostname":"evil.test","action":"contact"}`)
			case "wrongaction":
				io.WriteString(w,
					`{"success":true,"hostname":"app.dev.test","action":"other"}`)
			case "boom":
				http.Error(w, "nope", http.StatusInternalServerError)
			default:
				io.WriteString(w,
					`{"success":false,"error-codes":["invalid-input-response"]}`)
			}
		}))
	t.Cleanup(srv.Close)
	return srv
}

func turnstilePost(token string) *http.Request {
	form := url.Values{}
	form.Set("message", "hello")
	if token != "" {
		form.Set(core.TurnstileFormField, token)
	}
	req := httptest.NewRequest(
		http.MethodPost, "http://app.dev.test/contact/send",
		strings.NewReader(form.Encode()))
	req.Host = "app.dev.test"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Accept", "text/html")
	return req
}

func TestTurnstileVerifyReachesBackend(t *testing.T) {
	var calls atomic.Int32
	var leaked atomic.Value
	backend := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			calls.Add(1)
			leaked.Store(r.Header.Get(core.DefaultTurnstileTokenHeader))
			io.WriteString(w, "form accepted")
		}))
	defer backend.Close()
	sv := turnstileSiteverify(t, "app.dev.test", "contact")
	gw := turnstileTestGateway(t, backend.URL,
		`{"siteKey":"0x4AAAA","secretEnv":"TEST_TURNSTILE_SECRET",
		  "paths":["/contact/*"],"action":"contact"}`, "")
	gw.turnstile.endpoint = sv.URL

	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, turnstilePost("good"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if calls.Load() != 1 {
		t.Fatalf("backend calls = %d", calls.Load())
	}

	// Header mode (fetch/SPA): the token is accepted, then stripped
	// before the backend sees the request.
	req := turnstilePost("")
	req.Header.Set(core.DefaultTurnstileTokenHeader, "good")
	rec2 := httptest.NewRecorder()
	gw.ServeHTTP(rec2, req)
	if rec2.Code != http.StatusOK {
		t.Fatalf("header mode status = %d, body = %s",
			rec2.Code, rec2.Body.String())
	}
	if calls.Load() != 2 {
		t.Fatalf("backend calls = %d, want 2", calls.Load())
	}
	if got, _ := leaked.Load().(string); got != "" {
		t.Fatalf("the Turnstile token reached the backend: %q", got)
	}
}

func TestTurnstileMissingTokenIs403(t *testing.T) {
	var calls atomic.Int32
	backend := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			calls.Add(1)
		}))
	defer backend.Close()
	sv := turnstileSiteverify(t, "app.dev.test", "contact")
	gw := turnstileTestGateway(t, backend.URL,
		`{"siteKey":"0x4AAAA","secretEnv":"TEST_TURNSTILE_SECRET",
		  "paths":["/contact/*"]}`, "")
	gw.turnstile.endpoint = sv.URL

	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, turnstilePost(""))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d", rec.Code)
	}
	if calls.Load() != 0 {
		t.Fatal("the backend was reached without a token")
	}
	if !strings.Contains(rec.Body.String(), "Verification") {
		t.Fatalf("body = %s", rec.Body.String())
	}
}

func TestTurnstileInvalidTokenIs403JSON(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {}))
	defer backend.Close()
	sv := turnstileSiteverify(t, "app.dev.test", "contact")
	gw := turnstileTestGateway(t, backend.URL,
		`{"siteKey":"0x4AAAA","secretEnv":"TEST_TURNSTILE_SECRET",
		  "paths":["/contact/*"]}`, "")
	gw.turnstile.endpoint = sv.URL

	req := turnstilePost("nope")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Sec-Fetch-Dest", "empty")
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"turnstile_failed"`) {
		t.Fatalf("body = %s", rec.Body.String())
	}
}

func TestTurnstileExpiredReason(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {}))
	defer backend.Close()
	sv := turnstileSiteverify(t, "app.dev.test", "contact")
	gw := turnstileTestGateway(t, backend.URL,
		`{"siteKey":"0x4AAAA","secretEnv":"TEST_TURNSTILE_SECRET",
		  "paths":["/contact/*"]}`, "")
	gw.turnstile.endpoint = sv.URL

	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, turnstilePost("expired"))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "expired") {
		t.Fatalf("body = %s", rec.Body.String())
	}
}

func TestTurnstileUnavailableIs503(t *testing.T) {
	var calls atomic.Int32
	backend := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			calls.Add(1)
		}))
	defer backend.Close()
	sv := turnstileSiteverify(t, "app.dev.test", "contact")
	gw := turnstileTestGateway(t, backend.URL,
		`{"siteKey":"0x4AAAA","secretEnv":"TEST_TURNSTILE_SECRET",
		  "paths":["/contact/*"]}`, "")
	gw.turnstile.endpoint = sv.URL

	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, turnstilePost("boom"))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d", rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Fatal("missing Retry-After")
	}
	if calls.Load() != 0 {
		t.Fatal("the backend was reached during a Siteverify outage")
	}
}

func TestTurnstileHostnameAndActionMismatch(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {}))
	defer backend.Close()
	sv := turnstileSiteverify(t, "app.dev.test", "contact")

	cases := []struct {
		token string
		block string
	}{
		{"wronghost",
			`{"siteKey":"0x4AAAA","secretEnv":"TEST_TURNSTILE_SECRET",
			  "paths":["/contact/*"],"hostname":"app.dev.test"}`},
		{"wrongaction",
			`{"siteKey":"0x4AAAA","secretEnv":"TEST_TURNSTILE_SECRET",
			  "paths":["/contact/*"],"action":"contact"}`},
	}
	for _, c := range cases {
		gw := turnstileTestGateway(t, backend.URL, c.block, "")
		gw.turnstile.endpoint = sv.URL
		rec := httptest.NewRecorder()
		gw.ServeHTTP(rec, turnstilePost(c.token))
		if rec.Code != http.StatusForbidden {
			t.Errorf("token %s: status = %d", c.token, rec.Code)
		}
	}
}

func TestTurnstileNonMatchingPathIsNotChallenged(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, "ok")
		}))
	defer backend.Close()
	sv := turnstileSiteverify(t, "app.dev.test", "contact")
	gw := turnstileTestGateway(t, backend.URL,
		`{"siteKey":"0x4AAAA","secretEnv":"TEST_TURNSTILE_SECRET",
		  "paths":["/contact/*"]}`, "")
	gw.turnstile.endpoint = sv.URL

	req := httptest.NewRequest(
		http.MethodPost, "http://app.dev.test/other/send",
		strings.NewReader("message=hi"))
	req.Host = "app.dev.test"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestTurnstileInjectionAndCSP(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			io.WriteString(w, "<html><body><form method=post>hi</form></body></html>")
		}))
	defer backend.Close()
	gw := turnstileTestGateway(t, backend.URL,
		`{"siteKey":"0x4AAAA","secretEnv":"TEST_TURNSTILE_SECRET",
		  "paths":["/contact/*"],"action":"contact",
		  "forms":["form#contact"]}`,
		`, "csp": {"mode": "nonce"}`)

	// The page path matches: the widget script is injected.
	req := httptest.NewRequest(http.MethodGet, "http://app.dev.test/contact/", nil)
	req.Host = "app.dev.test"
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)
	body := rec.Body.String()
	if !strings.Contains(body, "challenges.cloudflare.com/turnstile") ||
		!strings.Contains(body, "cf-turnstile-response") {
		t.Fatalf("widget script missing: %s", body)
	}
	if !strings.Contains(body, `"siteKey":"0x4AAAA"`) {
		t.Fatalf("site key missing from the script: %s", body)
	}
	csp := strings.Join(rec.Header().Values("Content-Security-Policy"), " ")
	if !strings.Contains(csp, "challenges.cloudflare.com") {
		t.Fatalf("CSP missing the Turnstile origin: %q", csp)
	}

	// Another path is left untouched.
	req2 := httptest.NewRequest(http.MethodGet, "http://app.dev.test/other", nil)
	req2.Host = "app.dev.test"
	rec2 := httptest.NewRecorder()
	gw.ServeHTTP(rec2, req2)
	if strings.Contains(rec2.Body.String(), "challenges.cloudflare.com/turnstile") {
		t.Fatal("the widget was injected on a non-matching path")
	}
}

func TestTurnstileGETIsNotChallenged(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			io.WriteString(w, "<html><body>page</body></html>")
		}))
	defer backend.Close()
	sv := turnstileSiteverify(t, "app.dev.test", "")
	gw := turnstileTestGateway(t, backend.URL,
		`{"siteKey":"0x4AAAA","secretEnv":"TEST_TURNSTILE_SECRET",
		  "paths":["/contact/*"]}`, "")
	gw.turnstile.endpoint = sv.URL

	req := httptest.NewRequest(http.MethodGet, "http://app.dev.test/contact/", nil)
	req.Host = "app.dev.test"
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestTurnstileTokenExtraction(t *testing.T) {
	ctx := &RequestContext{}

	req := httptest.NewRequest(http.MethodPost, "http://x/", nil)
	req.Header.Set(core.DefaultTurnstileTokenHeader, "header-token")
	if tok, ok := turnstileToken(
		req, ctx, core.DefaultTurnstileTokenHeader); !ok || tok != "header-token" {
		t.Fatalf("header token = %q, %v", tok, ok)
	}

	form := url.Values{}
	form.Set(core.TurnstileFormField, "form-token")
	req = httptest.NewRequest(http.MethodPost, "http://x/", nil)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	ctx.RawBody = []byte(form.Encode())
	if tok, ok := turnstileToken(req, ctx, core.DefaultTurnstileTokenHeader); !ok ||
		tok != "form-token" {
		t.Fatalf("form token = %q, %v", tok, ok)
	}

	req = httptest.NewRequest(http.MethodPost, "http://x/", nil)
	req.Header.Set("Content-Type", "application/json")
	ctx.RawBody = []byte(`{"cf-turnstile-response":"json-token"}`)
	if tok, ok := turnstileToken(req, ctx, core.DefaultTurnstileTokenHeader); !ok ||
		tok != "json-token" {
		t.Fatalf("json token = %q, %v", tok, ok)
	}

	// multipart
	var b strings.Builder
	b.WriteString("--BOUND\r\n")
	b.WriteString("Content-Disposition: form-data; name=\"cf-turnstile-response\"\r\n\r\n")
	b.WriteString("multi-token\r\n--BOUND--\r\n")
	req = httptest.NewRequest(http.MethodPost, "http://x/", nil)
	req.Header.Set("Content-Type", "multipart/form-data; boundary=BOUND")
	ctx.RawBody = []byte(b.String())
	if tok, ok := turnstileToken(req, ctx, core.DefaultTurnstileTokenHeader); !ok ||
		tok != "multi-token" {
		t.Fatalf("multipart token = %q, %v", tok, ok)
	}

	// garbage / too long
	req = httptest.NewRequest(http.MethodPost, "http://x/", nil)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	ctx.RawBody = []byte("cf-turnstile-response=" + strings.Repeat("a", 3000))
	if _, ok := turnstileToken(
		req, ctx, core.DefaultTurnstileTokenHeader); ok {
		t.Fatal("an oversized token was accepted")
	}
}
