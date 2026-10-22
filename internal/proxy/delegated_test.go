package proxy

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func delegatedBroker(
	t *testing.T,
	tokenHandler http.HandlerFunc,
) *httptest.Server {
	t.Helper()

	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("X-Broker-Secret") != "delegated-secret" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			if r.URL.Path == "/providers" {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"providers":[
					{"name":"github","display_name":"GitHub"}
				]}`))
				return
			}
			if strings.HasPrefix(r.URL.Path, "/token/") {
				tokenHandler(w, r)
				return
			}
			http.NotFound(w, r)
		},
	))
	t.Cleanup(srv.Close)
	return srv
}

func delegatedBridge(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-User-Id", "user-1")
			w.Header().Set("X-Username", "alice")
			w.WriteHeader(http.StatusOK)
		},
	))
	t.Cleanup(srv.Close)
	return srv
}

func okDelegatedToken(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"provider":"github","access_token":"gh-token","token_type":"bearer"}`))
}

func TestDelegatedRESTInjectsToken(t *testing.T) {
	t.Setenv("DELEGATED_TEST_SECRET", "delegated-secret")

	var gotAuth, gotUser string
	backend := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			gotAuth = r.Header.Get("Authorization")
			gotUser = r.Header.Get("X-User-Id")
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"ok":true}`))
		},
	))
	t.Cleanup(backend.Close)

	broker := delegatedBroker(t, okDelegatedToken)
	bridge := delegatedBridge(t)
	clearAuthCache()
	t.Cleanup(clearAuthCache)

	cfg := loadForTest(t, fmt.Sprintf(`{
		"tokenBroker": {"url": %q, "secretEnv": "DELEGATED_TEST_SECRET"},
		"routes": [{
			"host": "api.test", "path": "/*", "backend": %q,
			"auth": {},
			"upstream": {"delegated": {"provider": "github"}}
		}]
	}`, broker.URL, backend.URL))

	gw, err := New(cfg, WithAuthBridgeURL(bridge.URL))
	if err != nil {
		t.Fatal(err)
	}

	resp := doRequestWithHeaders(t, gw, "api.test", "/repos",
		map[string]string{"Cookie": "access_token=u1"})
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, body = %s", resp.StatusCode, b)
	}
	if gotAuth != "Bearer gh-token" {
		t.Fatalf("Authorization = %q, want Bearer gh-token", gotAuth)
	}
	if gotUser != "user-1" {
		t.Fatalf("X-User-Id = %q", gotUser)
	}
}

func TestDelegatedRESTNotConnected(t *testing.T) {
	t.Setenv("DELEGATED_TEST_SECRET", "delegated-secret")

	backendHits := 0
	backend := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			backendHits++
			w.WriteHeader(http.StatusOK)
		},
	))
	t.Cleanup(backend.Close)

	broker := delegatedBroker(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{
			"error":"not_connected",
			"provider":"github",
			"connect_url":"https://login.test/connect/github?returnTo=x"
		}`))
	})
	bridge := delegatedBridge(t)
	clearAuthCache()
	t.Cleanup(clearAuthCache)

	cfg := loadForTest(t, fmt.Sprintf(`{
		"tokenBroker": {"url": %q, "secretEnv": "DELEGATED_TEST_SECRET"},
		"routes": [{
			"host": "api.test", "path": "/*", "backend": %q,
			"auth": {},
			"upstream": {"delegated": {"provider": "github"}}
		}]
	}`, broker.URL, backend.URL))

	gw, err := New(cfg, WithAuthBridgeURL(bridge.URL))
	if err != nil {
		t.Fatal(err)
	}

	resp := doRequestWithHeaders(t, gw, "api.test", "/repos",
		map[string]string{"Cookie": "access_token=u2"})
	if resp.StatusCode != http.StatusUnauthorized {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, body = %s", resp.StatusCode, b)
	}
	if backendHits != 0 {
		t.Fatalf("backend called %d times, want 0", backendHits)
	}

	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body["error"] != "delegated_credentials_required" {
		t.Fatalf("error = %v", body["error"])
	}
	connect, _ := body["connect_url"].(string)
	if !strings.Contains(connect, "returnTo=") ||
		!strings.Contains(connect, "api.test") {
		t.Fatalf("connect_url = %q", connect)
	}
}

func TestDelegatedPageRedirectsToConnect(t *testing.T) {
	t.Setenv("DELEGATED_TEST_SECRET", "delegated-secret")

	backend := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			t.Error("backend must not be called")
		},
	))
	t.Cleanup(backend.Close)

	broker := delegatedBroker(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{
			"error":"reauthorization_required",
			"provider":"github",
			"connect_url":"https://login.test/connect/github"
		}`))
	})
	bridge := delegatedBridge(t)
	clearAuthCache()
	t.Cleanup(clearAuthCache)

	cfg := loadForTest(t, fmt.Sprintf(`{
		"tokenBroker": {"url": %q, "secretEnv": "DELEGATED_TEST_SECRET"},
		"routes": [{
			"host": "page.test", "path": "/*", "backend": %q,
			"frontend": true, "auth": {},
			"upstream": {"delegated": {"provider": "github"}}
		}]
	}`, broker.URL, backend.URL))

	gw, err := New(cfg, WithAuthBridgeURL(bridge.URL))
	if err != nil {
		t.Fatal(err)
	}

	resp := doRequestWithHeaders(t, gw, "page.test", "/dashboard",
		map[string]string{"Cookie": "access_token=u3"})
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want 302", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if !strings.HasPrefix(loc, "https://login.test/connect/github?") ||
		!strings.Contains(loc, "returnTo=") {
		t.Fatalf("Location = %q", loc)
	}
}

func TestDelegatedBrokerUnavailable(t *testing.T) {
	t.Setenv("DELEGATED_TEST_SECRET", "delegated-secret")

	backend := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			t.Error("backend must not be called")
		},
	))
	t.Cleanup(backend.Close)

	broker := delegatedBroker(t, okDelegatedToken)
	bridge := delegatedBridge(t)
	clearAuthCache()
	t.Cleanup(clearAuthCache)

	cfg := loadForTest(t, fmt.Sprintf(`{
		"tokenBroker": {"url": %q, "secretEnv": "DELEGATED_TEST_SECRET"},
		"routes": [{
			"host": "api.test", "path": "/*", "backend": %q,
			"auth": {},
			"upstream": {"delegated": {"provider": "github"}}
		}]
	}`, broker.URL, backend.URL))

	gw, err := New(cfg, WithAuthBridgeURL(bridge.URL))
	if err != nil {
		t.Fatal(err)
	}

	// The provider list was fetched at load; now make the broker
	// unreachable for the token call.
	broker.Close()

	resp := doRequestWithHeaders(t, gw, "api.test", "/repos",
		map[string]string{"Cookie": "access_token=u4"})
	if resp.StatusCode != http.StatusBadGateway {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, body = %s", resp.StatusCode, b)
	}
	var body map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&body)
	if body["error"] != "token_broker_unavailable" {
		t.Fatalf("error = %v", body["error"])
	}
}

func TestDelegatedUnknownProviderRefusesStartup(t *testing.T) {
	t.Setenv("DELEGATED_TEST_SECRET", "delegated-secret")

	broker := delegatedBroker(t, okDelegatedToken)
	cfg := loadForTest(t, fmt.Sprintf(`{
		"tokenBroker": {"url": %q, "secretEnv": "DELEGATED_TEST_SECRET"},
		"routes": [{
			"host": "api.test", "path": "/*", "backend": "http://backend",
			"auth": {},
			"upstream": {"delegated": {"provider": "gitlab"}}
		}]
	}`, broker.URL))

	_, err := New(cfg)
	if err == nil || !strings.Contains(err.Error(), "gitlab") {
		t.Fatalf("error = %v, want unknown provider", err)
	}
}

func TestDelegatedMCPConnectURLReturnsToConnections(t *testing.T) {
	t.Setenv("DELEGATED_TEST_SECRET", "delegated-secret")

	upstream := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			t.Error("upstream must not be called without a token")
		},
	))
	t.Cleanup(upstream.Close)

	broker := delegatedBroker(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{
			"error":"not_connected",
			"provider":"github",
			"connect_url":"https://login.test/connect/github"
		}`))
	})
	bridge := delegatedBridge(t)
	clearAuthCache()
	t.Cleanup(clearAuthCache)

	cfg := loadForTest(t, fmt.Sprintf(`{
		"tokenBroker": {"url": %q, "secretEnv": "DELEGATED_TEST_SECRET"},
		"routes": [{
			"host": "mcp.test", "path": "/mcp", "backend": %q,
			"auth": {},
			"mcp": {"enabled": true, "path": "/mcp", "upstream": {}},
			"upstream": {"delegated": {"provider": "github"}}
		}]
	}`, broker.URL, upstream.URL))

	gw, err := New(cfg, WithAuthBridgeURL(bridge.URL))
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost,
		"http://mcp.test/mcp",
		strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`))
	req.Host = "mcp.test"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Authorization", "Bearer gate-one")
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body)
	}
	var body map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	connect, _ := body["connect_url"].(string)
	if !strings.Contains(connect, "returnTo=") ||
		!strings.Contains(connect, "%2Fconnections") {
		t.Fatalf("connect_url = %q, want connections returnTo", connect)
	}
}

func TestDelegatedMCPInjectsToken(t *testing.T) {
	t.Setenv("DELEGATED_TEST_SECRET", "delegated-secret")

	var gotAuth string
	backend := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			gotAuth = r.Header.Get("Authorization")
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"42"}`))
		},
	))
	t.Cleanup(backend.Close)

	openapi := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(testOpenAPIDoc))
		},
	))
	t.Cleanup(openapi.Close)

	broker := delegatedBroker(t, okDelegatedToken)
	bridge := delegatedBridge(t)
	clearAuthCache()
	t.Cleanup(clearAuthCache)

	cfg := loadForTest(t, fmt.Sprintf(`{
		"tokenBroker": {"url": %q, "secretEnv": "DELEGATED_TEST_SECRET"},
		"routes": [{
			"host": "gram.test", "path": "/mcp", "backend": %q,
			"auth": {},
			"mcp": {"enabled": true, "path": "/mcp", "scope": "mcp-tools",
				"operations": [{"name":"get_item","operationId":"get_item"}]},
			"upstream": {"delegated": {"provider": "github"}}
		}, {
			"host": "gram.test", "path": "/*", "backend": %q,
			"openapi": {"url": %q}
		}]
	}`, broker.URL, backend.URL, backend.URL, openapi.URL))

	gw, err := New(cfg, WithAuthBridgeURL(bridge.URL))
	if err != nil {
		t.Fatal(err)
	}

	_, decoded := postMCP(t, gw,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{
			"_meta":{
				"io.modelcontextprotocol/protocolVersion":"2026-07-28",
				"io.modelcontextprotocol/clientCapabilities":{}
			},
			"name":"get_item",
			"arguments":{"id":"42"}}}`,
		map[string]string{
			"Mcp-Protocol-Version": "2026-07-28",
			"Mcp-Method":           "tools/call",
			"Mcp-Name":             "get_item",
		})

	if _, hasErr := decoded["error"]; hasErr {
		t.Fatalf("JSON-RPC error: %v", decoded["error"])
	}
	if gotAuth != "Bearer gh-token" {
		t.Fatalf("backend Authorization = %q, want Bearer gh-token", gotAuth)
	}
}
