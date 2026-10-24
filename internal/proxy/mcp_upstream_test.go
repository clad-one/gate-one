package proxy

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"cladone/gate-one/internal/core"
)

func TestFilterMCPToolsJSON(t *testing.T) {
	f := &core.MCPToolFilter{Exclude: []string{"delete_*"}}
	out, changed, err := filterMCPToolsJSON([]byte(`{
		"jsonrpc":"2.0","id":1,
		"result":{
			"tools":[
				{"name":"list_issues","description":"list"},
				{"name":"delete_repo","description":"delete"}
			],
			"nextCursor":"page-2"
		}
	}`), f, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("expected a change")
	}

	var msg struct {
		Result struct {
			Tools      []struct{ Name string } `json:"tools"`
			NextCursor string                  `json:"nextCursor"`
		} `json:"result"`
	}
	if err := json.Unmarshal(out, &msg); err != nil {
		t.Fatal(err)
	}
	if len(msg.Result.Tools) != 1 || msg.Result.Tools[0].Name != "list_issues" {
		t.Fatalf("tools = %+v", msg.Result.Tools)
	}
	if msg.Result.NextCursor != "page-2" {
		t.Fatalf("cursor = %q", msg.Result.NextCursor)
	}
}

func TestFilterMCPToolsSSE(t *testing.T) {
	f := &core.MCPToolFilter{Include: []string{"list_*"}}
	raw := "event: message\n" +
		`data: {"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"list_issues"},{"name":"create_issue"}]}}` +
		"\n\n" +
		"event: message\n" +
		`data: {"jsonrpc":"2.0","method":"notifications/tools/list_changed"}` +
		"\n\n"

	out, err := filterMCPToolsSSE([]byte(raw), f, nil)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if !strings.Contains(s, `"list_issues"`) {
		t.Fatalf("allowed tool lost: %s", s)
	}
	if strings.Contains(s, `"create_issue"`) {
		t.Fatalf("hidden tool leaked: %s", s)
	}
	if !strings.Contains(s, "notifications/tools/list_changed") {
		t.Fatalf("notification lost: %s", s)
	}

	// Fail closed: an unparseable tools/list payload could contain
	// tool names the filter cannot inspect.
	if _, err := filterMCPToolsSSE(
		[]byte("data: not-json\n\n"), f, nil); err == nil {
		t.Fatal("expected an error for unparseable SSE data")
	}
}

func TestMCPUpstreamStaticHeadersAndSSE(t *testing.T) {
	var seenAuth, seenKey, seenMethod string

	upstream := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			seenAuth = r.Header.Get("Authorization")
			seenKey = r.Header.Get("X-API-Key")

			body, _ := io.ReadAll(r.Body)
			var req struct {
				Method string `json:"method"`
			}
			_ = json.Unmarshal(body, &req)
			seenMethod = req.Method

			if req.Method == "tools/call" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			w.Header().Set("Content-Type", "text/event-stream")
			w.Header().Set("Mcp-Session-Id", "sse-session")
			_, _ = w.Write([]byte(
				"event: message\n" +
					`data: {"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"list_issues"},{"name":"delete_repo"}]}}` +
					"\n\n" +
					"event: message\n" +
					`data: {"jsonrpc":"2.0","method":"notifications/tools/list_changed"}` +
					"\n\n",
			))
		},
	))
	t.Cleanup(upstream.Close)

	bridge := delegatedBridge(t)
	clearAuthCache()
	t.Cleanup(clearAuthCache)

	t.Setenv("STATIC_API_KEY", "static-key")
	cfg := loadForTest(t, fmt.Sprintf(`{
		"routes": [{
			"host": "mcp.test", "path": "/mcp", "backend": %q,
			"auth": {},
			"mcp": {
				"enabled": true,
				"path": "/mcp",
				"upstream": {"tools": {"exclude": ["delete_*"]}}
			},
			"upstream": {"headers": {
				"Authorization": "Bearer static-service-token",
				"X-API-Key": "${STATIC_API_KEY}"
			}}
		}]
	}`, upstream.URL))

	gw, err := New(cfg, WithAuthBridgeURL(bridge.URL))
	if err != nil {
		t.Fatal(err)
	}

	call := func(body string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost,
			"http://mcp.test/mcp", strings.NewReader(body))
		req.Host = "mcp.test"
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		req.Header.Set("Authorization", "Bearer gate-one-token")
		rec := httptest.NewRecorder()
		gw.ServeHTTP(rec, req)
		return rec
	}

	rec := call(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("tools/list status = %d: %s", rec.Code, rec.Body)
	}
	if seenAuth != "Bearer static-service-token" ||
		seenKey != "static-key" || seenMethod != "tools/list" {
		t.Fatalf("upstream saw auth=%q key=%q method=%q",
			seenAuth, seenKey, seenMethod)
	}
	if !strings.Contains(rec.Body.String(), "list_issues") {
		t.Fatalf("allowed tool missing: %s", rec.Body)
	}
	if strings.Contains(rec.Body.String(), "delete_repo") {
		t.Fatalf("hidden tool leaked: %s", rec.Body)
	}
	if got := rec.Header().Get("Content-Type"); !strings.HasPrefix(got, "text/event-stream") {
		t.Fatalf("Content-Type = %q", got)
	}

	// An upstream 401 is an upstream credential problem, not a Gate
	// One session problem: the client must not be told to re-auth
	// against Gate One.
	rec = call(`{"jsonrpc":"2.0","id":2,"method":"tools/call",
		"params":{"name":"list_issues","arguments":{}}}`)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("upstream 401 status = %d: %s", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), "upstream_mcp_authentication_failed") {
		t.Fatalf("upstream 401 body = %s", rec.Body)
	}
}

func TestMCPUpstreamSessionOwnership(t *testing.T) {
	var upstreamCalls int

	upstream := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			upstreamCalls++
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Mcp-Session-Id", "shared-session")
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
		},
	))
	t.Cleanup(upstream.Close)

	bridge := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			user := "user-1"
			if strings.Contains(r.Header.Get("Authorization"), "user-2") {
				user = "user-2"
			}
			w.Header().Set("X-User-Id", user)
			w.WriteHeader(http.StatusOK)
		},
	))
	t.Cleanup(bridge.Close)
	clearAuthCache()
	t.Cleanup(clearAuthCache)

	cfg := loadForTest(t, fmt.Sprintf(`{
		"routes": [{
			"host": "mcp.test", "path": "/mcp", "backend": %q,
			"auth": {},
			"mcp": {"enabled": true, "path": "/mcp", "upstream": {}}
		}]
	}`, upstream.URL))

	gw, err := New(cfg, WithAuthBridgeURL(bridge.URL))
	if err != nil {
		t.Fatal(err)
	}

	call := func(bearer, session string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost,
			"http://mcp.test/mcp",
			strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`))
		req.Host = "mcp.test"
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+bearer)
		req.Header.Set("Mcp-Session-Id", session)
		rec := httptest.NewRecorder()
		gw.ServeHTTP(rec, req)
		return rec
	}

	rec := call("user-1", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("user-1 initialize status = %d: %s", rec.Code, rec.Body)
	}
	if got := rec.Header().Get("Mcp-Session-Id"); got != "shared-session" {
		t.Fatalf("session = %q", got)
	}

	// The same upstream session id, presented by another Gate One
	// user, must be refused before it reaches the upstream.
	before := upstreamCalls
	rec = call("user-2", "shared-session")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("user-2 session reuse status = %d: %s", rec.Code, rec.Body)
	}
	if upstreamCalls != before {
		t.Fatalf("cross-user session reached upstream")
	}
}

func TestMCPUpstreamProxyFilter(t *testing.T) {
	t.Setenv("DELEGATED_TEST_SECRET", "delegated-secret")

	var (
		upstreamAuth    string
		upstreamCall    string
		upstreamName    string
		upstreamSession string
		upstreamCalls   int
	)

	upstream := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			upstreamCalls++
			upstreamAuth = r.Header.Get("Authorization")
			upstreamSession = r.Header.Get("Mcp-Session-Id")

			body, _ := io.ReadAll(r.Body)
			var req struct {
				ID     json.RawMessage `json:"id"`
				Method string          `json:"method"`
				Params struct {
					Name string `json:"name"`
				} `json:"params"`
			}
			_ = json.Unmarshal(body, &req)

			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Mcp-Session-Id", "upstream-session")
			switch req.Method {
			case "tools/list":
				_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[
					{"name":"list_issues"},
					{"name":"delete_repo"}
				]}}`))
			case "tools/call":
				upstreamCall = req.Params.Name
				upstreamName = r.Header.Get("Mcp-Name")
				_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":2,"result":{
					"content":[{"type":"text","text":"ok"}]
				}}`))
			default:
				_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
			}
		},
	))
	t.Cleanup(upstream.Close)

	broker := delegatedBroker(t, okDelegatedToken)
	bridge := delegatedBridge(t)
	clearAuthCache()
	t.Cleanup(clearAuthCache)

	cfg := loadForTest(t, fmt.Sprintf(`{
		"tokenBroker": {"url": %q, "secretEnv": "DELEGATED_TEST_SECRET"},
		"routes": [{
			"host": "mcp.test", "path": "/mcp", "backend": %q,
			"auth": {},
			"mcp": {
				"enabled": true,
				"path": "/mcp",
				"upstream": {"tools": {"exclude": ["delete_*"]}}
			},
			"upstream": {"delegated": {"provider": "github"}}
		}]
	}`, broker.URL, upstream.URL))

	gw, err := New(cfg, WithAuthBridgeURL(bridge.URL))
	if err != nil {
		t.Fatal(err)
	}

	call := func(body string, headers map[string]string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost,
			"http://mcp.test/mcp", strings.NewReader(body))
		req.Host = "mcp.test"
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		req.Header.Set("Authorization", "Bearer gate-one-token")
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		rec := httptest.NewRecorder()
		gw.ServeHTTP(rec, req)
		return rec
	}

	rec := call(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`,
		map[string]string{"Mcp-Session-Id": "downstream-session"})
	if rec.Code != http.StatusOK {
		t.Fatalf("tools/list status = %d: %s", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), "list_issues") {
		t.Fatalf("allowed tool missing: %s", rec.Body)
	}
	if strings.Contains(rec.Body.String(), "delete_repo") {
		t.Fatalf("hidden tool leaked: %s", rec.Body)
	}
	if upstreamAuth != "Bearer gh-token" {
		t.Fatalf("upstream Authorization = %q", upstreamAuth)
	}
	if upstreamSession != "downstream-session" {
		t.Fatalf("upstream session = %q", upstreamSession)
	}
	if got := rec.Header().Get("Mcp-Session-Id"); got != "upstream-session" {
		t.Fatalf("downstream session = %q", got)
	}

	// A hidden tool cannot be called by guessing its name: the
	// upstream must not see the request.
	before := upstreamCalls
	rec = call(`{"jsonrpc":"2.0","id":2,"method":"tools/call",
		"params":{"name":"delete_repo","arguments":{}}}`,
		map[string]string{"Mcp-Session-Id": "downstream-session"})
	if rec.Code != http.StatusOK {
		t.Fatalf("blocked call status = %d: %s", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), "tool not available") {
		t.Fatalf("blocked call body = %s", rec.Body)
	}
	if upstreamCalls != before {
		t.Fatalf("hidden tool reached upstream")
	}

	// An allowed call is forwarded with the delegated token. A
	// client-supplied Mcp-Name cannot name another (hidden) tool:
	// the header is rebuilt from the inspected body.
	rec = call(`{"jsonrpc":"2.0","id":3,"method":"tools/call",
		"params":{"name":"list_issues","arguments":{}}}`,
		map[string]string{
			"Mcp-Session-Id": "downstream-session",
			"Mcp-Name":       "delete_repo",
		})
	if rec.Code != http.StatusOK {
		t.Fatalf("allowed call status = %d: %s", rec.Code, rec.Body)
	}
	if upstreamCall != "list_issues" {
		t.Fatalf("upstream call = %q", upstreamCall)
	}
	if upstreamName != "list_issues" {
		t.Fatalf("upstream Mcp-Name = %q", upstreamName)
	}
	if !strings.Contains(rec.Body.String(), `"text":"ok"`) {
		t.Fatalf("allowed call body = %s", rec.Body)
	}
}
