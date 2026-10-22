package proxy

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestMCPToolsCallProxiesREST is the end-to-end contract of the
// REST → MCP conversion: tools/call on the MCP route produces the
// documented HTTP request on the backend (method, path template
// substitution, query parameters, gateway identity) and the REST
// answer comes back as MCP text content.
func TestMCPToolsCallProxiesREST(t *testing.T) {

	var (
		method string
		path   string
		query  string
		user   string
		roles  string
	)

	gw, _ := newMCPGatewayWithOpenAPI(t,
		func(w http.ResponseWriter, r *http.Request) {
			method = r.Method
			path = r.URL.Path
			query = r.URL.RawQuery
			user = r.Header.Get("X-User-Id")
			roles = r.Header.Get("X-Roles")

			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w,
				`{"id":"42","name":"widget"}`)
		})

	_, decoded := postMCP(t, gw,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{
			"_meta":{
				"io.modelcontextprotocol/protocolVersion":"2026-07-28",
				"io.modelcontextprotocol/clientCapabilities":{}
			},
			"name":"get_item",
			"arguments":{"id":"42","verbose":true}}}`,
		map[string]string{
			"Mcp-Protocol-Version": "2026-07-28",
			"Mcp-Method":           "tools/call",
			"Mcp-Name":             "get_item",
		})

	if err, ok := decoded["error"]; ok {
		t.Fatalf("unexpected JSON-RPC error: %v", err)
	}

	result, _ := decoded["result"].(map[string]any)
	if result == nil {
		t.Fatalf("missing result: %v", decoded)
	}

	if isErr, _ := result["isError"].(bool); isErr {
		t.Fatalf("tool call failed: %v", result)
	}

	content, _ := result["content"].([]any)
	if len(content) != 1 {
		t.Fatalf("content = %v", result["content"])
	}
	first, _ := content[0].(map[string]any)
	text, _ := first["text"].(string)

	if !strings.Contains(text, "widget") {
		t.Errorf("tool text = %q, want the backend JSON", text)
	}

	if method != http.MethodGet {
		t.Errorf("backend method = %q, want GET", method)
	}
	if path != "/items/42" {
		t.Errorf("backend path = %q, want /items/42", path)
	}
	if query != "verbose=true" {
		t.Errorf("backend query = %q, want verbose=true", query)
	}
	if user != "user-1" {
		t.Errorf("X-User-Id = %q, want the MCP identity", user)
	}
	if roles != "admin" {
		t.Errorf("X-Roles = %q, want admin", roles)
	}
}

// TestMCPToolsCallUnknownTool: an unknown tool name is a JSON-RPC
// error, never a call to the backend.
func TestMCPToolsCallUnknownTool(t *testing.T) {

	called := false

	gw, _ := newMCPGatewayWithOpenAPI(t,
		func(w http.ResponseWriter, r *http.Request) {
			called = true
		})

	body := `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{
		"_meta":{
			"io.modelcontextprotocol/protocolVersion":"2026-07-28",
			"io.modelcontextprotocol/clientCapabilities":{}
		},
		"name":"nope","arguments":{}}}`

	req := httptest.NewRequest(
		http.MethodPost, "http://gram.test/mcp", strings.NewReader(body))
	req.Host = "gram.test"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Mcp-Protocol-Version", "2026-07-28")
	req.Header.Set("Mcp-Method", "tools/call")
	req.Header.Set("Mcp-Name", "nope")

	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	var decoded map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&decoded); err != nil {
		t.Fatalf("response %d not JSON-RPC: %v", rec.Code, err)
	}

	if _, hasErr := decoded["error"]; !hasErr {
		t.Fatalf("unknown tool accepted: %v", decoded)
	}
	if called {
		t.Error("backend called for an unknown tool")
	}
}
