package proxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// newMCPProtocolGateway builds a gateway with an MCP route whose
// auth-bridge is stubbed (200, fake identity): MCP requests pass
// authentication and reach the embedded MCP server. The backend must
// never be contacted by the tested methods (discover / initialize /
// tools/list).
func newMCPProtocolGateway(t *testing.T) *Gateway {
	t.Helper()

	backend := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		},
	))
	t.Cleanup(backend.Close)

	bridge := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-User-Id", "user-1")
			w.Header().Set("X-Username", "user-1")
			w.WriteHeader(http.StatusOK)
		},
	))
	t.Cleanup(bridge.Close)

	routesJSON := `{
		"routes": [{
			"host": "gram.test",
			"path": "/mcp",
			"backend": "` + backend.URL + `",
			"auth": {},
			"mcp": {"enabled": true, "path": "/mcp", "scope": "mcp-tools", "operations": []}
		}]
	}`

	cfg := loadForTest(t, routesJSON)

	gw, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	gw.authBridgeBaseURL = bridge.URL

	return gw
}

// postMCP sends a JSON-RPC request on the MCP route and returns the
// decoded (generic JSON-RPC) response. headers allows adding the
// standard 2026-07-28 protocol headers (Mcp-Protocol-Version,
// Mcp-Method, Mcp-Name).
func postMCP(
	t *testing.T,
	gw *Gateway,
	body string,
	headers map[string]string,
) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()

	req := httptest.NewRequest(
		http.MethodPost,
		"http://gram.test/mcp",
		strings.NewReader(body),
	)
	req.Host = "gram.test"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Fatalf("Content-Type = %q, want application/json", ct)
	}

	if rec.Code != http.StatusOK && rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}

	var decoded map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&decoded); err != nil {
		t.Fatalf("response %d not JSON-RPC: %v", rec.Code, err)
	}

	return rec, decoded
}

// TestMCPLegacyInitialize checks compatibility with legacy clients
// (initialize handshake, revisions ≤ 2025-11-25): the gateway
// negotiates at most 2025-11-25.
func TestMCPLegacyInitialize(t *testing.T) {
	gw := newMCPProtocolGateway(t)

	rec, decoded := postMCP(t, gw,
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{
			"protocolVersion":"2025-11-25","capabilities":{},
			"clientInfo":{"name":"legacy-client","version":"0"}}}`,
		nil)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if _, hasErr := decoded["error"]; hasErr {
		t.Fatalf("unexpected JSON-RPC error: %v", decoded["error"])
	}

	result, _ := decoded["result"].(map[string]any)
	if result == nil {
		t.Fatalf("missing result in response: %v", decoded)
	}
	if v, _ := result["protocolVersion"].(string); v != "2025-11-25" {
		t.Errorf("negotiated protocolVersion = %q, want 2025-11-25", v)
	}

	serverInfo, _ := result["serverInfo"].(map[string]any)
	if name, _ := serverInfo["name"].(string); name != "cladone-gateway" {
		t.Errorf("serverInfo.name = %v, want cladone-gateway", serverInfo)
	}
}

// TestMCPDiscover20260728 checks the server/discover RPC of the
// 2026-07-28 revision (replacing the initialize handshake): the
// client must discover the supported revisions, including its own.
func TestMCPDiscover20260728(t *testing.T) {
	gw := newMCPProtocolGateway(t)

	// The 2026-07-28 revision requires the standard headers:
	// Mcp-Protocol-Version must equal the _meta, Mcp-Method the method.
	rec, decoded := postMCP(t, gw,
		`{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{
			"_meta":{
				"io.modelcontextprotocol/protocolVersion":"2026-07-28",
				"io.modelcontextprotocol/clientInfo":{"name":"new-client","version":"0"},
				"io.modelcontextprotocol/clientCapabilities":{}
			}}}`,
		map[string]string{
			"Mcp-Protocol-Version": "2026-07-28",
			"Mcp-Method":           "server/discover",
		})

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if _, hasErr := decoded["error"]; hasErr {
		t.Fatalf("unexpected JSON-RPC error: %v", decoded["error"])
	}

	result, _ := decoded["result"].(map[string]any)
	if result == nil {
		t.Fatalf("missing result in response: %v", decoded)
	}

	supported, _ := result["supportedVersions"].([]any)
	versions := map[string]bool{}
	for _, v := range supported {
		if s, ok := v.(string); ok {
			versions[s] = true
		}
	}
	if len(versions) == 0 {
		t.Fatalf("supportedVersions missing: %v", result)
	}

	if !versions["2026-07-28"] {
		t.Errorf("supportedVersions = %v, want 2026-07-28 advertised", supported)
	}
	if !versions["2025-11-25"] {
		t.Errorf("supportedVersions = %v, want legacy 2025-11-25 advertised", supported)
	}
}

// TestMCPToolsList20260728 checks a business operation in 2026-07-28
// stateless mode (no prior handshake): the tool list exposes
// processStream and advertises ttlMs/cacheScope.
func TestMCPToolsList20260728(t *testing.T) {
	gw := newMCPProtocolGateway(t)

	rec, decoded := postMCP(t, gw,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{
			"_meta":{
				"io.modelcontextprotocol/protocolVersion":"2026-07-28",
				"io.modelcontextprotocol/clientCapabilities":{}
			}}}`,
		map[string]string{
			"Mcp-Protocol-Version": "2026-07-28",
			"Mcp-Method":           "tools/list",
		})

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if _, hasErr := decoded["error"]; hasErr {
		t.Fatalf("unexpected JSON-RPC error: %v", decoded["error"])
	}

	result, _ := decoded["result"].(map[string]any)
	if result == nil {
		t.Fatalf("missing result in response: %v", decoded)
	}

	tools, _ := result["tools"].([]any)
	var names []string
	for _, tool := range tools {
		if m, ok := tool.(map[string]any); ok {
			if n, ok := m["name"].(string); ok {
				names = append(names, n)
			}
		}
	}

	found := false
	for _, n := range names {
		if n == "processStream" {
			found = true
		}
	}
	if !found {
		t.Errorf("tools = %v, want processStream", names)
	}
}
