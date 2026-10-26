package proxy

// Static upstream headers (upstream.headers) applied to locally derived
// REST→MCP tools, with the same semantics as the external MCP proxy.

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMCPStaticHeadersReachLocalTools(t *testing.T) {
	var got http.Header
	backend := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			got = r.Header.Clone()
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
			"host": "gram.test", "path": "/mcp",
			"backend": "` + backend.URL + `",
			"auth": {},
			"upstream": {"headers": {
				"X-Api-Key": "s3cret",
				"X-Remove": ""
			}},
			"mcp": {"enabled": true, "path": "/mcp",
				"operations": [{"name":"get_item","operationId":"get_item"}]}
		}, {
			"host": "gram.test", "path": "/*",
			"backend": "` + backend.URL + `",
			"openapi": {"url": "` + openapi.URL + `"}
		}]
	}`
	cfg := loadForTest(t, routesJSON)

	gw, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	gw.setAuthBridgeForTest(bridge.URL)

	_, decoded := postMCP(t, gw,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{
			"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28",
			"io.modelcontextprotocol/clientCapabilities":{}},
			"name":"get_item","arguments":{"id":"42"}}}`,
		map[string]string{
			"Mcp-Protocol-Version": "2026-07-28",
			"Mcp-Method":           "tools/call",
			"Mcp-Name":             "get_item",
		})
	if e, ok := decoded["error"]; ok {
		t.Fatalf("unexpected JSON-RPC error: %v", e)
	}

	if v := got.Get("X-Api-Key"); v != "s3cret" {
		t.Errorf("X-Api-Key = %q, want the static header", v)
	}
	if v := got.Get("X-Remove"); v != "" {
		t.Errorf("X-Remove = %q, want it removed (empty value)", v)
	}
	if v := got.Get("X-User-Id"); v != "user-1" {
		t.Errorf("X-User-Id = %q, want the gateway identity", v)
	}
}
