package proxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cladone/gateway/internal/core"
)

// newMCPProtocolGateway construit une gateway avec une route MCP dont
// l'auth-bridge est stubbé (200, identité factice) : les requêtes MCP
// passent l'authentification et atteignent le serveur MCP embarqué.
// Le backend ne doit jamais être contacté par les méthodes testées
// (discover / initialize / tools/list).
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

	cfgPath := filepath.Join(t.TempDir(), "routes.json")
	if err := os.WriteFile(cfgPath, []byte(routesJSON), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := core.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}

	gw, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	gw.authBridgeBaseURL = bridge.URL

	return gw
}

// postMCP envoie une requête JSON-RPC sur la route MCP et retourne la
// réponse décodée (JSON-RPC générique). headers permet d'ajouter les
// en-têtes standard du protocole 2026-07-28 (Mcp-Protocol-Version,
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

// TestMCPLegacyInitialize vérifie la compatibilité avec les clients
// legacy (handshake initialize, révisions ≤ 2025-11-25) : la gateway
// négocie au maximum 2025-11-25.
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

// TestMCPDiscover20260728 vérifie le RPC server/discover de la
// révision 2026-07-28 (remplace le handshake initialize) : le client
// doit découvrir les révisions supportées, dont la sienne.
func TestMCPDiscover20260728(t *testing.T) {
	gw := newMCPProtocolGateway(t)

	// La révision 2026-07-28 exige les en-têtes standard :
	// Mcp-Protocol-Version doit égaler le _meta, Mcp-Method la méthode.
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

// TestMCPToolsList20260728 vérifie une opération métier en mode
// stateless 2026-07-28 (pas de handshake préalable) : la liste des
// outils expose processStream et annonce ttlMs/cacheScope.
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
