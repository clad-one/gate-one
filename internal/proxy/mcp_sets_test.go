package proxy

// Tests du modèle « services + ensembles » : chaque unité d'accès
// (service autonome ou mcpSet) porte sa propre audience/scope, les
// membres d'un ensemble sont filtrés, un service non autonome n'est
// pas exposé directement.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type unitCall struct {
	resource string
	scope    string
}

// newMCPSetsGateway builds a gateway with:
//   - a standalone service "github" (own resource/scope);
//   - a service "gitlab" that is NOT standalone;
//   - a set "git-read" mounting both, with its own resource/scope and
//     an identity condition.
//
// The auth-bridge stub records X-MCP-Resource / X-MCP-Scope and
// answers 401 (challenge).
func newMCPSetsGateway(t *testing.T) (*Gateway, *[]unitCall) {
	t.Helper()

	var calls []unitCall
	bridge := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			calls = append(calls, unitCall{
				resource: r.Header.Get("X-MCP-Resource"),
				scope:    r.Header.Get("X-MCP-Scope"),
			})
			w.WriteHeader(http.StatusUnauthorized)
		},
	))
	t.Cleanup(bridge.Close)

	routesJSON := `{
		"routes": [
			{
				"host": "svc.test", "path": "/github",
				"backend": "http://backend.test", "auth": {},
				"mcp": {"enabled": true, "name": "github",
					"resource": "https://svc.test/github",
					"scope": "svc-scope"}
			},
			{
				"host": "svc.test", "path": "/gitlab",
				"backend": "http://backend.test",
				"mcp": {"enabled": true, "name": "gitlab",
					"standalone": false}
			}
		],
		"mcpSets": {
			"git-read": {
				"host": "mcp.test", "endpoint": "/git-read",
				"resource": "https://mcp.test/git-read",
				"scope": "set-scope",
				"identity": {"roles": ["user"]},
				"members": [
					{"service": "github", "path": "/github"},
					{"service": "gitlab", "path": "/gitlab",
					 "tools": ["list_*"]}
				]
			}
		}
	}`

	cfg := loadForTest(t, routesJSON)

	gw, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	gw.authBridgeBaseURL = bridge.URL

	return gw, &calls
}

func TestMCPSetMemberUsesSetUnit(t *testing.T) {
	gw, calls := newMCPSetsGateway(t)

	resp := doGet(t, gw, "mcp.test", "/git-read/github")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}

	wwwAuth := resp.Header.Get("WWW-Authenticate")
	if !strings.Contains(wwwAuth, `scope="set-scope"`) {
		t.Errorf("challenge = %q, want scope=set-scope", wwwAuth)
	}
	if !strings.Contains(wwwAuth,
		`resource_metadata="https://mcp.test/.well-known/oauth-protected-resource/git-read"`) {
		t.Errorf("challenge = %q, want the set metadata URL", wwwAuth)
	}

	if len(*calls) != 1 {
		t.Fatalf("auth-bridge calls = %d, want 1", len(*calls))
	}
	c := (*calls)[0]
	if c.resource != "https://mcp.test/git-read" {
		t.Errorf("X-MCP-Resource = %q, want the set resource", c.resource)
	}
	if c.scope != "set-scope" {
		t.Errorf("X-MCP-Scope = %q, want set-scope", c.scope)
	}
}

func TestMCPStandaloneServiceKeepsItsOwnUnit(t *testing.T) {
	gw, calls := newMCPSetsGateway(t)

	resp := doGet(t, gw, "svc.test", "/github")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}

	wwwAuth := resp.Header.Get("WWW-Authenticate")
	if !strings.Contains(wwwAuth,
		`resource_metadata="https://svc.test/.well-known/oauth-protected-resource/github"`) {
		t.Errorf("challenge = %q, want the service metadata URL", wwwAuth)
	}

	c := (*calls)[0]
	if c.resource != "https://svc.test/github" || c.scope != "svc-scope" {
		t.Errorf("unit = %q/%q, want the service unit", c.resource, c.scope)
	}
}

func TestMCPNonStandaloneServiceIsNotDirectlyServed(t *testing.T) {
	gw, _ := newMCPSetsGateway(t)

	resp := doGet(t, gw, "svc.test", "/gitlab")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (service exposed only via its set)",
			resp.StatusCode)
	}

	// …but it is served under the set.
	resp = doGet(t, gw, "mcp.test", "/git-read/gitlab")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("set member status = %d, want 401", resp.StatusCode)
	}
}

func TestMCPMetadataPerUnit(t *testing.T) {
	gw, _ := newMCPSetsGateway(t)

	check := func(host, path, wantResource, wantScope string) {
		t.Helper()
		resp := doGet(t, gw, host, path)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s%s status = %d", host, path, resp.StatusCode)
		}
		var md struct {
			Resource string   `json:"resource"`
			Scopes   []string `json:"scopes_supported"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&md); err != nil {
			t.Fatal(err)
		}
		if md.Resource != wantResource {
			t.Errorf("%s%s resource = %q, want %q",
				host, path, md.Resource, wantResource)
		}
		if len(md.Scopes) != 1 || md.Scopes[0] != wantScope {
			t.Errorf("%s%s scopes = %v, want [%s]",
				host, path, md.Scopes, wantScope)
		}
	}

	check("mcp.test", "/.well-known/oauth-protected-resource/git-read",
		"https://mcp.test/git-read", "set-scope")
	check("svc.test", "/.well-known/oauth-protected-resource/github",
		"https://svc.test/github", "svc-scope")
	// origin form (compatibility): first unit of the host
	check("mcp.test", "/.well-known/oauth-protected-resource",
		"https://mcp.test/git-read", "set-scope")
}

// --- per-member tool filtering on a locally derived service ---

const setsOpenAPIDoc = `{
  "openapi": "3.0.0",
  "info": {"title": "t", "version": "1"},
  "paths": {
    "/items": {
      "get": {"operationId": "list_items",
        "responses": {"200": {"description": "ok"}}}
    },
    "/items/{id}": {
      "get": {"operationId": "get_item",
        "parameters": [{"name": "id", "in": "path",
          "required": true, "schema": {"type": "string"}}],
        "responses": {"200": {"description": "ok"}}}
    }
  }
}`

func newMCPSetFilterGateway(t *testing.T) *Gateway {
	t.Helper()

	backend := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"ok":true}`))
		},
	))
	t.Cleanup(backend.Close)

	openapi := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(setsOpenAPIDoc))
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
		"routes": [
			{
				"host": "mcp.test", "path": "/filtered",
				"backend": "` + backend.URL + `",
				"mcp": {"enabled": true, "name": "tools",
					"standalone": false,
					"operations": [
						{"name": "get_item", "operationId": "get_item"},
						{"name": "list_items", "operationId": "list_items"}
					]}
			},
			{
				"host": "mcp.test", "path": "/*",
				"backend": "` + backend.URL + `",
				"openapi": {"url": "` + openapi.URL + `"}
			}
		],
		"mcpSets": {
			"filtered": {
				"host": "mcp.test", "endpoint": "/filtered",
				"resource": "https://mcp.test/filtered",
				"scope": "mcp-tools",
				"members": [
					{"service": "tools", "path": "/", "tools": ["get_*"]}
				]
			}
		}
	}`

	cfg := loadForTest(t, routesJSON)

	gw, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	gw.authBridgeBaseURL = bridge.URL

	return gw
}

func postMCPAt(
	t *testing.T,
	gw *Gateway,
	host, path, body string,
	headers map[string]string,
) map[string]any {
	t.Helper()

	req := httptest.NewRequest(
		http.MethodPost, "http://"+host+path, strings.NewReader(body))
	req.Host = host
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK && rec.Code != http.StatusAccepted &&
		rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}

	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v (%s)", err, rec.Body.String())
	}
	return out
}

func TestMCPSetMemberFiltersLocalTools(t *testing.T) {
	gw := newMCPSetFilterGateway(t)

	decoded := postMCPAt(t, gw, "mcp.test", "/filtered",
		`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{`+
			`"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28",`+
			`"io.modelcontextprotocol/clientCapabilities":{}}}}`,
		map[string]string{
			"Mcp-Protocol-Version": "2026-07-28",
			"Mcp-Method":           "tools/list",
		})

	raw, _ := json.Marshal(decoded)
	s := string(raw)
	if !strings.Contains(s, "get_item") {
		t.Errorf("allowed tool missing: %s", s)
	}
	if strings.Contains(s, "list_items") {
		t.Errorf("hidden tool leaked: %s", s)
	}
}

func TestMCPSetMemberHidesToolAtCallTime(t *testing.T) {
	gw := newMCPSetFilterGateway(t)

	decoded := postMCPAt(t, gw, "mcp.test", "/filtered",
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{`+
			`"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28",`+
			`"io.modelcontextprotocol/clientCapabilities":{}},`+
			`"name":"list_items","arguments":{}}}`,
		map[string]string{
			"Mcp-Protocol-Version": "2026-07-28",
			"Mcp-Method":           "tools/call",
			"Mcp-Name":             "list_items",
		})

	raw, _ := json.Marshal(decoded)
	s := string(raw)
	if !strings.Contains(s, "error") &&
		!strings.Contains(s, "unknown tool") {
		t.Errorf("hidden tool call was not refused: %s", s)
	}
}
