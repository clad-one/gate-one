// MCP server construction.
//
// The set of tools is entirely derived from the route's mcp policy
// (operations) and the upstream OpenAPI document — see openapi.go.
// Behaviour notes live in tools.go.
package mcpserver

import (
	"net/http"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type Server struct {
	HTTPHandler http.Handler
}

// DelegatedTokenHeader is set by the gateway (never by the MCP
// client) on the MCP HTTP request after it obtained the user's
// upstream token from the broker. The tool handler relays its value
// to the backend under DelegatedCredentials.Header.
const DelegatedTokenHeader = "X-Gate-One-Delegated-Token"

// DelegatedCredentials describes how the gateway injects the
// per-user backend token into REST calls produced by tools/call.
// nil = no delegated credentials on this route.
type DelegatedCredentials struct {
	Header string
	Prefix string
}

// StaticUpstream: static headers (and optional Host override) sent to
// the backend on every tool call. Values are already resolved at load
// (${VAR}); an empty value removes the header.
type StaticUpstream struct {
	Headers      map[string]string
	HostOverride string
}

// New builds the MCP server for one route. ops is the resolved
// operation list (may be empty: the server then exposes no tool, but
// still answers initialize/tools/list).
func New(
	backend string,
	ops []Operation,
	delegated *DelegatedCredentials,
	static *StaticUpstream,
) *Server {

	server := mcp.NewServer(
		&mcp.Implementation{
			Name:    "cladone-gate-one",
			Version: "0.1.0",
		},
		nil,
	)

	client := &http.Client{Timeout: backendTimeout}
	backend = strings.TrimRight(backend, "/")

	for i := range ops {
		h := &toolHandler{
			backend:   backend,
			op:        ops[i],
			client:    client,
			delegated: delegated,
			static:    static,
		}

		server.AddTool(
			&mcp.Tool{
				Name:        ops[i].Name,
				Description: ops[i].Description,
				InputSchema: ops[i].InputSchema,
			},
			h.call,
		)
	}

	handler := mcp.NewStreamableHTTPHandler(
		func(*http.Request) *mcp.Server {
			return server
		},
		&mcp.StreamableHTTPOptions{
			// Stateless: each request is independent (no session
			// state to keep between calls).
			Stateless: true,

			// JSON responses: easier to inspect and to test with
			// curl.
			JSONResponse: true,

			// The SDK refuses non-loopback Host headers when the
			// TCP connection's local address is loopback (DNS
			// rebinding guard for a local server). Gate One is a
			// reverse proxy: its Host is a public vhost by design
			// and every route is matched (and authenticated) on
			// it — unknown hosts never reach the MCP handler.
			DisableLocalhostProtection: true,
		},
	)

	return &Server{
		HTTPHandler: handler,
	}
}
