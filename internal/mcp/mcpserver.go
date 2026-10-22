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

// New builds the MCP server for one route. ops is the resolved
// operation list (may be empty: the server then exposes no tool, but
// still answers initialize/tools/list).
func New(
	backend string,
	ops []Operation,
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
			backend: backend,
			op:      ops[i],
			client:  client,
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
