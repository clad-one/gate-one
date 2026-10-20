package mcpserver

import (
	"net/http"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type Server struct {
	HTTPHandler http.Handler
}

func New(
	backend string,
) *Server {

	server := mcp.NewServer(
		&mcp.Implementation{
			Name:    "cladone-gate-one",
			Version: "0.1.0",
		},
		nil,
	)

	process := NewProcessStreamServer(
		backend,
	)

	mcp.AddTool(
		server,
		&mcp.Tool{
			Name:        "processStream",
			Description: "Process French text and stream the processing results.",
		},
		process.Tool,
	)

	handler := mcp.NewStreamableHTTPHandler(
		func(*http.Request) *mcp.Server {
			return server
		},
		&mcp.StreamableHTTPOptions{
			// Important for this first version:
			// each request is independent.
			Stateless: true,

			// Easier to test with curl.
			JSONResponse: true,
		},
	)

	return &Server{
		HTTPHandler: handler,
	}
}
