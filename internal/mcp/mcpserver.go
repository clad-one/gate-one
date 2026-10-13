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
			Name:    "cladone-gateway",
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
			// Important pour cette première version :
			// chaque requête est indépendante.
			Stateless: true,

			// Plus facile à tester avec curl.
			JSONResponse: true,
		},
	)

	return &Server{
		HTTPHandler: handler,
	}
}
