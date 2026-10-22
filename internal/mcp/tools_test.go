package mcpserver

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// callTool invokes h.call the way the SDK does (raw arguments).
func callTool(
	t *testing.T,
	h *toolHandler,
	arguments string,
	headers http.Header,
) (*mcp.CallToolResult, error) {
	t.Helper()

	return h.call(context.Background(), &mcp.CallToolRequest{
		Params: &mcp.CallToolParamsRaw{
			Name:      h.op.Name,
			Arguments: json.RawMessage(arguments),
		},
		Extra: &mcp.RequestExtra{Header: headers},
	})
}

// TestCallPathQueryHeader: path parameters are escaped, arrays
// become repeated query keys, objects compact JSON, header
// parameters are set and the gateway identity is forwarded.
func TestCallPathQueryHeader(t *testing.T) {
	var seenPath, seenQuery string
	var seenTenant, seenUser string

	backend := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			seenPath = r.URL.EscapedPath()
			seenQuery = r.URL.RawQuery
			seenTenant = r.Header.Get("X-Tenant")
			seenUser = r.Header.Get("X-User-Id")
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"ok":true}`)
		},
	))
	t.Cleanup(backend.Close)

	h := &toolHandler{
		backend: backend.URL,
		op: Operation{
			Name:     "lookup",
			Method:   "GET",
			Path:     "/items/{id}",
			BasePath: "/v1",
			Parameters: []Parameter{
				{Name: "id", In: "path", Required: true},
				{Name: "tag", In: "query"},
				{Name: "filter", In: "query"},
				{Name: "X-Tenant", In: "header"},
			},
		},
		client: backend.Client(),
	}

	res, err := callTool(t, h,
		`{"id":"a/b","tag":["x","y"],
		  "filter":{"kind":"book"},"X-Tenant":"t1"}`,
		http.Header{"X-User-Id": {"user-1"}})
	if err != nil {
		t.Fatalf("call: %v", err)
	}

	if seenPath != "/v1/items/a%2Fb" {
		t.Errorf("path = %q, want /v1/items/a%%2Fb", seenPath)
	}
	if !strings.Contains(seenQuery, "tag=x&tag=y") {
		t.Errorf("query = %q, want repeated tag", seenQuery)
	}
	if !strings.Contains(seenQuery,
		"filter=%7B%22kind%22%3A%22book%22%7D") {
		t.Errorf("query = %q, want JSON-encoded object", seenQuery)
	}
	if seenTenant != "t1" {
		t.Errorf("X-Tenant = %q", seenTenant)
	}
	if seenUser != "user-1" {
		t.Errorf("X-User-Id = %q, want forwarded identity", seenUser)
	}

	if res.IsError {
		t.Fatalf("unexpected tool error: %+v", res.Content)
	}
	if got := textContent(t, res); got != `{"ok":true}` {
		t.Errorf("result = %q", got)
	}
}

// TestCallBody: the "body" argument is forwarded verbatim as
// application/json; a missing required body is a protocol error.
func TestCallBody(t *testing.T) {
	var seenMethod, seenBody, seenType string

	backend := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			b, _ := io.ReadAll(r.Body)
			seenMethod = r.Method
			seenBody = string(b)
			seenType = r.Header.Get("Content-Type")
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"created":1}`)
		},
	))
	t.Cleanup(backend.Close)

	h := &toolHandler{
		backend: backend.URL,
		op: Operation{
			Name:         "create",
			Method:       "POST",
			Path:         "/items",
			Body:         &Body{Required: true},
			BodyArgument: "body",
		},
		client: backend.Client(),
	}

	if _, err := callTool(t, h, `{}`, nil); err == nil {
		t.Fatal("missing required body: expected an error")
	}

	if _, err := callTool(t, h, `{"body":{"name":"x"}}`, nil); err != nil {
		t.Fatalf("call: %v", err)
	}

	if seenMethod != "POST" {
		t.Errorf("method = %q", seenMethod)
	}
	if seenBody != `{"name":"x"}` {
		t.Errorf("body = %q", seenBody)
	}
	if seenType != "application/json" {
		t.Errorf("Content-Type = %q", seenType)
	}
}

// TestCallSSE: an event-stream response is joined into plain text.
func TestCallSSE(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = io.WriteString(w,
				"data: {\"chunk\":1}\n\ndata: {\"chunk\":2}\n\n")
		},
	))
	t.Cleanup(backend.Close)

	h := &toolHandler{
		backend: backend.URL,
		op:      Operation{Name: "stream", Method: "GET", Path: "/s"},
		client:  backend.Client(),
	}

	res, err := callTool(t, h, `{}`, nil)
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	want := "{\"chunk\":1}\n{\"chunk\":2}"
	if got := textContent(t, res); got != want {
		t.Errorf("text = %q, want %q", got, want)
	}
}

// TestCallBackendError: a non-2xx answer is an MCP tool error whose
// text carries the status and body (not a protocol error).
func TestCallBackendError(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = io.WriteString(w, `{"error":"boom"}`)
		},
	))
	t.Cleanup(backend.Close)

	h := &toolHandler{
		backend: backend.URL,
		op:      Operation{Name: "fail", Method: "GET", Path: "/x"},
		client:  backend.Client(),
	}

	res, err := callTool(t, h, `{}`, nil)
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	if !res.IsError {
		t.Fatal("IsError = false, want true")
	}
	if got := textContent(t, res); !strings.Contains(got, "HTTP 500") ||
		!strings.Contains(got, "boom") {
		t.Errorf("error text = %q", got)
	}
}

// TestCallBinary: binary responses are refused instead of being
// decoded as text.
func TestCallBinary(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "image/png")
			_, _ = w.Write([]byte{0x89, 0x50, 0x4e, 0x47})
		},
	))
	t.Cleanup(backend.Close)

	h := &toolHandler{
		backend: backend.URL,
		op:      Operation{Name: "img", Method: "GET", Path: "/i"},
		client:  backend.Client(),
	}

	res, err := callTool(t, h, `{}`, nil)
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	if !res.IsError || !strings.Contains(textContent(t, res), "binary") {
		t.Errorf("binary response not refused: %+v", res)
	}
}

func textContent(t *testing.T, res *mcp.CallToolResult) string {
	t.Helper()
	if len(res.Content) != 1 {
		t.Fatalf("content entries = %d, want 1", len(res.Content))
	}
	tc, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("content type = %T, want *TextContent", res.Content[0])
	}
	return tc.Text
}

// TestCallFlattenedBody: when the request body is flattened, the
// declared body fields are regrouped into one JSON object and the
// required ones are enforced.
func TestCallFlattenedBody(t *testing.T) {
	var seenBody string

	backend := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			b, _ := io.ReadAll(r.Body)
			seenBody = string(b)
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"ok":true}`)
		},
	))
	t.Cleanup(backend.Close)

	h := &toolHandler{
		backend: backend.URL,
		op: Operation{
			Name:               "process",
			Method:             "POST",
			Path:               "/process",
			Body:               &Body{Required: true},
			BodyFields:         []string{"mode", "text"},
			BodyRequiredFields: []string{"text"},
		},
		client: backend.Client(),
	}

	if _, err := callTool(t, h, `{"mode":"x"}`, nil); err == nil ||
		!strings.Contains(err.Error(), "text") {
		t.Fatalf("missing required body field error = %v", err)
	}

	if _, err := callTool(t, h,
		`{"text":"bonjour","mode":"sentence"}`, nil); err != nil {
		t.Fatalf("call: %v", err)
	}

	// Deterministic JSON (map keys sorted by encoding/json).
	if seenBody != `{"mode":"sentence","text":"bonjour"}` {
		t.Errorf("body = %q", seenBody)
	}
}
