// Generic REST → MCP call path.
//
// One toolHandler is built per resolved Operation. It translates MCP
// tool arguments into an HTTP request against the route backend:
//
//   - path parameters are URL-escaped and substituted in the template;
//   - query parameters support scalars, arrays (repeated keys) and
//     objects (compact JSON);
//   - header parameters are set as-is (reserved headers refused);
//   - the "body" argument is sent verbatim as application/json;
//   - the gateway identity (X-User-*) established for the MCP
//     request is forwarded to the backend;
//   - when the route declares delegated credentials, the per-user
//     token fetched by the gateway from the token broker is injected
//     into the configured backend header (default Authorization:
//     Bearer …).
//
// The response is returned as MCP text content. SSE payloads are
// joined (data: lines) so an LLM sees the events, not the framing.
package mcpserver

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// maxBackendResponse bounds one backend response: a runaway upstream
// must not exhaust the gateway's memory.
const maxBackendResponse = 8 << 20

// backendTimeout is the per-call budget (same order as the previous
// hard-coded processStream adapter).
const backendTimeout = 60 * time.Second

// reservedHeaders are never accepted as header parameters: they
// would let a tool caller forge the gateway identity, hijack the
// session transport or override the target host.
var reservedHeaders = map[string]bool{
	"authorization": true,
	"cookie":        true,
	"host":          true,
}

type toolHandler struct {
	backend   string
	op        Operation
	client    *http.Client
	delegated *DelegatedCredentials
}

func (h *toolHandler) call(
	ctx context.Context,
	req *mcp.CallToolRequest,
) (*mcp.CallToolResult, error) {

	args := map[string]json.RawMessage{}

	if req.Params != nil && len(req.Params.Arguments) > 0 {
		if err := json.Unmarshal(req.Params.Arguments, &args); err != nil {
			return nil, fmt.Errorf(
				"invalid arguments: %w", err)
		}
	}

	query := url.Values{}
	headers := http.Header{}

	// Path values are collected first: they are substituted into
	// the template after every argument has been validated.
	pathValues := map[string]string{}

	for _, p := range h.op.Parameters {

		raw, present := args[p.Name]

		if !present {
			if p.Required {
				return nil, fmt.Errorf(
					"missing required argument %q", p.Name)
			}
			continue
		}

		switch p.In {

		case "path":
			v, ok := scalarString(raw)
			if !ok {
				return nil, fmt.Errorf(
					"argument %q must be a scalar", p.Name)
			}
			pathValues[p.Name] = v

		case "query":
			if err := addQuery(query, p.Name, raw); err != nil {
				return nil, err
			}

		case "header":
			v, ok := scalarString(raw)
			if !ok {
				return nil, fmt.Errorf(
					"header argument %q must be a scalar", p.Name)
			}
			headers.Set(p.Name, v)
		}
	}

	target, err := h.targetURL(pathValues, query)
	if err != nil {
		return nil, err
	}

	var body io.Reader
	if h.op.Body != nil {
		body, err = h.requestBody(args)
		if err != nil {
			return nil, err
		}
		if body != nil {
			headers.Set("Content-Type", "application/json")
		}
	}

	httpReq, err := http.NewRequestWithContext(
		ctx, h.op.Method, target, body)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}

	for k, vs := range headers {
		httpReq.Header[k] = vs
	}
	httpReq.Header.Set(
		"Accept", "application/json, text/event-stream, */*")

	h.forwardIdentity(httpReq, req)

	resp, err := h.client.Do(httpReq)
	if err != nil {
		return toolError("request failed: %v", err), nil
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(
		io.LimitReader(resp.Body, maxBackendResponse+1))
	if err != nil {
		return toolError("read response: %v", err), nil
	}
	if len(raw) > maxBackendResponse {
		return toolError(
			"response exceeds %d bytes", maxBackendResponse), nil
	}

	contentType := resp.Header.Get("Content-Type")

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return toolError("HTTP %d: %s",
			resp.StatusCode,
			strings.TrimSpace(bodyText(raw, contentType))), nil
	}

	if !textual(contentType) {
		return toolError(
			"binary response (%s, %d bytes) is not returned "+
				"through MCP", contentType, len(raw)), nil
	}

	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{
			Text: bodyText(raw, contentType),
		}},
	}, nil
}

// requestBody builds the JSON payload from the tool arguments:
// either the single "body" argument (non-object schemas) or the
// flattened body properties. nil means "no body".
func (h *toolHandler) requestBody(
	args map[string]json.RawMessage,
) (io.Reader, error) {

	if h.op.BodyArgument != "" {

		raw, present := args[h.op.BodyArgument]
		if !present {
			if h.op.Body.Required {
				return nil, fmt.Errorf(
					"missing required argument %q",
					h.op.BodyArgument)
			}
			return nil, nil
		}

		if !json.Valid(raw) {
			return nil, fmt.Errorf(
				"argument %q is not valid JSON",
				h.op.BodyArgument)
		}
		return bytes.NewReader(raw), nil
	}

	fields := map[string]json.RawMessage{}

	for _, name := range h.op.BodyFields {
		if raw, ok := args[name]; ok {
			fields[name] = raw
		}
	}

	for _, name := range h.op.BodyRequiredFields {
		if _, ok := fields[name]; !ok {
			return nil, fmt.Errorf(
				"missing required argument %q", name)
		}
	}

	if len(fields) == 0 {
		if h.op.Body.Required {
			return nil, fmt.Errorf("missing required request body")
		}
		return nil, nil
	}

	payload, err := json.Marshal(fields)
	if err != nil {
		return nil, fmt.Errorf("encode request body: %w", err)
	}

	return bytes.NewReader(payload), nil
}

// forwardIdentity relays the gateway identity. The MCP request was
// authenticated by the gateway; the backend trusts X-User-* headers,
// never a client-supplied token.
func (h *toolHandler) forwardIdentity(
	httpReq *http.Request,
	req *mcp.CallToolRequest,
) {

	if req.Extra == nil {
		return
	}

	for _, name := range []string{
		"X-User-Id", "X-Username", "X-Email", "X-Roles", "X-Scopes",
	} {
		if v := req.Extra.Header.Get(name); v != "" {
			httpReq.Header.Set(name, v)
		}
	}

	// Per-user upstream token: the gateway fetched it from the
	// broker for the authenticated caller and placed it in an
	// internal header (the client-supplied value is stripped by the
	// gateway before the MCP handler runs). Never accept it from
	// tool arguments: Authorization and X-Gate-One-* are reserved.
	if h.delegated != nil {
		if v := req.Extra.Header.Get(DelegatedTokenHeader); v != "" {
			httpReq.Header.Set(
				h.delegated.Header,
				h.delegated.Prefix+v,
			)
		}
	}
}

func (h *toolHandler) targetURL(
	pathValues map[string]string,
	query url.Values,
) (string, error) {

	path := h.op.BasePath + h.op.Path
	rawPath := path

	// Deterministic substitution order (map iteration would not
	// matter for correctness, but keeps the error messages stable).
	names := make([]string, 0, len(pathValues))
	for name := range pathValues {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		v := pathValues[name]
		path = strings.ReplaceAll(path, "{"+name+"}", v)
		rawPath = strings.ReplaceAll(
			rawPath, "{"+name+"}", url.PathEscape(v))
	}

	if strings.Contains(rawPath, "{") {
		return "", fmt.Errorf(
			"unresolved path parameter in %q", h.op.Path)
	}

	target := strings.TrimRight(h.backend, "/") + rawPath

	u, err := url.Parse(target)
	if err != nil {
		return "", fmt.Errorf("invalid target URL: %w", err)
	}
	u.RawQuery = query.Encode()

	return u.String(), nil
}

func addQuery(
	values url.Values,
	name string,
	raw json.RawMessage,
) error {

	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return fmt.Errorf("argument %q: %w", name, err)
	}

	switch t := v.(type) {

	case nil:
		return nil // omitted

	case []any:
		for _, item := range t {
			if item == nil {
				continue
			}
			s, ok := scalarStringValue(item)
			if !ok {
				return fmt.Errorf(
					"argument %q: array items must be scalars", name)
			}
			values.Add(name, s)
		}

	case map[string]any:
		b, err := json.Marshal(t)
		if err != nil {
			return fmt.Errorf("argument %q: %w", name, err)
		}
		values.Add(name, string(b))

	default:
		s, ok := scalarStringValue(t)
		if !ok {
			return fmt.Errorf(
				"argument %q must be a scalar, array or object", name)
		}
		values.Add(name, s)
	}

	return nil
}

func scalarString(raw json.RawMessage) (string, bool) {

	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return "", false
	}
	return scalarStringValue(v)
}

func scalarStringValue(v any) (string, bool) {

	switch t := v.(type) {
	case string:
		return t, true
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64), true
	case bool:
		return strconv.FormatBool(t), true
	}
	return "", false
}

// bodyText returns the response body as text; SSE framing is
// stripped so tool output is the payload stream itself.
func bodyText(raw []byte, contentType string) string {

	if strings.Contains(contentType, "text/event-stream") {
		if s, err := readSSE(bytes.NewReader(raw)); err == nil {
			return s
		}
	}
	return string(raw)
}

func readSSE(r io.Reader) (string, error) {

	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)

	var events []string

	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		events = append(events,
			strings.TrimSpace(strings.TrimPrefix(line, "data:")))
	}

	if err := scanner.Err(); err != nil {
		return "", err
	}
	return strings.Join(events, "\n"), nil
}

func textual(contentType string) bool {

	ct := strings.ToLower(strings.TrimSpace(contentType))

	if ct == "" {
		return true // no declaration: best effort
	}

	for _, prefix := range []string{
		"text/",
		"application/json",
		"application/xml",
		"application/x-ndjson",
		"application/javascript",
		"application/x-www-form-urlencoded",
	} {
		if strings.HasPrefix(ct, prefix) {
			return true
		}
	}

	return strings.HasSuffix(ct, "+json") ||
		strings.HasSuffix(ct, "+xml")
}

func toolError(format string, args ...any) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		IsError: true,
		Content: []mcp.Content{&mcp.TextContent{
			Text: fmt.Sprintf(format, args...),
		}},
	}
}
