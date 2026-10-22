package proxy

// External MCP proxy (mcp.upstream).
//
// Gate One stays the authenticated MCP endpoint: it verifies the
// client's Gate One token, fetches the per-user upstream token from
// the broker, then transparently proxies the Streamable HTTP exchange
// to an external MCP server. The upstream never sees the Gate One
// bearer, cookies or identity headers.
//
// Tool filtering is enforced twice:
//   - tools/list responses are filtered before reaching the client;
//   - tools/call requests naming a hidden tool are answered locally
//     with a JSON-RPC error and never reach the upstream.
//
// The proxy is stateless: the upstream session id is relayed through
// the regular Mcp-Session-Id header, so the upstream can keep its own
// session state. This is also what makes per-user credentials safe:
// each request is authorized with the caller's own token.

import (
	"bytes"
	"cladone/gate-one/internal/core"
	mcpserver "cladone/gate-one/internal/mcp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	maxMCPBody = 8 << 20

	// Post requests (including tools/call) must not hold a client
	// forever. GET SSE streams use the client's context instead.
	mcpPostTimeout   = 60 * time.Second
	mcpDeleteTimeout = 15 * time.Second
	maxMCPUPSessions = 10000
)

type mcpUpstream struct {
	endpoint  *url.URL
	client    *http.Client
	filter    *core.MCPToolFilter
	upstream  *core.UpstreamPolicy
	delegated *core.DelegatedCredentialPolicy

	// sessions binds upstream Mcp-Session-Id values to the Gate One
	// user who created them. A downstream client cannot reuse another
	// user's upstream session by guessing/observing its id.
	mu       sync.Mutex
	sessions map[string]string
}

func newMCPUpstream(route *core.Route) (*mcpUpstream, error) {
	raw := route.MCP.Upstream.URL
	if raw == "" {
		raw = route.Backend
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("mcp.upstream.url %q: invalid URL", raw)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf(
			"mcp.upstream.url %q: scheme must be http or https", raw)
	}
	if u.User != nil {
		return nil, fmt.Errorf(
			"mcp.upstream.url %q: userinfo forbidden", raw)
	}

	return &mcpUpstream{
		endpoint: u,
		client: &http.Client{
			Transport: backendTransport,
			CheckRedirect: func(
				req *http.Request,
				via []*http.Request,
			) error {
				// Never follow a redirect with the delegated
				// Authorization header to another origin.
				return http.ErrUseLastResponse
			},
		},
		filter:    route.MCP.Upstream.Tools,
		upstream:  route.Upstream,
		delegated: route.DelegatedCredentials(),
		sessions:  make(map[string]string),
	}, nil
}

func toolFilterSize(f *core.MCPToolFilter) int {
	if f == nil {
		return 0
	}
	return len(f.Include) + len(f.Exclude)
}

func (p *mcpUpstream) rememberSession(sessionID, userID string) {
	if len(sessionID) > 512 {
		// An upstream session id is an opaque token, not a data
		// channel; refuse to use unbounded memory for it.
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.sessions) >= maxMCPUPSessions {
		// Bounded memory: unknown ids are still passed to the
		// upstream (the source of truth); only the local ownership
		// cache is reset.
		p.sessions = make(map[string]string)
	}
	p.sessions[sessionID] = userID
}

func (p *mcpUpstream) forgetSession(sessionID string) {
	if sessionID == "" {
		return
	}
	p.mu.Lock()
	delete(p.sessions, sessionID)
	p.mu.Unlock()
}

func (p *mcpUpstream) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost, http.MethodGet, http.MethodDelete:
	default:
		w.Header().Set("Allow", "POST, GET, DELETE")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	userID := r.Header.Get("X-User-Id")
	if sid := r.Header.Get("Mcp-Session-Id"); sid != "" && userID != "" {
		p.mu.Lock()
		owner, known := p.sessions[sid]
		p.mu.Unlock()
		if known && owner != userID {
			log.Printf(
				"MCP upstream: session ownership mismatch host=%s",
				r.Host)
			writeMCPProxyError(w, http.StatusForbidden,
				"mcp_session_forbidden")
			return
		}
	}

	var (
		body     []byte
		method   string
		toolName string
		reqID    json.RawMessage
		buffered bool
	)

	if r.Method == http.MethodPost {
		var err error
		body, err = readMCPBody(r.Body)
		if err != nil {
			writeMCPProxyError(w, http.StatusRequestEntityTooLarge,
				"mcp_request_too_large")
			return
		}
		method, toolName, reqID, err = inspectMCPRequest(body)
		if err != nil {
			writeMCPProxyError(w, http.StatusBadRequest,
				"invalid_mcp_request")
			return
		}

		if method == "tools/call" &&
			p.filter != nil && !p.filter.Allows(toolName) {
			log.Printf(
				"MCP upstream: blocked tool=%q host=%s",
				toolName, r.Host)
			writeMCPToolUnavailable(w, reqID)
			return
		}

		buffered = method == "tools/list" &&
			p.filter != nil &&
			(len(p.filter.Include)+len(p.filter.Exclude) > 0)
	}

	ctx := r.Context()
	var cancel context.CancelFunc
	switch r.Method {
	case http.MethodPost:
		ctx, cancel = context.WithTimeout(ctx, mcpPostTimeout)
	case http.MethodDelete:
		ctx, cancel = context.WithTimeout(ctx, mcpDeleteTimeout)
	}
	if cancel != nil {
		defer cancel()
	}

	upReq, err := http.NewRequestWithContext(
		ctx, r.Method, p.endpoint.String(), bytes.NewReader(body))
	if err != nil {
		writeMCPProxyError(w, http.StatusBadGateway,
			"upstream_mcp_unavailable")
		return
	}
	p.copyRequestHeaders(r.Header, upReq.Header)
	// Keep the MCP routing headers consistent with the body that was
	// inspected and filtered. This prevents a client from naming a
	// hidden tool in Mcp-Name while sending an allowed name in the
	// body (or vice versa).
	if method != "" {
		upReq.Header.Set("Mcp-Method", method)
		if method == "tools/call" && toolName != "" {
			upReq.Header.Set("Mcp-Name", toolName)
		} else {
			upReq.Header.Del("Mcp-Name")
		}
	}
	p.applyUpstreamHeaders(upReq, r)

	resp, err := p.client.Do(upReq)
	if err != nil {
		if !errors.Is(err, context.Canceled) {
			log.Printf("MCP upstream: %v", err)
		}
		writeMCPProxyError(w, http.StatusBadGateway,
			"upstream_mcp_unavailable")
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized ||
		resp.StatusCode == http.StatusForbidden {
		_, _ = io.Copy(io.Discard,
			io.LimitReader(resp.Body, 64<<10))
		writeMCPProxyError(w, http.StatusBadGateway,
			"upstream_mcp_authentication_failed")
		return
	}
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		// Never relay an upstream redirect: following it downstream
		// would expose a Gate One bearer to the redirect target, and
		// following it here would carry the delegated credential.
		_, _ = io.Copy(io.Discard,
			io.LimitReader(resp.Body, 64<<10))
		writeMCPProxyError(w, http.StatusBadGateway,
			"upstream_mcp_redirect")
		return
	}

	sessionID := resp.Header.Get("Mcp-Session-Id")
	if sessionID == "" {
		sessionID = r.Header.Get("Mcp-Session-Id")
	}
	if r.Method == http.MethodDelete && resp.StatusCode < 300 {
		p.forgetSession(sessionID)
	} else if sessionID != "" && userID != "" {
		p.rememberSession(sessionID, userID)
	}

	if buffered && resp.StatusCode == http.StatusOK {
		p.writeFilteredList(w, resp)
		return
	}

	p.writeUpstreamResponse(w, resp)
}

func readMCPBody(r io.Reader) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r, maxMCPBody+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxMCPBody {
		return nil, fmt.Errorf("body too large")
	}
	return body, nil
}

// inspectMCPRequest extracts the JSON-RPC method, tool name and id
// from a single request. JSON-RPC batches are refused: MCP does not
// use them, and accepting them would complicate the call-time filter.
func inspectMCPRequest(body []byte) (
	method, toolName string,
	id json.RawMessage,
	err error,
) {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return "", "", nil, nil
	}
	if trimmed[0] == '[' {
		return "", "", nil, fmt.Errorf("batch requests not supported")
	}

	var req struct {
		ID     json.RawMessage `json:"id"`
		Method string          `json:"method"`
		Params struct {
			Name string `json:"name"`
		} `json:"params"`
	}
	if err := json.Unmarshal(trimmed, &req); err != nil {
		return "", "", nil, err
	}
	return req.Method, req.Params.Name, req.ID, nil
}

func (p *mcpUpstream) copyRequestHeaders(src, dst http.Header) {
	for _, name := range []string{
		"Content-Type",
		"Accept",
		"Mcp-Protocol-Version",
		"Mcp-Session-Id",
		"Mcp-Method",
		"Mcp-Name",
		"Last-Event-ID",
	} {
		for _, v := range src.Values(name) {
			dst.Add(name, v)
		}
	}
	// Ask for an uncompressed answer: tools/list must be inspectable
	// (an opaque compressed body could hide tools from the filter).
	dst.Set("Accept-Encoding", "identity")
	dst.Set("User-Agent", "cladone-gate-one-mcp-proxy/1")
}

func (p *mcpUpstream) applyUpstreamHeaders(
	req *http.Request,
	downstream *http.Request,
) {
	if p.upstream != nil {
		for k, v := range p.upstream.Headers {
			if v == "" {
				req.Header.Del(k)
				continue
			}
			req.Header.Set(k, v)
		}
		if p.upstream.HostOverride != "" {
			req.Host = p.upstream.HostOverride
		}
	}

	// The gateway put the broker token in an internal header before
	// calling this handler. The downstream Authorization header was
	// never copied: it is the Gate One bearer.
	if p.delegated != nil {
		if token := downstream.Header.Get(
			mcpserver.DelegatedTokenHeader); token != "" {
			req.Header.Set(
				p.delegated.HeaderValue(),
				p.delegated.PrefixValue()+token,
			)
		}
	}
}

func (p *mcpUpstream) writeFilteredList(
	w http.ResponseWriter,
	resp *http.Response,
) {
	if enc := resp.Header.Get("Content-Encoding"); enc != "" &&
		!strings.EqualFold(enc, "identity") {
		writeMCPProxyError(w, http.StatusBadGateway,
			"upstream_mcp_invalid_response")
		return
	}

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxMCPBody+1))
	if err != nil || len(raw) > maxMCPBody {
		writeMCPProxyError(w, http.StatusBadGateway,
			"upstream_mcp_invalid_response")
		return
	}

	contentType := resp.Header.Get("Content-Type")
	outType := contentType
	var out []byte

	if strings.Contains(strings.ToLower(contentType), "text/event-stream") {
		out, err = filterMCPToolsSSE(raw, p.filter)
	} else {
		var changed bool
		out, changed, err = filterMCPToolsJSON(raw, p.filter)
		if err == nil && changed {
			outType = "application/json"
		}
	}
	if err != nil {
		log.Printf("MCP upstream: tools/list filter: %v", err)
		writeMCPProxyError(w, http.StatusBadGateway,
			"upstream_mcp_invalid_response")
		return
	}

	copyMCPResponseHeaders(w.Header(), resp.Header, false)
	if outType == "" {
		outType = "application/json"
	}
	w.Header().Set("Content-Type", outType)
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(out)
}

func (p *mcpUpstream) writeUpstreamResponse(
	w http.ResponseWriter,
	resp *http.Response,
) {
	copyMCPResponseHeaders(w.Header(), resp.Header, true)
	w.WriteHeader(resp.StatusCode)

	contentType := strings.ToLower(resp.Header.Get("Content-Type"))
	if strings.Contains(contentType, "text/event-stream") {
		fw := &flushWriter{w: w}
		if f, ok := w.(http.Flusher); ok {
			fw.f = f
		}
		_, _ = io.Copy(fw, resp.Body)
		return
	}
	_, _ = io.Copy(w, resp.Body)
}

func copyMCPResponseHeaders(dst, src http.Header, contentLength bool) {
	for _, name := range []string{
		"Content-Type",
		"Content-Encoding",
		"Mcp-Session-Id",
		"Cache-Control",
		"Retry-After",
		"Last-Event-ID",
	} {
		for _, v := range src.Values(name) {
			dst.Add(name, v)
		}
	}
	if contentLength {
		if v := src.Get("Content-Length"); v != "" {
			dst.Set("Content-Length", v)
		}
	}
	dst.Set("Cache-Control", "no-store")
}

type flushWriter struct {
	w http.ResponseWriter
	f http.Flusher
}

func (fw *flushWriter) Write(p []byte) (int, error) {
	n, err := fw.w.Write(p)
	if fw.f != nil {
		fw.f.Flush()
	}
	return n, err
}

func writeMCPProxyError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(`{"error":"` + code + `"}`))
}

func writeMCPToolUnavailable(w http.ResponseWriter, id json.RawMessage) {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"error": map[string]any{
			"code":    -32601,
			"message": "tool not available",
		},
	})
}

// filterMCPToolsJSON removes hidden tools from a JSON-RPC
// tools/list response. It leaves every other message untouched.
func filterMCPToolsJSON(
	raw []byte,
	f *core.MCPToolFilter,
) ([]byte, bool, error) {
	var msg map[string]json.RawMessage
	if err := json.Unmarshal(raw, &msg); err != nil {
		return nil, false, err
	}
	resultRaw, ok := msg["result"]
	if !ok {
		return raw, false, nil
	}
	var result map[string]json.RawMessage
	if err := json.Unmarshal(resultRaw, &result); err != nil {
		return nil, false, err
	}
	toolsRaw, ok := result["tools"]
	if !ok {
		return raw, false, nil
	}
	var tools []json.RawMessage
	if err := json.Unmarshal(toolsRaw, &tools); err != nil {
		return nil, false, err
	}

	filtered := make([]json.RawMessage, 0, len(tools))
	for _, tool := range tools {
		var meta struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal(tool, &meta); err != nil {
			return nil, false, err
		}
		if f.Allows(meta.Name) {
			filtered = append(filtered, tool)
		}
	}

	newTools, err := json.Marshal(filtered)
	if err != nil {
		return nil, false, err
	}
	result["tools"] = newTools
	newResult, err := json.Marshal(result)
	if err != nil {
		return nil, false, err
	}
	msg["result"] = newResult
	out, err := json.Marshal(msg)
	if err != nil {
		return nil, false, err
	}
	return out, true, nil
}

// filterMCPToolsSSE filters tools/list JSON-RPC messages embedded in
// an SSE stream. Other events (notifications, errors) are preserved.
func filterMCPToolsSSE(
	raw []byte,
	f *core.MCPToolFilter,
) ([]byte, error) {
	s := strings.ReplaceAll(string(raw), "\r\n", "\n")
	events := strings.Split(s, "\n\n")

	var out strings.Builder
	for _, event := range events {
		if event == "" {
			continue
		}
		lines := strings.Split(event, "\n")

		var dataLines []int
		var data []string
		for i, line := range lines {
			if !strings.HasPrefix(line, "data:") {
				continue
			}
			dataLines = append(dataLines, i)
			v := strings.TrimPrefix(line, "data:")
			v = strings.TrimPrefix(v, " ")
			data = append(data, v)
		}

		if len(data) > 0 {
			filtered, changed, err := filterMCPToolsJSON(
				[]byte(strings.Join(data, "\n")), f)
			if err != nil {
				// Fail closed: an unparseable tools/list
				// payload could hide tool names from the filter.
				return nil, err
			}
			if changed {
				newLines := make([]string, 0,
					len(lines)-len(dataLines)+1)
				newLines = append(newLines,
					lines[:dataLines[0]]...)
				newLines = append(newLines,
					"data: "+string(filtered))
				last := dataLines[len(dataLines)-1]
				if last+1 < len(lines) {
					newLines = append(newLines, lines[last+1:]...)
				}
				lines = newLines
			}
		}

		out.WriteString(strings.Join(lines, "\n"))
		out.WriteString("\n\n")
	}
	return []byte(out.String()), nil
}
