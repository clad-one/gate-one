package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

type RequestContext struct {
	Host   string
	Path   string
	Method string

	Query   map[string]string
	Headers map[string]string
	Body    map[string]any
	RawBody []byte

	UserID    string
	SessionID string
	Username  string
	Email     string
	Roles     []string
	Scopes    []string
	Claims    map[string]any
}

// HasRole / HasScope / HasClaim: helpers matching the identity
// conditions (evaluated AFTER authentication — see matchesIdentity).

func (ctx *RequestContext) HasScope(scope string) bool {
	for _, s := range ctx.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}

// HasClaim checks the presence of a claim ("*" = any value) or the
// equality of its stringified value (JSON boolean → "true"/"false",
// numbers → Go format).
func (ctx *RequestContext) HasClaim(key, want string) bool {
	v, ok := ctx.Claims[key]
	if !ok {
		return false
	}
	if want == "*" {
		return true
	}
	return fmt.Sprintf("%v", v) == want
}

func BuildContext(r *http.Request) (*RequestContext, error) {

	ctx := &RequestContext{
		Host:    r.Host,
		Path:    r.URL.Path,
		Method:  r.Method,
		Query:   map[string]string{},
		Headers: map[string]string{},
		Body:    map[string]any{},
	}

	for k := range r.URL.Query() {
		ctx.Query[k] = r.URL.Query().Get(k)
	}

	for k := range r.Header {
		ctx.Headers[k] = r.Header.Get(k)
	}

	if r.Body != nil {

		data, err := io.ReadAll(r.Body)
		if err != nil {
			return nil, err
		}

		// IMPORTANT: restore ORIGINAL body (not reread)
		r.Body = io.NopCloser(bytes.NewBuffer(data))

		ctx.RawBody = data
		// optional JSON parse (safe copy)
		if len(data) > 0 && json.Valid(data) {
			_ = json.Unmarshal(data, &ctx.Body)
		}
	}

	return ctx, nil
}
