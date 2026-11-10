package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
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
	IssuedAt  time.Time
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

// HasClaim checks a claim condition: the claim must be present, then
// ANY of the accepted values must match. "*" means "present, any
// value". A stringified comparison is used for scalars (JSON boolean →
// "true"/"false", numbers → Go format); an array-valued claim (groups,
// roles in a token…) matches when one of its elements matches.
func (ctx *RequestContext) HasClaim(key string, wants []string) bool {
	v, ok := ctx.Claims[key]
	if !ok || len(wants) == 0 {
		return false
	}
	for _, want := range wants {
		if want == "*" {
			return true
		}
		if claimValueMatches(v, want) {
			return true
		}
	}
	return false
}

// claimValueMatches compares one accepted value with the token claim.
// A token claim may itself be a list: any element may match.
func claimValueMatches(have any, want string) bool {
	switch v := have.(type) {
	case []string:
		for _, item := range v {
			if item == want {
				return true
			}
		}
		return false
	case []any:
		for _, item := range v {
			if fmt.Sprintf("%v", item) == want {
				return true
			}
		}
		return false
	default:
		return fmt.Sprintf("%v", have) == want
	}
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
