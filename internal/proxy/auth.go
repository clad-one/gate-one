package proxy

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
)

var ErrRedirect = errors.New("auth redirect")
var ErrUnauthorized = errors.New("unauthorized")

func writeMCPAuthChallenge(w http.ResponseWriter, resourceMetadataURL, scope string) {
	w.Header().Set(
		"WWW-Authenticate",
		fmt.Sprintf(
			`Bearer resource_metadata="%s", scope="%s"`,
			resourceMetadataURL,
			scope,
		),
	)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)

	_, _ = w.Write([]byte(`{
  "error": "unauthorized",
  "error_description": "Bearer token required"
}`))
}

func splitRoles(s string) []string {
	if s == "" {
		return nil
	}

	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))

	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}

	return out
}

func (g *Gateway) checkAuth(
	w http.ResponseWriter,
	r *http.Request,
	ctx *RequestContext,
) (*RequestContext, error) {
	log.Printf(
		"AUTH CHECK method=%s host=%s uri=%s authorization=%t",
		r.Method,
		r.Host,
		r.RequestURI,
		r.Header.Get("Authorization") != "",
	)
	req, err := http.NewRequest(
		http.MethodGet,
		g.authBridgeBaseURLFor()+"/auth",
		nil,
	)
	if err != nil {
		return nil, err
	}

	if auth := r.Header.Get("Authorization"); auth != "" {
		req.Header.Set("Authorization", auth)
	}
	for _, c := range r.Cookies() {
		req.AddCookie(c)
	}
	req.Header.Set("X-Forwarded-Host", r.Host)
	req.Header.Set("X-Forwarded-Uri", r.RequestURI)
	req.Header.Set("X-Forwarded-Method", r.Method)

	resp, err := g.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	log.Printf(
		"AUTH BRIDGE status=%d user=%q username=%q roles=%q",
		resp.StatusCode,
		resp.Header.Get("X-User-Id"),
		resp.Header.Get("X-Username"),
		resp.Header.Get("X-Roles"),
	)

	// Propagate any cookies auth-bridge issued (e.g. a silently
	// refreshed access_token/refresh_token) back to the browser,
	// regardless of whether auth ultimately succeeded or not.
	for _, c := range resp.Header["Set-Cookie"] {
		w.Header().Add("Set-Cookie", c)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("authentication failed")
	}
	ctx.UserID = resp.Header.Get("X-User-Id")
	ctx.Username = resp.Header.Get("X-Username")
	ctx.Email = resp.Header.Get("X-Email")
	ctx.Roles = splitRoles(resp.Header.Get("X-Roles"))
	return ctx, nil
}

func (g *Gateway) checkMCPAuth(
	w http.ResponseWriter,
	r *http.Request,
	ctx *RequestContext,
	resourceMetadataURL string,
	scope string,
) (*RequestContext, error) {

	req, err := http.NewRequest(
		http.MethodGet,
		g.authBridgeBaseURLFor()+"/auth/mcp",
		nil,
	)
	if err != nil {
		return nil, err
	}

	if auth := r.Header.Get("Authorization"); auth != "" {
		req.Header.Set("Authorization", auth)
	}

	// Header interne : le scope exigé déclaré par la policy mcp de la
	// route (X-MCP-Scope). La requête est construite ici, jamais
	// recopiée des headers d'entrée : un client externe ne peut pas le
	// forger.
	req.Header.Set("X-MCP-Scope", scope)

	resp, err := g.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	log.Printf(
		"MCP AUTH BRIDGE status=%d user=%q username=%q roles=%q",
		resp.StatusCode,
		resp.Header.Get("X-User-Id"),
		resp.Header.Get("X-Username"),
		resp.Header.Get("X-Roles"),
	)

	switch resp.StatusCode {

	case http.StatusUnauthorized:
		writeMCPAuthChallenge(w, resourceMetadataURL, scope)
		return nil, ErrUnauthorized

	case http.StatusForbidden:
		// resource_metadata est attendu aussi sur le 403
		// (MCP 2026-07-28, cohérence avec le 401).
		w.Header().Set(
			"WWW-Authenticate",
			fmt.Sprintf(
				`Bearer error="insufficient_scope", scope="%s", resource_metadata="%s"`,
				scope,
				resourceMetadataURL,
			),
		)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)

		_, _ = w.Write([]byte(fmt.Sprintf(`{
  "error": "insufficient_scope",
  "error_description": "%s scope required"
}`, scope)))

		return nil, ErrUnauthorized

	case http.StatusOK:
		// continue

	default:
		return nil, errors.New("MCP authentication failed")
	}

	ctx.UserID = resp.Header.Get("X-User-Id")
	ctx.Username = resp.Header.Get("X-Username")
	ctx.Email = resp.Header.Get("X-Email")
	ctx.Roles = splitRoles(resp.Header.Get("X-Roles"))

	return ctx, nil
}
