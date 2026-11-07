package proxy

import (
	"cladone/gate-one/internal/core"
	"cladone/gate-one/internal/tokenbroker"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/url"
)

// fetchDelegatedToken obtains the authenticated user's current
// access token from the broker. The token is short-lived; the broker
// refreshes it server-side when needed.
func (g *Gateway) fetchDelegatedToken(
	r *http.Request,
	ctx *RequestContext,
	d *core.TokenBrokerPolicy,
) (string, error) {
	if g.tokenBroker == nil {
		return "", &tokenbroker.Error{
			Kind:     tokenbroker.KindUnavailable,
			Provider: d.Provider,
			Message:  "token broker not configured",
		}
	}
	tok, err := g.tokenBroker.Token(r.Context(), ctx.UserID, d.Provider)
	if err != nil {
		return "", err
	}
	return tok.AccessToken, nil
}

// injectDelegated sets the per-user token on a REST request about to
// be proxied. Any client-supplied value of the target header is
// overwritten (Set).
func (g *Gateway) injectDelegated(
	r *http.Request,
	ctx *RequestContext,
	d *core.TokenBrokerPolicy,
) error {
	token, err := g.fetchDelegatedToken(r, ctx, d)
	if err != nil {
		return err
	}
	r.Header.Set(d.HeaderValue(), d.PrefixValue()+token)
	return nil
}

// writeDelegatedError answers a request whose delegated credential
// could not be obtained. API routes get a machine-readable JSON body;
// page routes are redirected to the connect page when the user can
// fix the problem by authorizing the provider.
func (g *Gateway) writeDelegatedError(
	w http.ResponseWriter,
	r *http.Request,
	cr *compiledRoute,
	err error,
) {
	kind := tokenbroker.KindOf(err)
	provider := ""
	connectURL := ""
	var e *tokenbroker.Error
	if errors.As(err, &e) {
		provider = e.Provider
		connectURL = e.ConnectURL
	}

	status := http.StatusBadGateway
	code := "token_broker_unavailable"

	switch kind {
	case tokenbroker.KindNotConnected:
		status = http.StatusUnauthorized
		code = "delegated_credentials_required"
	case tokenbroker.KindReauthorizationRequired:
		status = http.StatusConflict
		code = "reauthorization_required"
	case tokenbroker.KindUnknownProvider:
		status = http.StatusInternalServerError
		code = "delegated_provider_misconfigured"
	case tokenbroker.KindUnauthorized:
		status = http.StatusBadGateway
		code = "token_broker_unauthorized"
	case tokenbroker.KindUpstreamUnavailable:
		status = http.StatusBadGateway
		code = "upstream_unavailable"
	}

	if connectURL != "" {
		returnTo := absoluteRequestURL(r)
		// An MCP client cannot use the MCP endpoint as a browser
		// landing page: after authorizing, send the browser to the
		// connections page, where the user can see the new link and
		// retry the tool call.
		if cr != nil && (cr.mcp != nil || cr.mcpUpstream != nil) {
			if u, err := url.Parse(connectURL); err == nil {
				u.Path = "/connections"
				u.RawQuery = ""
				u.Fragment = ""
				returnTo = u.String()
			}
		}
		connectURL = withReturnTo(connectURL, returnTo)
	}

	if cr != nil && cr.pageRoute &&
		(kind == tokenbroker.KindNotConnected ||
			kind == tokenbroker.KindReauthorizationRequired) {

		if connectURL != "" {
			http.Redirect(w, r, connectURL, http.StatusFound)
			return
		}
	}

	if kind == tokenbroker.KindUnauthorized ||
		kind == tokenbroker.KindUnavailable ||
		kind == tokenbroker.KindInvalidResponse {
		log.Printf("delegated credentials: %v", err)
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", `Bearer realm="delegated-credentials"`)
	}
	w.WriteHeader(status)

	out := map[string]any{"error": code}
	if provider != "" {
		out["provider"] = provider
	}
	if connectURL != "" &&
		(kind == tokenbroker.KindNotConnected ||
			kind == tokenbroker.KindReauthorizationRequired) {
		out["connect_url"] = connectURL
	}
	_ = json.NewEncoder(w).Encode(out)
}

// withReturnTo replaces the broker's default return target with the
// caller's original URL (the broker allow-lists it at connect time).
func withReturnTo(connectURL, returnTo string) string {
	if connectURL == "" || returnTo == "" {
		return connectURL
	}
	u, err := url.Parse(connectURL)
	if err != nil {
		return connectURL
	}
	q := u.Query()
	q.Set("returnTo", returnTo)
	u.RawQuery = q.Encode()
	return u.String()
}

func absoluteRequestURL(r *http.Request) string {
	if r == nil {
		return ""
	}
	path := r.URL.RequestURI()
	if path == "" {
		path = "/"
	}
	return clientScheme(r) + "://" + r.Host + path
}
