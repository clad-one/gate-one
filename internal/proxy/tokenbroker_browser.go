package proxy

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"cladone/gate-one/internal/authn"
)

// tbUserKey carries the authenticated user id from the browser handler
// to the reverse-proxy Director.
type tbUserKey struct{}

// newTokenBrokerBrowser builds the reverse proxy that serves the token
// broker's browser routes with the shared secret (and, for authenticated
// routes, the user id) injected. It returns nil when no browser host is
// configured.
func newTokenBrokerBrowser(
	baseURL, secret, host string,
) (*httputil.ReverseProxy, error) {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return nil, nil
	}
	target, err := url.Parse(strings.TrimRight(strings.TrimSpace(baseURL), "/"))
	if err != nil || target.Host == "" {
		return nil, fmt.Errorf(
			"tokenBroker.browserHost: tokenBroker.url %q is invalid", baseURL)
	}
	rp := httputil.NewSingleHostReverseProxy(target)
	orig := rp.Director
	rp.Director = func(req *http.Request) {
		orig(req)
		// Never trust client-supplied identity/secret headers: overwrite.
		req.Header.Del("X-Broker-Secret")
		req.Header.Del("X-User-Id")
		req.Header.Set("X-Broker-Secret", secret)
		if uid, _ := req.Context().Value(tbUserKey{}).(string); uid != "" {
			req.Header.Set("X-User-Id", uid)
		}
		req.Host = target.Host
	}
	rp.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		log.Printf("token broker browser: %v", err)
		http.Error(w, "token broker unavailable", http.StatusBadGateway)
	}
	return rp, nil
}

// serveTokenBrokerBrowser handles the token broker's browser routes on
// the configured host. It reports whether the request was handled.
//
//	GET  /connections                     (auth)   Services page
//	POST /connections/{provider}/disconnect (auth)  delete a connection
//	GET  /connect/{provider}              (auth)   start the OAuth flow
//	GET  /oauth/{provider}/callback       (public) the provider's return
//
// The callback is session-less by design: the token broker's one-shot
// state binds the return to the user. The other routes require a
// session; the identity is injected as X-User-Id.
func (g *Gateway) serveTokenBrokerBrowser(
	w http.ResponseWriter, r *http.Request, ctx *RequestContext,
) bool {
	if g.tbBrowser == nil ||
		normalizeHost(ctx.Host) != g.tbBrowserHost {
		return false
	}
	authed, ok := tokenBrokerBrowserRoute(ctx.Path)
	if !ok {
		return false
	}
	userID := ""
	if authed {
		entry := g.providerEntryForLoginHost(ctx.Host)
		if entry == nil {
			entry = g.defaultProvider
		}
		if entry == nil {
			g.writeTokenBrokerAuthRequired(w, r, nil,
				authn.ErrProviderUnavailable)
			return true
		}
		sctx, err := g.checkAuthWithProvider(w, r, ctx, entry)
		if err != nil {
			g.writeTokenBrokerAuthRequired(w, r, entry, err)
			return true
		}
		userID = sctx.UserID
	}
	r = r.WithContext(context.WithValue(r.Context(), tbUserKey{}, userID))
	g.tbBrowser.ServeHTTP(w, r)
	return true
}

// tokenBrokerBrowserRoute reports whether path is a token broker browser
// route, and whether it requires an authenticated user.
func tokenBrokerBrowserRoute(path string) (authed bool, ok bool) {
	switch {
	case path == "/connections",
		strings.HasPrefix(path, "/connections/"):
		// EVERY /connections subtree is broker UI: the services page,
		// disconnect (pause) AND connect (resume), erase, erase-all.
		// An explicit per-action list missed /connect and /erase: the
		// gateway answered 404 before the broker saw the request
		// (2026-11-12, "Connect" after a Disconnect).
		return true, true
	case strings.HasPrefix(path, "/connect/"):
		return true, true
	case strings.HasPrefix(path, "/oauth/") &&
		strings.HasSuffix(path, "/callback"):
		return false, true
	default:
		return false, false
	}
}

// writeTokenBrokerAuthRequired answers an unauthenticated browser-route
// request: a navigation is redirected to the login page (like a page
// route), anything else gets the API 401. A provider outage is a 502,
// never a login redirect (the login service is the thing that is down).
func (g *Gateway) writeTokenBrokerAuthRequired(
	w http.ResponseWriter, r *http.Request, entry *providerEntry, err error,
) {
	if errors.Is(err, authn.ErrProviderUnavailable) {
		http.Error(w, "authentication unavailable", http.StatusBadGateway)
		return
	}
	loginURL := ""
	if entry != nil && entry.provider != nil {
		loginURL = entry.provider.LoginURL()
	}
	if isDocumentNavigation(r) && loginURL != "" {
		returnTo := clientScheme(r) + "://" + r.Host + r.RequestURI
		http.Redirect(w, r,
			loginURL+"?returnTo="+url.QueryEscape(returnTo),
			http.StatusFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = w.Write([]byte(`{"error":"authentication_required"}`))
}
