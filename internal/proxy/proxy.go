package proxy

import (
	"cladone/gateway/internal/core"
	mcpserver "cladone/gateway/internal/mcp"
	"cladone/gateway/internal/pwa"
	"context"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync/atomic"
	"time"
)

type compiledRoute struct {
	route  *core.Route
	proxy  *httputil.ReverseProxy
	prefix string

	// true when this route is intended to return HTML pages
	pageRoute bool

	mcp *mcpserver.Server

	// non-nil when the route declares a pwa policy: serves
	// /__gateway_pwa/* and injects PWA tags into HTML responses
	pwa *pwa.Handler

	// route rateLimit/quota limiters (fixed windows), built
	// lazily on first need
	limiters *routeLimiters
}

type Gateway struct {
	routes []*compiledRoute
	config *core.Config //for policy inspection
	client *http.Client

	// auth-bridge base URL, overridable in tests to stub the
	// service (default: authBridgeBaseURL)
	authBridgeBaseURL string
}

func routeKey(host, path string) string {
	return host + "|" + path
}

// defaultMCPScope: the required scope when a route's mcp policy
// does not declare a "scope" field.
const defaultMCPScope = "mcp-tools"

// authBridgeBaseURLFor returns the auth-bridge base URL (production
// constant or test value).
func (g *Gateway) authBridgeBaseURLFor() string {
	if g.authBridgeBaseURL != "" {
		return g.authBridgeBaseURL
	}
	return "http://auth-bridge:3000"
}

// Option: functional modifier of the Gateway at construction.
type Option func(*Gateway)

// WithAuthBridgeURL overrides the auth-bridge base URL (default:
// http://auth-bridge:3000, the Docker network service name). Empty =
// default. Used by the CLI (-authBridge) and smoke tests.
func WithAuthBridgeURL(u string) Option {
	return func(g *Gateway) {
		if u != "" {
			g.authBridgeBaseURL = u
		}
	}
}

// WithLogBody enables verbose request logging (query + body):
// debug only — data may be sensitive.
func WithLogBody(v bool) Option {
	return func(g *Gateway) {
		logRequestBodies = v
	}
}

// logRequestBodies: debug mode (-logBody) — also logs request
// query/body (potentially sensitive data: opt-in).
var logRequestBodies = false

// authBridgeClientTimeout bounds every auth-bridge call: without
// it, a wedged auth-bridge (busy-loop, 2026-10-17 incident) froze
// ALL authenticated routes — every checkAuth waited forever.
// Package-level variable for tests.
var authBridgeClientTimeout = 5 * time.Second

// backendTransport: dedicated outbound transport instead of the default.
//   - sized pool: MaxIdleConnsPerHost = 2 by default → for a heavy page
//     served from a single origin (the proxified book: 878 images on
//     Cloudflare), every request beyond the first two paid a TLS
//     handshake; 100 idle per host = massive reuse (perf),
//     MaxConnsPerHost unbounded (throughput is not capped),
//   - safety bounds: dial/TLS/ResponseHeader timeouts — a hung
//     backend releases the connection instead of freezing it for life.
var backendTransport = func() *http.Transport {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.DialContext = (&net.Dialer{
		Timeout:   15 * time.Second,
		KeepAlive: 30 * time.Second,
	}).DialContext
	t.ResponseHeaderTimeout = 60 * time.Second
	t.MaxIdleConns = 200
	t.MaxIdleConnsPerHost = 100
	return t
}()

// Reloadable: handler wrapper allowing hot config replacement
// (SIGHUP) without rebuilding the image — routing switches
// atomically, in-flight requests finish on the old instance.
type Reloadable struct {
	current atomic.Pointer[Gateway]
}

func (h *Reloadable) Store(gw *Gateway) {
	h.current.Store(gw)
}

func (h *Reloadable) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.current.Load().ServeHTTP(w, r)
}

func New(cfg *core.Config, opts ...Option) (*Gateway, error) {

	var routes []*compiledRoute

	for i := range cfg.Routes {

		route := &cfg.Routes[i]

		u, err := url.Parse(route.Backend)
		if err != nil {
			return nil, err
		}

		rp := httputil.NewSingleHostReverseProxy(u)
		rp.Transport = backendTransport

		original := rp.Director

		upstream := route.Upstream

		// Body injections (401/403 guard, PWA, origin URL rewrite)
		// require PLAIN HTML: the Go stdlib decodes neither brotli
		// nor zstd — if the browser offers them and the origin
		// answers with one, a manipulated compressed body +
		// Content-Encoding removed = unreadable page. We therefore
		// force gzip upstream (decodable); decompression happens in
		// ModifyResponse, before the injection chain. Without
		// injection: the client's Accept-Encoding goes through as-is
		// (optimal passthrough).
		rwPlan := rewritePlanFor(route, u)

		injectsBody := guardEnabledFor(route) ||
			(route.PWA != nil && route.PWA.Enabled) ||
			rwPlan != nil ||
			route.InjectionBundle() != nil

		rp.Director = func(req *http.Request) {
			// the CLIENT host (with its non-standard port) — frozen
			// BEFORE the upstream policy rewrites it to the backend
			// origin: body/Location injectors read it back in
			// ModifyResponse and the rewritten URLs keep the browser
			// on the origin it called (demo :3000 included).
			clientHost := req.Host
			original(req)
			// freezes the CLIENT scheme (X-Forwarded-Proto from the
			// ingress, still intact here — ReverseProxy overwrites
			// it afterwards with the gateway→backend hop's scheme)
			// into the context: body injectors read it back in
			// ModifyResponse (resp.Request).
			ctx := context.WithValue(
				req.Context(), clientSchemeKey, clientScheme(req))
			ctx = context.WithValue(ctx, clientHostKey, clientHost)
			*req = *req.WithContext(ctx)
			if injectsBody {
				req.Header.Set("Accept-Encoding", "gzip")
			}
			// Upstream policy (proxified external site): Host
			// rewritten to the backend origin + static headers
			// (basic auth, service tokens). Without policy:
			// historical behavior — the browser's public Host is
			// preserved (internal-network backends).
			if upstream != nil {
				applyUpstreamDirector(upstream, u, req)
			}
		}

		cr := &compiledRoute{
			route:     route,
			proxy:     rp,
			prefix:    normalizePath(route.Path),
			pageRoute: route.Frontend,
		}

		if route.MCP != nil &&
			route.MCP.Enabled {

			mcpServer := mcpserver.New(
				route.Backend,
			)

			cr.mcp = mcpServer

			log.Printf(
				"MCP enabled host=%s path=%s",
				route.Host,
				route.MCP.Path,
			)
		}

		if route.PWA != nil && route.PWA.Enabled ||
			rwPlan != nil {

			cr.pwa = pwa.New(
				route.PWA,
				func() *pwa.RewriteSpec {
					if rwPlan == nil {
						return nil
					}
					return rwPlan.clientSpec()
				}(),
			)

			log.Printf(
				"CLIENT runtime enabled host=%s path=%s (pwa=%v rewriteBody=%v)",
				route.Host,
				route.Path,
				route.PWA != nil && route.PWA.Enabled,
				rwPlan != nil,
			)
		}

		// Route injection chain: the registry (injector.go) carries
		// each feature and their order — gzip → guard →
		// rewriteBody → upstream(headers) → pwa → custom. The guard
		// JS lives in guard/guard.js.tmpl (go:embed); custom
		// injections (bundle) are data, not code.
		if injectors := buildInjectors(cfg, route, u, rwPlan, injectsBody); len(injectors) > 0 {
			rp.ModifyResponse = chainInjectors(injectors)
		}

		routes = append(routes, cr)

	}

	gw := &Gateway{
		routes: routes,
		config: cfg,
		client: &http.Client{
			// Timeout: auth-bridge calls must never freeze request
			// handling (see authBridgeClientTimeout).
			Timeout:   authBridgeClientTimeout,
			Transport: backendTransport,
			CheckRedirect: func(
				req *http.Request,
				via []*http.Request,
			) error {
				return http.ErrUseLastResponse
			},
		},
	}

	for _, opt := range opts {
		opt(gw)
	}

	return gw, nil
}

func (g *Gateway) serveMCPProtectedResourceMetadata(
	w http.ResponseWriter,
	r *http.Request,
) {
	resource, ok := g.mcpResourceURLForHost(r.Host, clientScheme(r))
	if !ok {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	_ = json.NewEncoder(w).Encode(map[string]any{
		"resource": resource,
		"authorization_servers": []string{
			g.config.OIDC.Issuer,
		},
		"scopes_supported":         []string{g.mcpScopeForHost(r.Host)},
		"bearer_methods_supported": []string{"header"},
	})
}

func normalizePath(p string) string {
	if p == "/*" {
		return "/"
	}

	if strings.HasSuffix(p, "/*") {
		return strings.TrimSuffix(p, "/*") + "/"
	}

	return p
}

func matchPath(routePath, reqPath string) bool {
	if routePath == "/*" {
		return true
	}

	if strings.HasSuffix(routePath, "/*") {
		base := strings.TrimSuffix(routePath, "/*")
		return reqPath == base || strings.HasPrefix(reqPath, base+"/")
	}

	return reqPath == routePath
}

func normalizeHost(h string) string {
	h = strings.TrimSpace(h)
	h = strings.ToLower(h)
	return strings.Split(h, ":")[0]
}

func (g *Gateway) findRoute(ctx *RequestContext) (*compiledRoute, bool) {

	var (
		best    *compiledRoute
		bestLen int
	)

	for _, r := range g.routes {

		if normalizeHost(r.route.Host) != normalizeHost(ctx.Host) {
			continue
		}

		//if !strings.HasPrefix(ctx.Path, r.prefix) {
		if !matchPath(r.route.Path, ctx.Path) {
			continue
		}

		if len(r.prefix) > bestLen {
			best = r
			bestLen = len(r.prefix)
		}
	}

	if best == nil {
		log.Printf(
			"NO ROUTE host=%q path=%q",
			ctx.Host,
			ctx.Path,
		)
		return nil, false
	}

	return best, true
}

func extractToken(r *http.Request) string {

	// 1. Authorization header (API / JS fetch)
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimPrefix(auth, "Bearer ")
	}

	// 2. Cookie (browser session)
	cookie, err := r.Cookie("access_token")
	if err == nil {
		return cookie.Value
	}

	return ""
}

type RedirectError struct {
	Location string
}

func (e *RedirectError) Error() string {
	return "redirect"
}

func isBrowserRequest(r *http.Request) bool {
	accept := r.Header.Get("Accept")
	sec := r.Header.Get("Sec-Fetch-Dest")

	return strings.Contains(accept, "text/html") ||
		strings.Contains(sec, "document")
}

func (g *Gateway) isPubliclyForbidden(
	ctx *RequestContext,
) bool {

	for _, r := range g.routes {

		if normalizeHost(r.route.Host) !=
			normalizeHost(ctx.Host) {
			continue
		}

		if r.route.OpenAPI == nil {
			continue
		}

		if r.route.OpenAPI.Public {
			continue
		}

		if ctx.Path == "/openapi.json" {
			return true
		}
	}

	return false
}

// pwaHandlerForHost returns the client-runtime handler (PWA and/or
// client rewrite) of the first matching route, or nil.
func (g *Gateway) pwaHandlerForHost(host string) *pwa.Handler {
	for _, r := range g.routes {
		if r.pwa == nil {
			continue
		}
		if normalizeHost(r.route.Host) == normalizeHost(host) {
			return r.pwa
		}
	}
	return nil
}

// guardRouteForHost returns the first guard-enabled frontend route
// matching the host. The auth-state probe endpoint exists only there.
// userBadgeJSON serializes the route's userBadge policy for the
// guard script (JSON, or "null" when absent — no badge).
func userBadgeJSON(route *core.Route) string {
	if route == nil || route.UserBadge == nil {
		return "null"
	}
	return core.AsciiJSON(route.UserBadge, "null")
}

// uiGateJSON serializes the route's uiGate rules for the guard
// script (JSON array; "[]" when none). Passed as a Sprintf
// ARGUMENT: a "%" in the JSON is safe (arguments are not re-parsed
// as format).
func uiGateJSON(route *core.Route) string {
	if route == nil || len(route.UIGate) == 0 {
		return "[]"
	}
	return core.AsciiJSON(route.UIGate, "[]")
}

// patchJSONFor serializes the route bundle's patch rules for the
// guard script (PATCH=%s; "[]" without bundle or patch). Non-ASCII
// values are escaped (ascii-safe payload, see mojibake incident).
func patchJSONFor(route *core.Route) string {
	b := route.InjectionBundle()
	if b == nil || len(b.Patch) == 0 {
		return "[]"
	}
	return core.AsciiJSON(b.Patch, "[]")
}

// rewriteGuardJSON serializes the rewriteBody policy for the guard
// script (REWRITE=%s; "null" when absent). Origin hosts in BARE
// form (no scheme): the payload undergoes its own rewrite.
func rewriteGuardJSON(route *core.Route, backend *url.URL) string {
	dto := rewriteGuardDTOFor(route, backend)
	if dto == nil {
		return "null"
	}
	return core.AsciiJSON(dto, "null")
}

func (g *Gateway) guardRouteForHost(host string) (*compiledRoute, bool) {
	for _, cr := range g.routes {
		if cr.route.Frontend != true || !guardEnabledFor(cr.route) {
			continue
		}
		if normalizeHost(cr.route.Host) != normalizeHost(host) {
			continue
		}
		return cr, true
	}
	return nil, false
}

// serveAuthState answers the session probe: 200 + JSON
// {roles, scopes, claims} when the request carries a valid session,
// 401 otherwise. The guard script consumes the JSON for the
// declarative data-gtw-roles / data-gtw-scopes / data-gtw-claims
// gating. checkAuth propagates into w any session cookie it silently
// refreshed, so a 401 probe can still extend the session.
func (g *Gateway) serveAuthState(
	w http.ResponseWriter,
	r *http.Request,
	ctx *RequestContext,
) {
	// a session probe must never be cacheable
	w.Header().Set("Cache-Control", "no-store")
	sctx, err := g.checkAuth(w, r, ctx)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"authentication_required"}`))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"roles":  sctx.Roles,
		"scopes": sctx.Scopes,
		"claims": sctx.Claims,
	})
}

// mcpRouteForHost returns a host's enabled MCP route.
func (g *Gateway) mcpRouteForHost(host string) (*core.Route, bool) {
	for _, cr := range g.routes {
		if cr.route.MCP == nil || !cr.route.MCP.Enabled {
			continue
		}

		if normalizeHost(cr.route.Host) != normalizeHost(host) {
			continue
		}

		return cr.route, true
	}

	return nil, false
}

// clientSchemeKey: the CLIENT scheme (browser→ingress) frozen into
// the outgoing request's context by the Director — ReverseProxy
// overwrites X-Forwarded-Proto with the gateway→backend hop's
// scheme; body injectors (ModifyResponse) read the original value
// back here.
type clientSchemeKeyT struct{}

var clientSchemeKey = new(clientSchemeKeyT)

// clientScheme: the BROWSER request scheme (handlers seeing the
// incoming request): X-Forwarded-Proto (set by the ingress),
// otherwise direct TLS = https, otherwise plain http (direct
// demo).
func clientScheme(r *http.Request) string {
	if p := r.Header.Get("X-Forwarded-Proto"); p != "" {
		return p
	}
	if r.TLS != nil {
		return "https"
	}
	return "http"
}

// clientHostKey: same freeze for the CLIENT host (with its
// non-standard port when there is one — the demo runs on :3000). The
// upstream policy rewrites req.Host to the backend origin: the
// client value must be frozen BEFORE that.
type clientHostKeyT struct{}

var clientHostKey = new(clientHostKeyT)

// requestHostOut: the client host for ModifyResponse injectors
// (resp.Request = outgoing request): the value frozen by the
// Director before the upstream policy rewrites it. Empty = absent.
func requestHostOut(r *http.Request) string {
	if r != nil {
		if v, ok := r.Context().Value(clientHostKey).(string); ok {
			return v
		}
	}
	return ""
}

// requestSchemeOut: the client scheme for ModifyResponse injectors
// (resp.Request = outgoing request): the value frozen by the
// Director, otherwise what ReverseProxy set (X-Forwarded-Proto
// reflects direct inbound TLS), otherwise https.
func requestSchemeOut(r *http.Request) string {
	if r != nil {
		if v, ok := r.Context().Value(clientSchemeKey).(string); ok && v != "" {
			return v
		}
		if p := r.Header.Get("X-Forwarded-Proto"); p != "" {
			return p
		}
	}
	return "https"
}

func (g *Gateway) mcpResourceURLForHost(
	host string,
	scheme string,
) (string, bool) {
	route, ok := g.mcpRouteForHost(host)
	if !ok {
		return "", false
	}

	path := route.MCP.Path
	if path == "" {
		path = route.Path
	}

	if path == "" {
		path = "/mcp"
	}

	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	return scheme + "://" + normalizeHost(route.Host) + path, true
}

// mcpScopeForHost returns the MCP scope required for a host (the
// mcp policy's "scope" field, default defaultMCPScope).
func (g *Gateway) mcpScopeForHost(host string) string {
	route, ok := g.mcpRouteForHost(host)
	if !ok || route.MCP.Scope == "" {
		return defaultMCPScope
	}
	return route.MCP.Scope
}

func (g *Gateway) mcpResourceMetadataURL(
	host string,
	scheme string,
) (string, bool) {
	if _, ok := g.mcpResourceURLForHost(host, scheme); !ok {
		return "", false
	}

	return scheme + "://" +
		normalizeHost(host) +
		"/.well-known/oauth-protected-resource", true
}

func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	ctx, err := BuildContext(r)
	if err != nil {
		log.Printf("cannot build request context: %v", err)
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	// MCP OAuth protected-resource metadata
	if ctx.Path == "/.well-known/oauth-protected-resource" {
		if _, ok := g.mcpResourceURLForHost(ctx.Host, clientScheme(r)); ok {
			g.serveMCPProtectedResourceMetadata(w, r)
			return
		}
	}

	// Operations endpoints (gateway-served, any host)
	switch ctx.Path {
	case "/healthz":
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"ok"}`))
		return
	case "/__gateway/stats":
		serveStats(w, r)
		return
	}

	if g.isPubliclyForbidden(ctx) {
		http.NotFound(w, r)
		return
	}

	//
	// PWA virtual endpoints (gateway-served, never proxied)
	//
	if strings.HasPrefix(ctx.Path, pwa.PathPrefix) {
		if h := g.pwaHandlerForHost(ctx.Host); h != nil {
			h.ServeHTTP(w, r)
			return
		}
	}

	//
	// Auth-state probe (gateway-served, never proxied): 204 when the
	// caller holds a valid session, 401 otherwise. Consumed by the
	// injected guard for the declarative [data-cladone-auth] gating.
	//
	if ctx.Path == AuthStatePath {
		if _, ok := g.guardRouteForHost(ctx.Host); ok {
			g.serveAuthState(w, r, ctx)
			return
		}
	}

	//
	// MCP
	//

	if cr, ok := g.findMCP(ctx); ok {

		route := cr.route

		//
		// MCP OAuth authentication
		//
		if g.needsAuthentication(route, ctx) {

			resourceMetadataURL, ok := g.mcpResourceMetadataURL(
				ctx.Host, clientScheme(r))
			if !ok {
				http.Error(
					w,
					"MCP authentication configuration error",
					http.StatusInternalServerError,
				)
				return
			}

			ctx, err = g.checkMCPAuth(
				w,
				r,
				ctx,
				resourceMetadataURL,
				g.mcpScopeForHost(ctx.Host),
			)

			if err != nil {
				// checkMCPAuth already answered (401/403 challenge)
				// except on a network/transport error: there, the
				// response is still blank — write a 502 rather than
				// letting Go emit an empty 200.
				if errors.Is(err, ErrUnauthorized) {
					return
				}
				log.Printf(
					"MCP auth-bridge unreachable: %v",
					err,
				)
				http.Error(
					w,
					"authentication service unavailable",
					http.StatusBadGateway,
				)
				return
			}
		}

		//
		// Identity available to the MCP handler.
		//
		r.Header.Set(
			"X-User-Id",
			ctx.UserID,
		)

		r.Header.Set(
			"X-Username",
			ctx.Username,
		)

		r.Header.Set(
			"X-Email",
			ctx.Email,
		)

		r.Header.Set(
			"X-Roles",
			strings.Join(ctx.Roles, ","),
		)

		cr.mcp.HTTPHandler.ServeHTTP(
			w,
			r,
		)

		return
	}

	cr, ok := g.findRoute(ctx)

	// One line per request; the body (potentially sensitive data)
	// only reaches the logs in debug mode (-logBody).
	if logRequestBodies {
		log.Printf(
			"REQ host=%q method=%q path=%q query=%v body=%v matched=%v",
			ctx.Host,
			ctx.Method,
			ctx.Path,
			ctx.Query,
			ctx.Body,
			ok,
		)
	} else {
		log.Printf(
			"REQ host=%q method=%q path=%q matched=%v",
			ctx.Host,
			ctx.Method,
			ctx.Path,
			ok,
		)
	}

	if !ok {
		http.NotFound(w, r)
		return
	}

	route := cr.route
	p := cr.proxy

	// Statistics: the response's FINAL status is counted per route
	// (302 auth, 401, 403, 429, 200 proxified…).
	sw := &statsWriter{ResponseWriter: w}
	w = sw
	defer func() {
		statRecord(routeKey(route.Host, route.Path), sw.status)
	}()

	//
	// HEAD fallback
	//
	if route.AutoHead && r.Method == http.MethodHead {

		r.Method = http.MethodGet
		ctx.Method = http.MethodGet

		w = &headResponseWriter{
			ResponseWriter: w,
		}
	}

	//
	// Authentication
	//
	if g.needsAuthentication(route, ctx) {

		ctx, err = g.checkAuth(w, r, ctx)

		if err != nil {

			//
			// Page route
			//
			if cr.pageRoute {

				host := r.Host

				returnTo := clientScheme(r) + "://" +
					host + r.RequestURI

				http.Redirect(
					w,
					r,
					g.config.LoginURLFor(route)+"?returnTo="+
						url.QueryEscape(returnTo),
					http.StatusFound,
				)
				return
			}

			//
			// API route
			//
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("WWW-Authenticate", `Bearer realm="gateway"`)
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error":"authentication_required"}`))
			return
		}

		//
		// Identity conditions (roles/scopes/claims/user):
		// authenticated but insufficient → 403. The guard script
		// only intercepts the 401 — a rights refusal must not
		// trigger a login invitation (loop).
		//
		if route.Auth != nil &&
			hasIdentityConditions(route.Auth.When) &&
			!matchesIdentity(route.Auth.When, ctx) {

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(`{"error":"forbidden","error_description":"identity conditions not met"}`))
			return
		}
	}

	//
	// Rate limit / quota (fixed window, key = identity or IP):
	// 429 + Retry-After when the window is full.
	//
	if enforceLimits(w, r, cr, ctx) {
		return
	}

	//
	// Forward headers
	//

	r.Header.Set("X-User-Id", ctx.UserID)
	r.Header.Set("X-Username", ctx.Username)
	r.Header.Set("X-Email", ctx.Email)
	r.Header.Set("X-Roles", strings.Join(ctx.Roles, ","))

	// X-Forwarded-*: Traefik already provides them in production;
	// setting them here guarantees identical behavior on direct
	// gateway access (tests, diagnostics) — without overwriting the
	// upstream.
	if r.Header.Get("X-Forwarded-Proto") == "" {
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		r.Header.Set("X-Forwarded-Proto", scheme)
	}
	if r.Header.Get("X-Forwarded-Host") == "" {
		r.Header.Set("X-Forwarded-Host", r.Host)
	}

	p.ServeHTTP(w, r)
}

func (ctx *RequestContext) HasRole(role string) bool {
	for _, r := range ctx.Roles {
		if r == role {
			return true
		}
	}
	return false
}

func matches(m *core.Match, ctx *RequestContext) bool {

	if m == nil {
		return true
	}

	// matches = technical conditions (evaluable pre-authentication)
	// + identity conditions (roles/scopes/claims/user, evaluated
	// after). Used by rateLimit/quota.
	if !matchesBasic(m, ctx) {
		return false
	}
	return matchesIdentity(m, ctx)
}

// matchesBasic: conditions evaluable WITHOUT a token (before
// authentication).
func matchesBasic(m *core.Match, ctx *RequestContext) bool {

	if m == nil {
		return true
	}

	if m.Method != "" && m.Method != ctx.Method {
		return false
	}

	for k, v := range m.Query {
		if ctx.Query[k] != v {
			return false
		}
	}

	for k, v := range m.Header {
		if ctx.Headers[k] != v {
			return false
		}
	}

	for k, v := range m.Body {
		if ctx.Body[k] != v {
			return false
		}
	}

	return true
}

// matchesIdentity: conditions requiring the verified token
// (roles/scopes/claims/user) — evaluated AFTER authentication.
func matchesIdentity(m *core.Match, ctx *RequestContext) bool {

	if m == nil {
		return true
	}

	for _, role := range m.Roles {
		if !ctx.HasRole(role) {
			return false
		}
	}

	for _, scope := range m.Scopes {
		if !ctx.HasScope(scope) {
			return false
		}
	}

	for k, v := range m.Claims {
		if !ctx.HasClaim(k, v) {
			return false
		}
	}

	if m.User != "" && ctx.Username != m.User {
		return false
	}

	return true
}

// hasIdentityConditions: does the when carry identity conditions
// (post-authentication evaluation required)?
func hasIdentityConditions(m *core.Match) bool {
	return m != nil &&
		(len(m.Roles) > 0 || len(m.Scopes) > 0 || len(m.Claims) > 0 || m.User != "")
}

func (g *Gateway) needsAuthentication(route *core.Route, ctx *RequestContext) bool {

	if route.Auth == nil {
		return false
	}

	// auth: true => always required
	if route.Auth.When == nil {
		return true
	}

	// Conditions TECHNICAL only (method/query/header/body): identity
	// conditions (roles/scopes/claims/user) are only evaluable after
	// authentication (the token does not exist yet) — see
	// matchesIdentity, applied post-auth as 403.
	return matchesBasic(route.Auth.When, ctx)
}

func (g *Gateway) findMCP(
	ctx *RequestContext,
) (*compiledRoute, bool) {

	for _, r := range g.routes {

		if r.mcp == nil {
			continue
		}

		if normalizeHost(r.route.Host) !=
			normalizeHost(ctx.Host) {
			continue
		}

		path := r.route.MCP.Path

		if path == "" {
			path = "/mcp"
		}

		if ctx.Path != path {
			continue
		}

		return r, true
	}

	return nil, false
}
