package proxy

import (
	"cladone/gateway/internal/core"
	mcpserver "cladone/gateway/internal/mcp"
	"cladone/gateway/internal/pwa"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
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
}

type Gateway struct {
	routes []*compiledRoute
	config *core.Config //for policy inspection
	client *http.Client

	// base URL de auth-bridge, surchargeable en tests pour stubber le
	// service (défaut : authBridgeBaseURL)
	authBridgeBaseURL string
}

func routeKey(host, path string) string {
	return host + "|" + path
}

// defaultMCPScope : le scope exigé quand la policy mcp d'une route ne
// déclare pas de champ "scope".
const defaultMCPScope = "mcp-tools"

// authBridgeBaseURLFor retourne l'URL de base de auth-bridge (constante
// de production ou valeur de test).
func (g *Gateway) authBridgeBaseURLFor() string {
	if g.authBridgeBaseURL != "" {
		return g.authBridgeBaseURL
	}
	return "http://auth-bridge:3000"
}

func New(cfg *core.Config) (*Gateway, error) {

	var routes []*compiledRoute

	for i := range cfg.Routes {

		route := &cfg.Routes[i]

		u, err := url.Parse(route.Backend)
		if err != nil {
			return nil, err
		}

		rp := httputil.NewSingleHostReverseProxy(u)

		original := rp.Director

		rp.Director = func(req *http.Request) {
			original(req)
			//req.Host = u.Host
		}

		cr := &compiledRoute{
			route:     route,
			proxy:     rp,
			prefix:    normalizePath(route.Path),
			pageRoute: route.Frontend,
		}

		// 401/403 guard script injection on frontend HTML responses
		if guardEnabledFor(route) {
			log.Printf(
				"GUARD enabled host=%s path=%s loginUrl=%s",
				route.Host,
				route.Path,
				guardLoginURL(route),
			)

			script := fmt.Sprintf(
				guardScript,
				guardLoginURL(route),
				AuthStatePath,
				uiGateJSON(route),
				userBadgeJSON(route),
			)
			rp.ModifyResponse = func(resp *http.Response) error {
				if resp.StatusCode != http.StatusOK ||
					!strings.Contains(
						resp.Header.Get("Content-Type"),
						"text/html",
					) {
					return nil
				}
				if err := injectGuardScript(resp, script); err != nil {
					// forward unmodified rather than break the page
					log.Printf(
						"GUARD injection failed host=%s: %v",
						route.Host,
						err,
					)
				}
				return nil
			}
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

		if route.PWA != nil && route.PWA.Enabled {

			cr.pwa = pwa.New(route.PWA)

			// Inject the manifest link + SW registration into
			// successful HTML responses proxied for this route.
			// Chain with any ModifyResponse already set (e.g. the
			// 401/403 guard) so both run.
			previous := rp.ModifyResponse
			rp.ModifyResponse = func(resp *http.Response) error {
				if previous != nil {
					if err := previous(resp); err != nil {
						return err
					}
				}
				return pwa.InjectResponse(resp)
			}

			log.Printf(
				"PWA enabled host=%s path=%s",
				route.Host,
				route.Path,
			)
		}

		routes = append(routes, cr)

	}

	return &Gateway{
		routes: routes,
		config: cfg,
		client: &http.Client{
			CheckRedirect: func(
				req *http.Request,
				via []*http.Request,
			) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

func (g *Gateway) serveMCPProtectedResourceMetadata(
	w http.ResponseWriter,
	r *http.Request,
) {
	resource, ok := g.mcpResourceURLForHost(r.Host)
	if !ok {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	_ = json.NewEncoder(w).Encode(map[string]any{
		"resource": resource,
		"authorization_servers": []string{
			"https://auth.cladone.com/realms/cladone",
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

// pwaHandlerForHost returns the PWA handler of the first PWA-enabled
// route matching the host, or nil when the host has none.
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
// userBadgeJSON sérialise la policy userBadge de la route pour le
// script de garde (JSON, ou "null" si absente — pas de badge).
func userBadgeJSON(route *core.Route) string {
	if route == nil || route.UserBadge == nil {
		return "null"
	}
	b, err := json.Marshal(route.UserBadge)
	if err != nil {
		return "null"
	}
	return string(b)
}

// uiGateJSON sérialise les règles uiGate de la route pour le script
// de garde (tableau JSON ; "[]" si aucune). Passé en ARGUMENT de
// Sprintf : un "%" dans le JSON est sûr (les arguments ne sont pas
// re-parsés comme format).
func uiGateJSON(route *core.Route) string {
	if route == nil || len(route.UIGate) == 0 {
		return "[]"
	}
	b, err := json.Marshal(route.UIGate)
	if err != nil {
		return "[]"
	}
	return string(b)
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

// mcpRouteForHost retourne la route MCP activée d'un host.
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

func (g *Gateway) mcpResourceURLForHost(host string) (string, bool) {
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

	return "https://" + normalizeHost(route.Host) + path, true
}

// mcpScopeForHost retourne le scope MCP exigé pour un host (champ
// "scope" de la policy mcp, défaut defaultMCPScope).
func (g *Gateway) mcpScopeForHost(host string) string {
	route, ok := g.mcpRouteForHost(host)
	if !ok || route.MCP.Scope == "" {
		return defaultMCPScope
	}
	return route.MCP.Scope
}

func (g *Gateway) mcpResourceMetadataURL(host string) (string, bool) {
	if _, ok := g.mcpResourceURLForHost(host); !ok {
		return "", false
	}

	return "https://" +
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
		if _, ok := g.mcpResourceURLForHost(ctx.Host); ok {
			g.serveMCPProtectedResourceMetadata(w, r)
			return
		}
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

			resourceMetadataURL, ok := g.mcpResourceMetadataURL(ctx.Host)
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
				// checkMCPAuth a déjà répondu (challenge 401/403)
				// sauf sur erreur réseau/transport : là, la réponse
				// est encore vierge — écrire un 502 plutôt que
				// laisser Go émettre un 200 vide.
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
		// Identité disponible pour le handler MCP.
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

	log.Printf(
		"Host=%q Path=%q Method=%q Query=%v Body=%v",
		ctx.Host,
		ctx.Path,
		ctx.Method,
		ctx.Query,
		ctx.Body,
	)

	log.Printf(
		"Host=%q Method=%q Path=%q",
		ctx.Host,
		ctx.Method,
		ctx.Path,
	)

	cr, ok := g.findRoute(ctx)

	log.Printf("matched=%v", ok)

	if !ok {
		http.NotFound(w, r)
		return
	}

	route := cr.route
	p := cr.proxy

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

				returnTo := "https://" + host + r.RequestURI

				http.Redirect(
					w,
					r,
					LoginPageURL+"?returnTo="+
						url.QueryEscape(returnTo),
					http.StatusFound,
				)
				return
			}

			//
			// API route
			//
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("WWW-Authenticate", `Bearer realm="cladone"`)
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error":"authentication_required"}`))
			return
		}

		//
		// Conditions d'identité (rôles/scopes/claims/user) :
		// authentifié mais insuffisant → 403. Le script de garde
		// n'intercepte QUE le 401 — un refus de droits ne doit pas
		// déclencher une invitation au login (boucle).
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
	// TODO rate limit
	//

	//
	// TODO quota
	//

	//
	// Forward headers
	//

	r.Header.Set("X-User-Id", ctx.UserID)
	r.Header.Set("X-Username", ctx.Username)
	r.Header.Set("X-Email", ctx.Email)
	r.Header.Set("X-Roles", strings.Join(ctx.Roles, ","))

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

	// matches = conditions techniques (évaluables pré-authentification)
	// + conditions d'identité (rôles/scopes/claims/user, évaluées
	// après). Utilisé par rateLimit/quota.
	if !matchesBasic(m, ctx) {
		return false
	}
	return matchesIdentity(m, ctx)
}

// matchesBasic : conditions évaluables SANS token (avant
// authentification).
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

// matchesIdentity : conditions nécessitant le token vérifié
// (rôles/scopes/claims/user) — évaluées APRÈS authentification.
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

// hasIdentityConditions : le when porte-t-il des conditions
// d'identité (évaluation post-authentification requise) ?
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

	// Conditions TECHNIQUES seulement (method/query/header/body) :
	// les conditions d'identité (roles/scopes/claims/user) ne sont
	// évaluables qu'après authentification (le token n'existe pas
	// encore) — cf. matchesIdentity, appliquée post-auth en 403.
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
