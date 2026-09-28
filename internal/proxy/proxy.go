package proxy

import (
    "encoding/json"
    "log"
    "strings"
    "net/http"
    "net/http/httputil"
    "net/url"
    "cladone/gateway/internal/core"
	mcpserver "cladone/gateway/internal/mcp"
)

type compiledRoute struct {
    route     *core.Route
    proxy     *httputil.ReverseProxy
    prefix    string

    // true when this route is intended to return HTML pages
    pageRoute bool
	
	mcp *mcpserver.Server
}

type Gateway struct {
    routes []*compiledRoute
    config *core.Config //for policy inspection
    client *http.Client
}

func routeKey(host, path string) string {
    return host + "|" + path
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
		"scopes_supported":          []string{"mcp-tools"},
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

func (g *Gateway) mcpResourceURLForHost(host string) (string, bool) {
	for _, cr := range g.routes {
		if cr.route.MCP == nil || !cr.route.MCP.Enabled {
			continue
		}

		if normalizeHost(cr.route.Host) != normalizeHost(host) {
			continue
		}

		path := cr.route.MCP.Path
		if path == "" {
			path = cr.route.Path
		}

		if path == "" {
			path = "/mcp"
		}

		if !strings.HasPrefix(path, "/") {
			path = "/" + path
		}

		return "https://" + normalizeHost(cr.route.Host) + path, true
	}

	return "", false
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
    		)
    
    		if err != nil {
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
                    "https://login.cladone.com/login?returnTo="+
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

    for _, role := range m.Roles {
        if !ctx.HasRole(role) {
            return false
        }
    }

    if m.User != "" && ctx.Username != m.User {
        return false
    }

    return true
}

func (g *Gateway) needsAuthentication(route *core.Route, ctx *RequestContext) bool {

    if route.Auth == nil {
        return false
    }

    // auth: true => always required
    if route.Auth.When == nil {
        return true
    }

    return matches(route.Auth.When, ctx)
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