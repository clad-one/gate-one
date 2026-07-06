package proxy

import (
    "log"
    "strings"
    "net/http"
    "net/http/httputil"
    "net/url"
    "cladone/gateway/internal/core"
)

type compiledRoute struct {
    route     *core.Route
    proxy     *httputil.ReverseProxy
    prefix    string

    // true when this route is intended to return HTML pages
    pageRoute bool
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

        routes = append(routes, &compiledRoute{
            route: route,
            proxy: rp,
            prefix: normalizePath(route.Path),

            // page routes are the catch-all routes
            pageRoute: route.Frontend,
        })
    }

    return &Gateway{
        routes: routes,    
        config: cfg,
        client: &http.Client{
            CheckRedirect: func(req *http.Request, via []*http.Request) error {
                return http.ErrUseLastResponse
            },
        },
    }, nil
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

func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {

    ctx, err := BuildContext(r)
    if err != nil {
        log.Printf("cannot build request context: %v", err)
        http.Error(w, "invalid request", http.StatusBadRequest)
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