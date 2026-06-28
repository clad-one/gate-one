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
    route  *core.Route
    proxy  *httputil.ReverseProxy
    prefix string
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
            req.Host = u.Host
        }

        routes = append(routes, &compiledRoute{
            route:  route,
            proxy:  rp,
            prefix: normalizePath(route.Path),
        })
    }

    return &Gateway{
        routes: routes,
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

func (g *Gateway) findRoute(ctx *RequestContext) (*core.Route, *httputil.ReverseProxy, bool) {

    var (
        bestRoute *core.Route
        bestProxy *httputil.ReverseProxy
        bestLen   int
    )

    for _, r := range g.routes {

        log.Printf("r.route.Host  = %q", r.route.Host )
        log.Printf("CTX HOST RAW = %q", ctx.Host)
        //host := strings.Split(ctx.Host, ":")[0]
        if normalizeHost(r.route.Host) != normalizeHost(ctx.Host) {
            continue
        }
        // host must match
        /*if r.route.Host != ctx.Host {
            continue
        }*/

        // prefix match
        if !strings.HasPrefix(ctx.Path, r.prefix) {
            continue
        }

        // longer prefix wins
        if len(r.prefix) > bestLen {
            bestLen = len(r.prefix)
            bestRoute = r.route
            bestProxy = r.proxy
        }
    }

    if bestRoute == nil {
        return nil, nil, false
    }

    return bestRoute, bestProxy, true
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

    route, p, ok := g.findRoute(ctx)
    if !ok {
        log.Printf("unknown route: host=%s path=%s", ctx.Host, ctx.Path)
        http.NotFound(w, r)
            return
    }

    //
    // Authentication
    //

    if g.needsAuthentication(route, ctx) {

        ctx, err = g.checkAuth(r, ctx)

        if err != nil {

            isBrowser := strings.Contains(r.Header.Get("Accept"), "text/html") ||
                strings.Contains(r.Header.Get("Sec-Fetch-Dest"), "document")

            // ✅ ONLY redirect for real page navigation
            if isBrowser && r.Method == "GET" {

                host := r.Header.Get("X-Forwarded-Host")
                uri := r.Header.Get("X-Forwarded-Uri")

                if host == "" {
                    host = r.Host
                }

                returnTo := "https://" + host + uri

                http.Redirect(w, r,
                    "https://login.cladone.com/login?returnTo="+url.QueryEscape(returnTo),
                    http.StatusFound,
                )
                return
            }

            // API CASE = signal only
            w.Header().Set("Content-Type", "application/json")
            w.Header().Set("WWW-Authenticate", `Bearer realm="cladone"`)
            w.WriteHeader(http.StatusUnauthorized)
            w.Write([]byte(`{"error":"authentication_required"}`))
            return
        }
    }

/*
    if g.needsAuthentication(route, ctx) {

        log.Printf("AUTH REQUIRED")

        ctx, err = g.checkAuth(r, ctx)

        if err != nil {

            if redir, ok := err.(*RedirectError); ok {
                http.Redirect(w, r, redir.Location, http.StatusFound)
                return
            }

            w.Header().Set("Content-Type", "application/json")
            w.WriteHeader(http.StatusUnauthorized)
            w.Write([]byte(`{"error":"authentication_required"}`))
            return
        }

        log.Printf("AUTH OK user=%s roles=%v", ctx.Username, ctx.Roles)
    }
*/
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