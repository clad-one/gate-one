package proxy

import (
    "log"
    "net/http"
    "net/http/httputil"
    "net/url"

    "cladone/gateway/internal/core"
)

type Gateway struct {
    routes map[string]*httputil.ReverseProxy
    config *core.Config
    client *http.Client
}

func routeKey(host, path string) string {
    return host + "|" + path
}

func New(cfg *core.Config) (*Gateway, error) {

    routes := map[string]*httputil.ReverseProxy{}

    for _, route := range cfg.Routes {

        u, err := url.Parse(route.Backend)
        if err != nil {
            return nil, err
        }

        rp := httputil.NewSingleHostReverseProxy(u)

        original := rp.Director

        rp.Director = func(req *http.Request) {

            original(req)

            req.Host = u.Host

            log.Printf(
                "%s %s -> %s",
                route.Host,
                route.Path,
                route.Backend,
            )
        }

        routes[routeKey(route.Host, route.Path)] = rp
    }

    return &Gateway{
        routes: routes,
        config: cfg,
        client: &http.Client{},
    }, nil

}

func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {

    //
    // construit le contexte complet de la requête
    //

    ctx, err := BuildContext(r)

    if err != nil {

        log.Printf("cannot build request context: %v", err)

        http.Error(
            w,
            "invalid request",
            http.StatusBadRequest,
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

    //
    // recherche du reverse proxy correspondant au host
    //

    p, ok := g.routes[routeKey(ctx.Host, ctx.Path)]

    if !ok {

        log.Printf("unknown host: %q", ctx.Host)

        http.NotFound(w, r)

        return
    }

    //
    // application des règles
    //

    if g.requiresAuthentication(ctx) {

        log.Printf("AUTH REQUIRED")

        if !g.checkAuth(r) {

            log.Printf("AUTH FAILED")

            w.Header().Set(
                "Content-Type",
                "application/json",
            )

            w.WriteHeader(http.StatusUnauthorized)

            w.Write([]byte(`{
                "error":"authentication_required"
            }`))

            return
        }

        log.Printf("AUTH OK")
    }

    //
    // transfert au backend
    //

    p.ServeHTTP(w, r)
}

func (g *Gateway) requiresAuthentication(ctx *RequestContext) bool {

    for _, route := range g.config.Routes {

        if route.Host != ctx.Host {
            continue
        }

        if route.Path != ctx.Path {
            continue
        }

        if route.Auth == nil {
            continue
        }

        if route.Auth.When == nil {
            return true
        }

        if route.Auth.When.Method != "" &&
           route.Auth.When.Method != ctx.Method {
            continue
        }

        ok := true

        for k,v := range route.Auth.When.Query {

            if ctx.Query[k] != v {
                ok = false
            }

        }

        for k,v := range route.Auth.When.Header {

            if ctx.Headers[k] != v {
                ok = false
            }

        }

        for k,v := range route.Auth.When.Body {

            if ctx.Body[k] != v {
                ok = false
            }

        }

        if ok {
            return true
        }
    }

    return false
}