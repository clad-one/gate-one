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
}

func New(cfg *core.Config) (*Gateway, error) {

    routes := make(map[string]*httputil.ReverseProxy)

    for host, h := range cfg.Hosts {

        svc, ok := cfg.Services[h.Service]

        if !ok {
            return nil,  http.ErrMissingFile
        }

        u, err := url.Parse(svc.URL)

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
                host,
                req.URL.Path,
                svc.URL,
            )

        }

        routes[host] = rp

    }

    return &Gateway{
        routes: routes,
    }, nil

}

func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {

    log.Printf("Host=%q URL=%q", r.Host, r.URL.Path)

    p, ok := g.routes[r.Host]
    if !ok {
        log.Printf("unknown host: %q", r.Host)
        http.NotFound(w, r)
        return
    }

    p.ServeHTTP(w, r)
}