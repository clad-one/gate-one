package proxy

import (
    "log"
    "net/http"
    "net/http/httputil"
    "net/url"
)

type Gateway struct {
    routes map[string]*httputil.ReverseProxy
}

func New(routes map[string]string) (*Gateway, error) {

    g := &Gateway{
        routes: map[string]*httputil.ReverseProxy{},
    }

    for host, target := range routes {

        u, err := url.Parse(target)
        if err != nil {
            return nil, err
        }

        rp := httputil.NewSingleHostReverseProxy(u)

        director := rp.Director

        rp.Director = func(req *http.Request) {

            director(req)

            req.Host = u.Host

            log.Printf(
                "%s %s -> %s",
                req.Host,
                req.URL.Path,
                target,
            )
        }

        rp.ErrorHandler = func(
            w http.ResponseWriter,
            r *http.Request,
            err error,
        ) {
            log.Println(err)
            http.Error(w, "Bad Gateway", 502)
        }

        g.routes[host] = rp
    }

    return g, nil
}

func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {

    log.Printf("Host=%q URL=%s", r.Host, r.URL.Path)

    rp, ok := g.routes[r.Host]

    if !ok {
        log.Printf("unknown host %q", r.Host)
        http.NotFound(w, r)
        return
    }

    rp.ServeHTTP(w, r)
}