package proxy

import (
	//"errors"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
)

type Router struct {
	routes map[string]*httputil.ReverseProxy
}

// NewRouter builds one reverse proxy per host
func NewRouter(routeMap map[string]string) (*Router, error) {

	routes := make(map[string]*httputil.ReverseProxy)

	for host, target := range routeMap {

		u, err := url.Parse(target)
		if err != nil {
			return nil, err
		}

		proxy := httputil.NewSingleHostReverseProxy(u)

		originalDirector := proxy.Director

		proxy.Director = func(req *http.Request) {

			originalDirector(req)

			// preserve real host routing inside backend
			req.Host = u.Host

			log.Printf("[proxy] %s %s -> %s",
				req.Method,
				req.URL.Path,
				target,
			)
		}

		proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("[proxy error] %v", err)
			http.Error(w, "Bad Gateway", http.StatusBadGateway)
		}

		routes[host] = proxy
	}

	return &Router{routes: routes}, nil
}

// ServeHTTP routes by Host header
func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {

	host := req.Host

	proxy, ok := r.routes[host]
	if !ok {
		http.Error(w, "No route for host", http.StatusNotFound)
		return
	}

	proxy.ServeHTTP(w, req)
}