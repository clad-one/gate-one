// Package netchaos provides controllable fault injection for the
// authentication load/chaos tests: a TCP latency proxy (Redis slow),
// an HTTP handler delay (broker slow) and a mutable reverse proxy
// (broker key rotation behind a stable public URL).
//
// It is test support code: no production binary imports it.
package netchaos

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"
	"sync/atomic"
	"time"
)

// DelayProxy forwards TCP to a target, sleeping before each forwarded
// chunk. A request/response exchange therefore pays roughly twice the
// configured delay (one sleep per direction).
type DelayProxy struct {
	ln     net.Listener
	target string
	delay  atomic.Int64 // nanoseconds

	mu    sync.Mutex
	conns map[net.Conn]struct{}
	done  chan struct{}
	once  sync.Once
}

// NewDelayProxy starts a proxy to target (host:port) with the given
// initial per-direction delay.
func NewDelayProxy(target string, delay time.Duration) (*DelayProxy, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	p := &DelayProxy{
		ln:     ln,
		target: target,
		conns:  map[net.Conn]struct{}{},
		done:   make(chan struct{}),
	}
	p.SetDelay(delay)
	go p.serve()
	return p, nil
}

// Addr is the proxy's host:port, to be used by the client under test.
func (p *DelayProxy) Addr() string { return p.ln.Addr().String() }

// SetDelay changes the per-direction delay at runtime.
func (p *DelayProxy) SetDelay(d time.Duration) {
	if d < 0 {
		d = 0
	}
	p.delay.Store(int64(d))
}

// Delay returns the current per-direction delay.
func (p *DelayProxy) Delay() time.Duration {
	return time.Duration(p.delay.Load())
}

// Close stops accepting and closes every proxied connection.
func (p *DelayProxy) Close() {
	p.once.Do(func() {
		close(p.done)
		_ = p.ln.Close()
		p.mu.Lock()
		for c := range p.conns {
			_ = c.Close()
		}
		p.conns = map[net.Conn]struct{}{}
		p.mu.Unlock()
	})
}

func (p *DelayProxy) serve() {
	for {
		client, err := p.ln.Accept()
		if err != nil {
			return
		}
		upstream, err := net.Dial("tcp", p.target)
		if err != nil {
			_ = client.Close()
			continue
		}
		p.track(client, upstream)

		go func() {
			defer p.untrack(client, upstream)
			defer client.Close()
			defer upstream.Close()

			finished := make(chan struct{}, 2)
			go func() {
				p.pipe(upstream, client)
				finished <- struct{}{}
			}()
			go func() {
				p.pipe(client, upstream)
				finished <- struct{}{}
			}()
			<-finished
		}()
	}
}

func (p *DelayProxy) track(conns ...net.Conn) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, c := range conns {
		p.conns[c] = struct{}{}
	}
}

func (p *DelayProxy) untrack(conns ...net.Conn) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, c := range conns {
		delete(p.conns, c)
	}
}

func (p *DelayProxy) pipe(dst, src net.Conn) {
	buf := make([]byte, 32*1024)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			if d := p.Delay(); d > 0 {
				select {
				case <-time.After(d):
				case <-p.done:
					return
				}
			}
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// HTTPDelay wraps an http.Handler with a runtime-adjustable delay,
// applied before the handler runs (request path only).
type HTTPDelay struct {
	next  http.Handler
	delay atomic.Int64
}

// NewHTTPDelay wraps next; a nil next is an error at use time.
func NewHTTPDelay(next http.Handler) *HTTPDelay {
	return &HTTPDelay{next: next}
}

// SetDelay changes the delay applied to each request.
func (h *HTTPDelay) SetDelay(d time.Duration) {
	if d < 0 {
		d = 0
	}
	h.delay.Store(int64(d))
}

// Delay returns the current delay.
func (h *HTTPDelay) Delay() time.Duration {
	return time.Duration(h.delay.Load())
}

func (h *HTTPDelay) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if d := h.Delay(); d > 0 {
		select {
		case <-time.After(d):
		case <-r.Context().Done():
			return
		}
	}
	h.next.ServeHTTP(w, r)
}

// HTTPProxy is a reverse proxy with a runtime-swappable target. It
// gives the stack under test one stable public URL while the backend
// (a broker instance) is replaced, which is exactly a key rotation
// rollout.
type HTTPProxy struct {
	ln  net.Listener
	srv *http.Server

	proxy atomic.Pointer[httputil.ReverseProxy]
	once  sync.Once
}

// NewHTTPProxy starts a proxy forwarding to target (absolute URL).
func NewHTTPProxy(target string) (*HTTPProxy, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	p := &HTTPProxy{ln: ln}
	if err := p.SetTarget(target); err != nil {
		_ = ln.Close()
		return nil, err
	}
	p.srv = &http.Server{
		Handler:           p,
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		_ = p.srv.Serve(ln)
	}()
	return p, nil
}

// URL is the stable public base URL of the proxy.
func (p *HTTPProxy) URL() string {
	return "http://" + p.ln.Addr().String()
}

// SetTarget points the proxy at another backend.
func (p *HTTPProxy) SetTarget(target string) error {
	u, err := url.Parse(target)
	if err != nil {
		return err
	}
	if u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("netchaos: invalid proxy target %q", target)
	}
	rp := httputil.NewSingleHostReverseProxy(u)
	rp.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, err error) {
		http.Error(w, "netchaos proxy: "+err.Error(), http.StatusBadGateway)
	}
	p.proxy.Store(rp)
	return nil
}

func (p *HTTPProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rp := p.proxy.Load()
	if rp == nil {
		http.Error(w, "netchaos proxy: no target",
			http.StatusBadGateway)
		return
	}
	rp.ServeHTTP(w, r)
}

// Close stops the proxy.
func (p *HTTPProxy) Close() {
	p.once.Do(func() {
		if p.srv != nil {
			_ = p.srv.Close()
		}
	})
}
