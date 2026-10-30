// Package ops exposes opt-in operational endpoints. Everything here
// is disabled by default: nothing listens unless the operator asks.
package ops

import (
	"log"
	"net"
	"net/http"
	"net/http/pprof"
	"time"
)

// StartPprof serves the standard net/http/pprof handlers on addr. An
// empty addr disables profiling and returns (nil, nil). The returned
// server is closed by the caller on shutdown.
//
// Binding is synchronous: an unusable address is a startup error, not
// a background log line.
//
// Profiling exposes goroutine dumps and heap contents (which may
// contain request data): keep it on loopback or behind the private
// network, never on the public entrypoint.
func StartPprof(addr string) (*http.Server, error) {
	if addr == "" {
		return nil, nil
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	warnNonLoopback(addr)
	return ServePprof(ln), nil
}

// ServePprof serves the pprof handlers on an existing listener. It is
// exported for tests (ephemeral port) and for callers that own the
// listener lifecycle.
func ServePprof(ln net.Listener) *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)

	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	go func() {
		if err := srv.Serve(ln); err != nil &&
			err != http.ErrServerClosed {
			log.Printf("pprof: %v", err)
		}
	}()
	return srv
}

func warnNonLoopback(addr string) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return
	}
	if host == "" || host == "127.0.0.1" || host == "::1" ||
		host == "localhost" {
		return
	}
	log.Printf(
		"pprof: WARNING listening on non-loopback %s "+
			"(heap/goroutine dumps may expose request data)",
		addr)
}
