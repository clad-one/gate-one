package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"cladone/gateway/internal/core"
	"cladone/gateway/internal/proxy"
)

func main() {

	configPath := flag.String(
		"config",
		"api-routes.json",
		"routes file path",
	)
	addr := flag.String(
		"addr",
		":3000",
		"listen address",
	)
	// authBridge: base URL of the authentication service. Default:
	// http://auth-bridge:3000 (Docker network service name).
	// Overridable on the CLI for smoke tests (local stub).
	authBridge := flag.String(
		"authBridge",
		"",
		"auth-bridge base URL (default http://auth-bridge:3000)",
	)
	// check: validates the configuration and prints the resolved
	// routes, without starting — fail-fast in CI, review before deploy.
	check := flag.Bool(
		"check",
		false,
		"validate the config and print the routes, without starting",
	)
	// logBody: debug mode — also logs request query/body
	// (potentially sensitive data: disabled by default).
	logBody := flag.Bool(
		"logBody",
		false,
		"log request query and body (debug)",
	)
	flag.Parse()

	cfg, err := core.Load(*configPath)

	if err != nil {
		log.Fatal(err)
	}

	printRoutes(cfg)

	if *check {
		fmt.Println("configuration is valid")
		return
	}

	log.Printf("Loaded %d routes", len(cfg.Routes))

	opts := []proxy.Option{
		proxy.WithAuthBridgeURL(*authBridge),
		proxy.WithLogBody(*logBody),
	}

	// Hot-reloadable config (SIGHUP): the file can be a mounted
	// volume — adding a route = edit + kill -s HUP, no rebuild. An
	// invalid config is REFUSED: the old one stays active (never an
	// outage over a typo).
	handler := &proxy.Reloadable{}
	load := func() error {
		c, err := core.Load(*configPath)
		if err != nil {
			return err
		}
		g, err := proxy.New(c, opts...)
		if err != nil {
			return err
		}
		handler.Store(g)
		return nil
	}
	if err := load(); err != nil {
		log.Fatal(err)
	}

	// Server timeouts: ReadHeaderTimeout cuts slowloris;
	// NO global Read/WriteTimeouts (they would kill long
	// streams: SSE, uploads); IdleTimeout recycles connections.
	srv := &http.Server{
		Addr:              *addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	// Graceful shutdown: SIGTERM (docker stop) lets in-flight
	// requests finish instead of cutting them; the margin (8 s)
	// stays under docker's default grace period (10 s).
	stopped := make(chan struct{})
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, os.Interrupt)
	go func() {
		s := <-sig
		log.Printf("%s: graceful shutdown (8 s max)…", s)
		ctx, cancel := context.WithTimeout(
			context.Background(), 8*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			log.Printf("shutdown: %v", err)
		}
		close(stopped)
	}()

	// Hot reload: SIGHUP re-loads the (validated) config and
	// switches the routing atomically.
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)

	go func() {
		for range hup {
			if err := load(); err != nil {
				log.Printf(
					"SIGHUP: reload REFUSED (%v) — the previous config stays active",
					err,
				)
				continue
			}
			log.Printf("SIGHUP: configuration reloaded")
		}
	}()

	log.Printf("Gateway listening on %s", *addr)

	if err := srv.ListenAndServe(); err != nil &&
		err != http.ErrServerClosed {
		log.Fatal(err)
	}
	<-stopped
	log.Printf("Gateway shut down cleanly")
}

// printRoutes: the resolved config, one line per route — reviewing
// a config is done by reading startup output (or -check).
func printRoutes(cfg *core.Config) {
	out := &strings.Builder{}
	fmt.Fprintf(out, "%-42s %-26s %-44s %s\n",
		"HOST", "PATH", "BACKEND", "POLICIES")
	for i := range cfg.Routes {
		r := &cfg.Routes[i]
		var p []string
		if r.Frontend {
			p = append(p, "frontend")
		}
		if r.AutoHead {
			p = append(p, "autoHead")
		}
		if r.Auth != nil {
			p = append(p, "auth")
		}
		if r.Upstream != nil {
			p = append(p, "upstream")
			if r.UpstreamRewriteBody() != nil {
				p = append(p, "rewriteBody")
			}
			if r.Upstream.RewriteCookies != nil {
				p = append(p, "rewriteCookies")
			}
		}
		if r.OpenAPI != nil {
			p = append(p, "openapi")
		}
		if r.MCP != nil && r.MCP.Enabled {
			p = append(p, "mcp")
		}
		if r.PWA != nil && r.PWA.Enabled {
			p = append(p, "pwa")
		}
		if r.UserBadge != nil {
			p = append(p, "userBadge")
		}
		if r.UIGate != nil {
			p = append(p, "uiGate")
		}
		if r.AuthGuard != nil {
			p = append(p, "authGuard")
		}
		fmt.Fprintf(out, "%-42s %-26s %-44s %s\n",
			r.Host, r.Path, r.Backend, strings.Join(p, ","))
	}
	fmt.Fprint(os.Stdout, out.String())
}
