package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"cladone/gate-one/internal/authn"
	"cladone/gate-one/internal/core"
	"cladone/gate-one/internal/ops"
	"cladone/gate-one/internal/proxy"
)

// Set by the release build (-ldflags "-X main.version=..."). The
// source tree builds a plain "dev" binary.
var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

func printVersion() {
	fmt.Printf("gate-one %s (commit %s, built %s)\n", version, commit, date)
}

// printReady is the onboarding banner: the URLs a human should open,
// the login page and (in dev) the accounts. Production logs stay
// short.
func printReady(cfg *core.Config, addr string) {
	ap := cfg.AuthProvider
	if ap == nil {
		return
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		host, port = addr, "3000"
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "localhost"
	}

	if ap.Type == "dev" {
		fmt.Println()
		fmt.Println("READY (dev auth — loopback only)")
		seen := map[string]bool{}
		for i := range cfg.Routes {
			h := cfg.Routes[i].Host
			if seen[h] {
				continue
			}
			seen[h] = true
			fmt.Printf("  http://%s:%s\n", h, port)
		}
		login := ap.LoginURL
		if login == "" {
			login = "http://login." + ap.CookieDomain
			if port != "" {
				login += ":" + port
			}
			login += "/login"
		}
		fmt.Printf("  login: %s\n", login)
		fmt.Println("  accounts: alice/alice (user), bob/bob (admin)")
		fmt.Println()
		return
	}

	fmt.Printf(
		"AUTH provider=%s login=%s\n",
		ap.Type, ap.LoginURL)
}

func main() {

	// Subcommands are dispatched before flag parsing so the
	// historical flag mode (`gate-one -config ...`) is untouched.
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "init":
			os.Exit(runInit(os.Args[2:]))
		case "doctor":
			os.Exit(runDoctor(os.Args[2:]))
		case "version":
			printVersion()
			return
		case "keygen":
			os.Exit(runKeygen(os.Args[2:]))
		case "sign":
			os.Exit(runSign(os.Args[2:]))
		case "verify":
			os.Exit(runVerify(os.Args[2:]))
		case "billing":
			os.Exit(runBilling(os.Args[2:]))
		case "allowance":
			os.Exit(runAllowance(os.Args[2:]))
		case "meter":
			os.Exit(runMeter(os.Args[2:]))
		}
	}

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
	// devAllowRemote: explicit opt-in for the embedded dev IdP on a
	// non-loopback bind (demo only; never production).
	devAllowRemote := flag.Bool(
		"dev-allow-remote",
		false,
		"allow the dev auth provider on a non-loopback listen address",
	)
	// pprofAddr: opt-in profiling/goroutine dump endpoint (phase 4.5
	// leak diagnosis). Empty = disabled, so nothing listens by
	// default.
	pprofAddr := flag.String(
		"pprof-addr",
		"",
		"optional pprof listen address (e.g. 127.0.0.1:6060)",
	)
	showVersion := flag.Bool(
		"version",
		false,
		"print the version and exit",
	)
	flag.Parse()

	if *showVersion {
		printVersion()
		return
	}

	// The embedded dev provider is loopback-only. If the user did not
	// explicitly choose an address, bind loopback: `init --dev` then
	// works with the default command, while Docker (non-dev) keeps
	// :3000.
	addrSet := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "addr" {
			addrSet = true
		}
	})

	cfg, err := core.LoadWithOptions(
		*configPath,
		core.LoadOptions{AuthBridgeURL: *authBridge},
	)

	if err != nil {
		log.Fatal(err)
	}

	if !addrSet && cfg.AuthProvider != nil &&
		cfg.AuthProvider.Type == "dev" {
		*addr = "127.0.0.1:3000"
	}

	printRoutes(cfg)

	if *check {
		if err := cfg.VerifyPluginManifests(); err != nil {
			fmt.Fprintf(os.Stderr, "check: %v\n", err)
			os.Exit(1)
		}
		checkOIDCRefreshTTL(os.Stdout, cfg)
		fmt.Println("Cladone G.O. Gate One: configuration is valid")
		return
	}

	log.Printf("Loaded %d routes", len(cfg.Routes))

	opts := []proxy.Option{
		proxy.WithAuthBridgeURL(*authBridge),
		proxy.WithLogBody(*logBody),
		proxy.WithListenAddr(*addr),
		proxy.WithDevRemote(*devAllowRemote),
	}

	// Hot-reloadable config (SIGHUP): the file can be a mounted
	// volume — adding a route = edit + kill -s HUP, no rebuild. An
	// invalid config is REFUSED: the old one stays active (never an
	// outage over a typo).
	handler := &proxy.Reloadable{}

	// First gateway: reuse the config loaded/validated above (no second
	// load, hence no duplicated startup warnings).
	g, err := proxy.New(cfg, opts...)
	if err != nil {
		log.Fatal(err)
	}
	handler.Store(g)
	proxy.ResetAuthCache()

	// SIGHUP reload: re-read, validate, then swap (the previous config
	// stays active if the new one is refused).
	load := func() error {
		c, err := core.LoadWithOptions(
			*configPath,
			core.LoadOptions{AuthBridgeURL: *authBridge},
		)
		if err != nil {
			return err
		}
		g, err := proxy.New(c, opts...)
		if err != nil {
			return err
		}
		handler.Store(g)
		proxy.ResetAuthCache()
		return nil
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
				handler.Audit("reload_failed", err.Error(),
					http.StatusInternalServerError)
				continue
			}
			log.Printf("SIGHUP: configuration reloaded")
			handler.Audit("reload", "", http.StatusOK)
		}
	}()

	log.Printf("Cladone G.O. Gate One listening on %s", *addr)
	printReady(cfg, *addr)

	psrv, err := ops.StartPprof(*pprofAddr)
	if err != nil {
		log.Fatal(err)
	}
	if psrv != nil {
		defer psrv.Close()
		log.Printf("pprof listening on %s", *pprofAddr)
	}

	if err := srv.ListenAndServe(); err != nil &&
		err != http.ErrServerClosed {
		log.Fatal(err)
	}
	<-stopped
	if err := handler.Close(); err != nil {
		log.Printf("gateway close: %v", err)
	}
	log.Printf("Gateway shut down cleanly")
}

// checkOIDCRefreshTTL probes OIDC issuers when revocationTtlSeconds is
// absent. It is best-effort and never changes the -check exit status:
// an unreachable issuer is reported, not treated as a config error.
func checkOIDCRefreshTTL(w io.Writer, cfg *core.Config) {
	for _, ap := range cfg.AuthProviders {
		if ap == nil || ap.Type != "oidc" ||
			ap.RevocationTTLSeconds > 0 {
			continue
		}
		ctx, cancel := context.WithTimeout(
			context.Background(), 3*time.Second)
		ttl, err := authn.ProbeRefreshTTL(ctx, ap.Issuer, nil)
		cancel()
		if err != nil {
			fmt.Fprintf(w,
				"WARNING: cannot discover OIDC issuer %s (%s): %v; "+
					"cannot verify its refresh-token TTL. Set "+
					"authProvider.revocationTtlSeconds (or "+
					"authProviders[].revocationTtlSeconds) explicitly if the "+
					"IdP does not advertise it.\n",
				ap.Issuer, ap.ID, err)
			continue
		}
		if ttl <= 0 {
			fmt.Fprintf(w, "WARNING: %s\n",
				authn.RefreshTTLWarning(ap.Issuer, ap.ID))
		}
	}
}

// printRoutes: the resolved config, one line per route — reviewing
// a config is done by reading startup output (or -check).
func printRoutes(cfg *core.Config) {
	out := &strings.Builder{}
	if t := cfg.Turnstile; t.Active() {
		fmt.Fprintf(out,
			"TURNSTILE hosts=%v paths=%v methods=%v forms=%d action=%q\n",
			t.Hosts, t.Paths, t.Methods, len(t.Forms), t.Action)
	}
	if len(cfg.AuthProviders) > 0 {
		for _, ap := range cfg.AuthProviders {
			if ap == nil {
				continue
			}
			label := ap.ID
			if label == "" {
				label = "default"
			}
			fmt.Fprintf(out,
				"AUTH PROVIDER %-12s %-6s login=%s issuer=%s",
				label, ap.Type, ap.LoginURL, ap.Issuer)
			if group := ap.SSOGroupID(); group != "" {
				fmt.Fprintf(out, " ssoGroup=%s", group)
			}
			if ap.DefaultAppURL != "" {
				fmt.Fprintf(out, " defaultApp=%s", ap.DefaultAppURL)
			}
			fmt.Fprintln(out)
		}
	} else if ap := cfg.AuthProvider; ap != nil {
		fmt.Fprintf(out, "AUTH PROVIDER %s  login=%s  issuer=%s\n",
			ap.Type, ap.LoginURL, ap.Issuer)
	}
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
			if ap := cfg.AuthProviderFor(r); ap != nil {
				p = append(p, "provider:"+ap.ID)
			}
		}
		if r.StripPrefix != "" {
			p = append(p, "stripPrefix")
		}
		if r.Upstream != nil {
			p = append(p, "upstream")
			if d := r.UpstreamTokenBroker(); d != nil {
				p = append(p, "tokenBroker:"+d.Provider)
			}
			if r.UpstreamRewriteBody() != nil {
				p = append(p, "rewriteBody")
			}
			if r.Upstream.RewriteCookies != nil {
				p = append(p, "rewriteCookies")
			}
			if r.Upstream.StripCookies == "none" {
				p = append(p, "cookies:forward")
			} else {
				p = append(p, "cookies:stripped")
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
		if r.CSP != nil && r.CSP.Mode != "off" {
			p = append(p, "csp:"+r.CSP.Mode)
			if r.CSP.ReportOnly {
				p = append(p, "csp:report-only")
			}
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
		fmt.Fprintf(out, "%-42s %-26s %-44s %s",
			r.Host, r.Path, r.Backend, strings.Join(p, ","))
		if src := r.WildcardSource(); src != "" {
			fmt.Fprintf(out, "  [wildcard %s]", src)
		}
		fmt.Fprintln(out)
	}
	if f := cfg.Feed; f != nil {
		fmt.Fprintf(out,
			"PUBLISHER FEED %s key=%s validUntil=%s plugins=%d revocations=%d\n",
			f.Publisher, f.Signature.KeyID, f.ValidUntil,
			len(f.Plugins), len(f.Revocations))
	}
	fmt.Fprint(os.Stdout, out.String())
}
