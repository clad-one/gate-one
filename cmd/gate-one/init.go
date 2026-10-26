package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"cladone/gate-one/internal/core"
	"cladone/gate-one/internal/proxy"
)

// runInit writes a minimal, working api-routes.json.
//
// Two templates:
//
//	static — a public reverse proxy, ZERO authentication dependency;
//	dev    — the embedded dev IdP (loopback), login form alice/bob.
//
// The generated file is the smallest thing that starts with the
// binary: no oidc block, no auth-bridge, no token-broker.
func runInit(args []string) int {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	host := fs.String("host", "app.localhost", "public application host")
	backend := fs.String("backend", "http://127.0.0.1:8080", "backend base URL")
	static := fs.Bool("static", false, "public site, no authentication")
	out := fs.String("out", "api-routes.json", "output config file")
	port := fs.String("port", "3000", "public listen port (dev login URL)")
	printOnly := fs.Bool("print", false, "print the config, do not write a file")
	force := fs.Bool("force", false, "overwrite an existing file")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	hostName := normalizeInitHost(*host)
	if hostName == "" {
		fmt.Fprintln(os.Stderr, "init: --host is required")
		return 2
	}
	if !strings.HasPrefix(*backend, "http://") &&
		!strings.HasPrefix(*backend, "https://") {
		fmt.Fprintf(os.Stderr, "init: --backend %q must be an http(s) URL\n", *backend)
		return 2
	}

	type route struct {
		Host      string         `json:"host"`
		Path      string         `json:"path"`
		Frontend  bool           `json:"frontend,omitempty"`
		Backend   string         `json:"backend"`
		Auth      *struct{}      `json:"auth,omitempty"`
		UserBadge map[string]any `json:"userBadge,omitempty"`
	}
	type provider struct {
		Type         string         `json:"type"`
		LoginBaseURL string         `json:"loginBaseUrl"`
		CookieDomain string         `json:"cookieDomain"`
		Dev          map[string]any `json:"dev,omitempty"`
	}
	type config struct {
		AuthProvider *provider `json:"authProvider,omitempty"`
		Routes       []route   `json:"routes"`
	}

	cfg := config{}
	routeCfg := route{
		Host: hostName, Path: "/*", Frontend: true, Backend: *backend,
	}

	if *static {
		cfg.Routes = []route{routeCfg}
	} else {
		cookieDomain, loginHost := deriveDevHosts(hostName)
		loginBase := fmt.Sprintf("http://%s:%s", loginHost, *port)
		cfg.AuthProvider = &provider{
			Type:         "dev",
			LoginBaseURL: loginBase,
			CookieDomain: cookieDomain,
		}
		routeCfg.Auth = &struct{}{}
		routeCfg.UserBadge = map[string]any{
			"position":    "right",
			"claims":      []string{"preferred_username", "email"},
			"logoutLabel": "Sign out",
		}
		cfg.Routes = []route{routeCfg}
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "init: %v\n", err)
		return 1
	}
	data = append(data, '\n')

	if *printOnly {
		_, _ = os.Stdout.Write(data)
		return 0
	}

	if !*force {
		if _, err := os.Stat(*out); err == nil {
			fmt.Fprintf(os.Stderr,
				"init: %s already exists (use --force to overwrite)\n", *out)
			return 1
		}
	}
	if err := os.WriteFile(*out, data, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "init: %v\n", err)
		return 1
	}

	fmt.Printf("wrote %s\n\nnext:\n", *out)
	if *port == "3000" {
		fmt.Printf("  gate-one -config %s\n\n", *out)
	} else {
		// The dev login URL embeds the public port; the listen
		// address must use the same one.
		fmt.Printf("  gate-one -config %s -addr 127.0.0.1:%s\n\n",
			*out, *port)
	}
	if *static {
		fmt.Printf("open http://%s:%s (public — no authentication)\n",
			hostName, *port)
	} else {
		fmt.Printf("open http://%s:%s\n", hostName, *port)
		fmt.Printf("login http://%s:%s/login\n", devLoginHost(hostName), *port)
		fmt.Println("accounts: alice/alice (user), bob/bob (admin)")
	}
	if !strings.HasSuffix(hostName, ".localhost") {
		fmt.Printf(
			"\nnote: %s must resolve to this machine (DNS or /etc/hosts)\n",
			hostName)
	}
	return 0
}

func normalizeInitHost(h string) string {
	h = strings.TrimSpace(strings.ToLower(h))
	h = strings.TrimPrefix(h, "http://")
	h = strings.TrimPrefix(h, "https://")
	h = strings.TrimSuffix(h, "/")
	if i := strings.IndexAny(h, "/?#"); i >= 0 {
		h = h[:i]
	}
	// drop a port: the route host is compared without it.
	if i := strings.LastIndex(h, ":"); i > 0 &&
		!strings.Contains(h[i:], "]") {
		h = h[:i]
	}
	return strings.Trim(h, ".")
}

// deriveDevHosts splits a public host into the shared cookie domain
// and the dedicated login host:
//
//	app.localhost       -> app.localhost / login.app.localhost
//	app.demo.localhost  -> demo.localhost / login.demo.localhost
//	app.acme.com        -> acme.com / login.acme.com
func deriveDevHosts(host string) (cookieDomain, loginHost string) {
	labels := strings.Split(host, ".")
	if len(labels) >= 3 {
		cookieDomain = strings.Join(labels[1:], ".")
	} else {
		cookieDomain = host
	}
	return cookieDomain, "login." + cookieDomain
}

func devLoginHost(host string) string {
	_, login := deriveDevHosts(host)
	return login
}

// runDoctor performs a deep readiness check without starting the
// server: config grammar, provider construction, provider health and
// token-broker reachability (proxy.New already validates delegated
// providers). It is the missing step between -check and a 502.
func runDoctor(args []string) int {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	configPath := fs.String("config", "api-routes.json", "routes file path")
	authBridge := fs.String("authBridge", "", "auth-bridge base URL override")
	addr := fs.String("addr", "127.0.0.1:3000", "listen address (dev safety check)")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	cfg, err := loadConfig(*configPath, *authBridge)
	if err != nil {
		fmt.Fprintf(os.Stderr, "doctor: config: %v\n", err)
		return 1
	}
	fmt.Println("config: OK")

	gw, err := newGateway(cfg, *authBridge, *addr, false)
	if err != nil {
		fmt.Fprintf(os.Stderr, "doctor: provider/routes: %v\n", err)
		return 1
	}
	fmt.Printf("provider: %s (login %s)\n",
		gw.ProviderName(), gw.ProviderLoginURL())

	if err := gw.CheckProvider(); err != nil {
		fmt.Fprintf(os.Stderr, "provider health: FAIL: %v\n", err)
		return 1
	}
	fmt.Println("provider health: OK")

	if len(cfg.Routes) == 0 {
		fmt.Fprintln(os.Stderr, "doctor: no routes")
		return 1
	}
	fmt.Printf("routes: %d compiled\n", len(cfg.Routes))
	fmt.Println("doctor: ready")
	return 0
}

func loadConfig(path, authBridge string) (*core.Config, error) {
	return core.LoadWithOptions(
		path, core.LoadOptions{AuthBridgeURL: authBridge})
}

func newGateway(
	cfg *core.Config,
	authBridge, addr string,
	devRemote bool,
) (*proxy.Gateway, error) {
	return proxy.New(
		cfg,
		proxy.WithAuthBridgeURL(authBridge),
		proxy.WithListenAddr(addr),
		proxy.WithDevRemote(devRemote),
	)
}
