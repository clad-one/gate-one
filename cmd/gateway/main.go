package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"cladone/gateway/internal/core"
	"cladone/gateway/internal/proxy"
)

func main() {

	configPath := flag.String(
		"config",
		"api-routes.json",
		"chemin du fichier de routes",
	)
	addr := flag.String(
		"addr",
		":3000",
		"adresse d'écoute",
	)
	// authBridge : base URL du service d'authentification. Défaut :
	// http://auth-bridge:3000 (nom de service du réseau Docker).
	// Surchargable en CLI pour les smoke tests (stub local).
	authBridge := flag.String(
		"authBridge",
		"",
		"base URL de auth-bridge (défaut http://auth-bridge:3000)",
	)
	// check : valide la configuration et affiche les routes
	// résolues, sans démarrer — fail-fast en CI, revue avant deploy.
	check := flag.Bool(
		"check",
		false,
		"valider la config et afficher les routes, sans démarrer",
	)
	// logBody : mode debug — logge aussi query/body des requêtes
	// (données potentiellement sensibles : désactivé par défaut).
	logBody := flag.Bool(
		"logBody",
		false,
		"logger query et body des requêtes (debug)",
	)
	flag.Parse()

	cfg, err := core.Load(*configPath)

	if err != nil {
		log.Fatal(err)
	}

	printRoutes(cfg)

	if *check {
		fmt.Println("configuration valide")
		return
	}

	log.Printf("Loaded %d routes", len(cfg.Routes))

	opts := []proxy.Option{
		proxy.WithAuthBridgeURL(*authBridge),
		proxy.WithLogBody(*logBody),
	}
	gw, err := proxy.New(cfg, opts...)

	if err != nil {
		log.Fatal(err)
	}

	// Timeouts serveur : ReadHeaderTimeout coupe le slowloris ;
	// PAS de Read/WriteTimeout globaux (ils tueraient les flux
	// longs : SSE, uploads) ; IdleTimeout recycle les connexions.
	srv := &http.Server{
		Addr:              *addr,
		Handler:           gw,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	log.Printf("Gateway listening on %s", *addr)

	log.Fatal(srv.ListenAndServe())
}

// printRoutes : la config résolue, une ligne par route — la revue
// d'une config se fait en lisant le démarrage (ou -check).
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
