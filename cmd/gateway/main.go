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

	// Config rechargeable à chaud (SIGHUP) : le fichier peut être un
	// volume monté — ajouter une route = éditer + kill -s HUP, sans
	// rebuild. Une config invalide est REFUSÉE : l'ancienne reste
	// active (jamais d'interruption pour une typo).
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

	// Timeouts serveur : ReadHeaderTimeout coupe le slowloris ;
	// PAS de Read/WriteTimeout globaux (ils tueraient les flux
	// longs : SSE, uploads) ; IdleTimeout recycle les connexions.
	srv := &http.Server{
		Addr:              *addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	// Arrêt gracieux : SIGTERM (docker stop) termine les requêtes en
	// vol au lieu de les couper ; la marge (8 s) reste sous la
	// grâce par défaut de docker (10 s).
	stopped := make(chan struct{})
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, os.Interrupt)
	go func() {
		s := <-sig
		log.Printf("%s : arrêt gracieux (8 s max)…", s)
		ctx, cancel := context.WithTimeout(
			context.Background(), 8*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			log.Printf("shutdown: %v", err)
		}
		close(stopped)
	}()

	// Reload à chaud : SIGHUP re-charge la config (validée) et
	// bascule le routage atomiquement.
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)

	go func() {
		for range hup {
			if err := load(); err != nil {
				log.Printf(
					"SIGHUP : rechargement REFUSÉ (%v) — l'ancienne config reste active",
					err,
				)
				continue
			}
			log.Printf("SIGHUP : configuration rechargée")
		}
	}()

	log.Printf("Gateway listening on %s", *addr)

	if err := srv.ListenAndServe(); err != nil &&
		err != http.ErrServerClosed {
		log.Fatal(err)
	}
	<-stopped
	log.Printf("Gateway arrêtée proprement")
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
			if r.UpstreamRewriteBody() != nil {
				p = append(p, "rewriteBody")
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
