// Command fake-google serves the reusable fake Google OIDC provider for
// the local Compose stack and E2E runs. It is not a production IdP.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"cladone/gate-one/internal/testutil/fakegoogle"
)

func main() {
	addr := flag.String("addr", ":9000", "listen address")
	issuer := flag.String(
		"issuer", "http://idp.localhost:9000",
		"public issuer URL (must be reachable by the browser and the IAM)")
	configPath := flag.String("config", "", "optional JSON config (users, clientId)")
	control := flag.Bool(
		"control", true,
		"enable /__control endpoints (failure injection, user selection)")
	flag.Parse()

	cfg := fakegoogle.Config{Issuer: *issuer}
	if *configPath != "" {
		data, err := os.ReadFile(*configPath)
		if err != nil {
			log.Fatal(err)
		}
		if err := json.Unmarshal(data, &cfg); err != nil {
			log.Fatalf("%s: %v", *configPath, err)
		}
	}
	// The flag is authoritative: the public URL is a deployment detail,
	// not a realm property.
	if strings.TrimSpace(*issuer) != "" {
		cfg.Issuer = *issuer
	}

	srv, err := fakegoogle.New(cfg)
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.Handle("/", srv)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	if *control {
		mux.HandleFunc("/__control/", controlHandler(srv))
	}

	httpSrv := &http.Server{
		Addr:              *addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	stopped := make(chan struct{})
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, os.Interrupt)
	go func() {
		<-sig
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(ctx)
		close(stopped)
	}()

	log.Printf("fake-google listening on %s (issuer %s, control=%t)",
		*addr, cfg.Issuer, *control)
	if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
	<-stopped
}

func controlHandler(srv *fakegoogle.Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		q := r.URL.Query()
		action := strings.TrimPrefix(r.URL.Path, "/__control/")
		switch action {
		case "fail":
			if q.Has("discovery") {
				srv.SetFailDiscovery(truthy(q.Get("discovery")))
			}
			if q.Has("jwks") {
				srv.SetFailJWKS(truthy(q.Get("jwks")))
			}
			if q.Has("token") {
				srv.SetFailToken(truthy(q.Get("token")))
			}
			if q.Has("invalidJwks") {
				srv.SetInvalidJWKS(truthy(q.Get("invalidJwks")))
			}
		case "user":
			email := strings.TrimSpace(q.Get("email"))
			if email == "" {
				http.Error(w, "email is required", http.StatusBadRequest)
				return
			}
			if err := srv.SetDefaultUser(email); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
		case "rotate":
			if err := srv.RotateKey(); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		case "retire":
			srv.RetireOldKeys()
		case "slow":
			ms, _ := strconv.Atoi(q.Get("ms"))
			srv.SetSlow(time.Duration(ms) * time.Millisecond)
		case "state":
			// handled below
		default:
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(srv.Status())
	}
}

func truthy(raw string) bool {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}
