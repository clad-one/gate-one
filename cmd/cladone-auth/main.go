// Command cladone-auth runs the small multi-tenant OIDC broker.
//
// It federates Google (V1), applies per-tenant policy (roles, tenant,
// audiences), and re-emits Ed25519-signed JWTs. Gate One trusts only
// this issuer.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"cladone/gate-one/internal/broker"
	"cladone/gate-one/internal/ops"
)

// Set by the release build.
var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "keygen":
			os.Exit(runKeygen(os.Args[2:]))
		case "revoke":
			os.Exit(runRevoke(os.Args[2:]))
		case "user":
			os.Exit(runUser(os.Args[2:]))
		case "version", "-version", "--version":
			fmt.Printf("cladone-auth %s (commit %s, built %s)\n", version, commit, date)
			return
		case "help", "-h", "--help":
			fmt.Println("usage: cladone-auth [keygen|revoke|user|version] [-config ...]")
			return
		}
	}

	configPath := flag.String("config", "cladone-auth.json", "broker config path")
	addr := flag.String("addr", "", "listen address (default: config listen or :8081)")
	pprofAddr := flag.String(
		"pprof-addr", "",
		"optional pprof listen address (e.g. 127.0.0.1:6061)")
	flag.Parse()

	cfg, err := broker.Load(*configPath)
	if err != nil {
		log.Fatal(err)
	}
	if *addr == "" {
		*addr = cfg.Listen
	}
	if *addr == "" {
		*addr = ":8081"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	b, err := broker.New(ctx, cfg)
	if err != nil {
		log.Fatal(err)
	}
	defer b.Close()

	srv := &http.Server{
		Addr:              *addr,
		Handler:           b.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	stopped := make(chan struct{})
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, os.Interrupt)
	go func() {
		<-sig
		sctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
		close(stopped)
	}()

	fmt.Printf("Cladone Auth broker listening on %s (public %s)\n",
		*addr, cfg.PublicURL)

	psrv, err := ops.StartPprof(*pprofAddr)
	if err != nil {
		log.Fatal(err)
	}
	if psrv != nil {
		defer psrv.Close()
		log.Printf("pprof listening on %s", *pprofAddr)
	}

	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
	<-stopped
}

func runKeygen(args []string) int {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	out := fs.String("out", "", "output key file (base64 raw Ed25519 seed)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *out == "" {
		fmt.Fprintln(os.Stderr, "keygen: -out is required")
		return 2
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Fprintln(os.Stderr, "keygen:", err)
		return 1
	}
	if err := os.MkdirAll(filepath.Dir(*out), 0o700); err != nil &&
		filepath.Dir(*out) != "." {
		fmt.Fprintln(os.Stderr, "keygen:", err)
		return 1
	}
	body := base64.RawURLEncoding.EncodeToString(priv.Seed()) + "\n"
	if err := os.WriteFile(*out, []byte(body), 0o600); err != nil {
		fmt.Fprintln(os.Stderr, "keygen:", err)
		return 1
	}
	fmt.Printf("private key: %s\n", *out)
	fmt.Printf("public key:  %s\n", base64.RawURLEncoding.EncodeToString(pub))
	return 0
}

func runRevoke(args []string) int {
	fs := flag.NewFlagSet("revoke", flag.ContinueOnError)
	configPath := fs.String("config", "cladone-auth.json", "broker config path")
	tenant := fs.String("tenant", "", "tenant id")
	sid := fs.String("sid", "", "session id to revoke")
	sub := fs.String("sub", "", "user subject to revoke")
	ttl := fs.Duration("ttl", 0,
		"revocation lifetime (0 = tenant refresh-token TTL, "+
			"never shorter than the session)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *tenant == "" || (*sid == "" && *sub == "") {
		fmt.Fprintln(os.Stderr, "revoke: -tenant and one of -sid/-sub are required")
		return 2
	}
	cfg, err := broker.Load(*configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "revoke:", err)
		return 1
	}
	autoTTL, err := broker.TenantRevocationTTL(cfg, *tenant)
	if err != nil {
		fmt.Fprintln(os.Stderr, "revoke:", err)
		return 1
	}
	if *ttl > 0 && *ttl < autoTTL {
		fmt.Fprintf(os.Stderr,
			"warning: -ttl %s is shorter than the tenant revocation TTL %s "+
				"(refresh token): old refresh tokens may become valid again\n",
			*ttl, autoTTL)
	}
	effective := *ttl
	if effective <= 0 {
		effective = autoTTL
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := broker.RevokeWithConfig(
		ctx, cfg, *tenant, *sid, *sub, *ttl,
	); err != nil {
		fmt.Fprintln(os.Stderr, "revoke:", err)
		return 1
	}
	fmt.Printf("revoked tenant=%s sid=%q sub=%q ttl=%s\n",
		*tenant, *sid, *sub, effective)
	return 0
}
