// Command redis-ha-probe validates the Sentinel path of the auth
// revocation store against a live Redis HA deployment: Sentinel
// discovery, ACL user, shared store id, and the combined revocation
// check. It is an operational probe (phase 5), not part of the
// server binaries.
//
//	docker run --rm --network cladone-auth-ha \
//	  -e REDIS_HA_APP_PASSWORD=... -v /tmp/redis-ha-probe:/probe:ro \
//	  alpine:3 /probe \
//	  -sentinels redis-sentinel-1:26379,redis-sentinel-2:26379,redis-sentinel-3:26379
//
// With Sentinel authentication or TLS, add -sentinel-user,
// -sentinel-password-env (pointing at an env var), -tls, -tls-ca and
// -tls-server-name as needed.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"cladone/gate-one/internal/authn"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "redis-ha-probe:", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		sentinels = flag.String(
			"sentinels", "",
			"comma-separated sentinel host:port list")
		master = flag.String(
			"master", "authmaster", "sentinel master name")
		sentinelUser = flag.String(
			"sentinel-user", "",
			"ACL user for the sentinels (empty = no sentinel auth)")
		sentinelPassEnv = flag.String(
			"sentinel-password-env", "",
			"environment variable holding the sentinel password")
		user    = flag.String("user", "app", "ACL user")
		passEnv = flag.String(
			"password-env", "REDIS_HA_APP_PASSWORD",
			"environment variable holding the ACL password")
		prefix = flag.String(
			"prefix", "cladone:auth:v1:",
			"shared key prefix (must be allowed by the ACL)")
		useTLS = flag.Bool(
			"tls", false, "speak TLS to the sentinels and Redis")
		tlsCa = flag.String(
			"tls-ca", "", "PEM CA bundle (default: system roots)")
		tlsServerName = flag.String(
			"tls-server-name", "", "TLS server name override")
	)
	flag.Parse()

	if *sentinels == "" {
		return fmt.Errorf("-sentinels is required")
	}
	password := os.Getenv(*passEnv)
	if password == "" {
		return fmt.Errorf("environment variable %s is empty", *passEnv)
	}
	var sentinelPassword string
	if *sentinelPassEnv != "" {
		sentinelPassword = os.Getenv(*sentinelPassEnv)
		if sentinelPassword == "" {
			return fmt.Errorf(
				"environment variable %s is empty", *sentinelPassEnv)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	store, err := authn.OpenRedisStore(ctx, authn.RedisConfig{
		SentinelAddrs:    strings.Split(*sentinels, ","),
		MasterName:       *master,
		SentinelUsername: *sentinelUser,
		SentinelPassword: sentinelPassword,
		Username:         *user,
		Password:         password,
		Prefix:           *prefix,
		DialTimeout:      2 * time.Second,
		ReadTimeout:      2 * time.Second,
		WriteTimeout:     2 * time.Second,
		TLS:              *useTLS,
		TLSCaFile:        *tlsCa,
		TLSServerName:    *tlsServerName,
	})
	if err != nil {
		return fmt.Errorf("open via sentinel: %w", err)
	}
	defer store.Close()
	fmt.Printf("sentinel discovery OK (master %q, store %s)\n",
		*master, store.StoreID())

	const issuer = "https://probe.invalid/t/mycompany"
	sid := fmt.Sprintf("probe-%d", time.Now().UnixNano())

	if err := store.Revoke(
		ctx, issuer, sid, "", time.Now().Add(time.Minute),
	); err != nil {
		return fmt.Errorf("revoke sid: %w", err)
	}
	revoked, err := store.CheckRevoked(ctx, issuer, sid, "", time.Time{})
	if err != nil {
		return fmt.Errorf("check sid: %w", err)
	}
	if !revoked {
		return fmt.Errorf("sid not reported as revoked")
	}
	fmt.Println("sid revocation OK")

	sub := fmt.Sprintf("probe-sub-%d", time.Now().UnixNano())
	before := time.Now().Add(-time.Minute)
	if err := store.RevokeSubject(
		ctx, issuer, sub, time.Now(), time.Now().Add(time.Minute),
	); err != nil {
		return fmt.Errorf("revoke sub: %w", err)
	}
	revoked, err = store.CheckRevoked(ctx, issuer, "", sub, before)
	if err != nil {
		return fmt.Errorf("check old token: %w", err)
	}
	if !revoked {
		return fmt.Errorf("old token not revoked")
	}
	revoked, err = store.CheckRevoked(
		ctx, issuer, "", sub, time.Now().Add(time.Minute))
	if err != nil {
		return fmt.Errorf("check new token: %w", err)
	}
	if revoked {
		return fmt.Errorf("new token after logout was revoked")
	}
	fmt.Println("sub revocation (issuedAt boundary) OK")
	fmt.Println("REDIS HA PROBE: SUCCESS")
	return nil
}
