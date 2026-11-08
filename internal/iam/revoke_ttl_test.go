package iam

import (
	"context"
	"testing"
	"time"

	"cladone/gate-one/pkg/authstate"

	"github.com/alicebob/miniredis/v2"
)

func ttlTestConfig(mr *miniredis.Miniredis, refresh, session int) *Config {
	return &Config{
		PublicURL: "https://iam.test",
		Tenants: []Tenant{{
			ID:                "mycompany",
			ClientID:          "gate-one",
			RedirectURIs:      []string{"https://login.test/callback"},
			Google:            GoogleConfig{ClientID: "google-client"},
			RefreshTokenTTL:   refresh,
			SessionTTLSeconds: session,
		}},
		Redis: &RedisConfig{
			URL:        "redis://" + mr.Addr() + "/0",
			Prefix:     "test:iam:",
			AuthPrefix: "test:auth:v1:",
		},
	}
}

func revokedSubTTL(t *testing.T, mr *miniredis.Miniredis, sub string) time.Duration {
	t.Helper()
	key := authstate.Key(
		"test:auth:v1:", "revoked:sub", "https://iam.test/t/mycompany", sub)
	if !mr.Exists(key) {
		t.Fatalf("revocation key %q missing", key)
	}
	return mr.TTL(key)
}

// The CLI revoke default must read the tenant refresh-token TTL: a
// revocation shorter than the refresh token lets it mint a new session
// after the logout.
func TestRevokeDefaultTTLUsesRefreshToken(t *testing.T) {
	mr := miniredis.RunT(t)
	cfg := ttlTestConfig(mr, 7200, 3600) // refresh 2h, session 1h

	if err := RevokeWithConfig(
		context.Background(), cfg, "mycompany", "", "sub-ttl", 0,
	); err != nil {
		t.Fatal(err)
	}
	ttl := revokedSubTTL(t, mr, "sub-ttl")
	if ttl < 7100*time.Second || ttl > 7200*time.Second {
		t.Fatalf("revocation ttl = %s, want ~2h (refresh token)", ttl)
	}
}

// A refresh TTL shorter than the session must not shorten the
// revocation below the session lifetime.
func TestRevokeDefaultTTLNeverShorterThanSession(t *testing.T) {
	mr := miniredis.RunT(t)
	cfg := ttlTestConfig(mr, 600, 3600) // refresh 10m, session 1h

	if err := RevokeWithConfig(
		context.Background(), cfg, "mycompany", "", "sub-session", 0,
	); err != nil {
		t.Fatal(err)
	}
	ttl := revokedSubTTL(t, mr, "sub-session")
	if ttl < 3500*time.Second || ttl > 3600*time.Second {
		t.Fatalf("revocation ttl = %s, want ~1h (session floor)", ttl)
	}
}

func TestRevokeExplicitTTLIsHonored(t *testing.T) {
	mr := miniredis.RunT(t)
	cfg := ttlTestConfig(mr, 7200, 3600)

	if err := RevokeWithConfig(
		context.Background(), cfg, "mycompany", "", "sub-explicit", time.Hour,
	); err != nil {
		t.Fatal(err)
	}
	ttl := revokedSubTTL(t, mr, "sub-explicit")
	if ttl < 3500*time.Second || ttl > 3600*time.Second {
		t.Fatalf("revocation ttl = %s, want ~1h (explicit)", ttl)
	}
}

func TestTenantRevocationTTL(t *testing.T) {
	cfg := &Config{Tenants: []Tenant{{
		ID:                "mycompany",
		RefreshTokenTTL:   7200,
		SessionTTLSeconds: 3600,
	}}}
	if d, err := TenantRevocationTTL(cfg, "mycompany"); err != nil || d != 2*time.Hour {
		t.Fatalf("ttl = %s, %v; want 2h", d, err)
	}
	if _, err := TenantRevocationTTL(cfg, "nope"); err == nil {
		t.Fatal("unknown tenant accepted")
	}
}
