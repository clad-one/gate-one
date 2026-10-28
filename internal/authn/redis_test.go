package authn

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
)

func TestAC_AUTH_18_RedisRevocationStore(t *testing.T) {
	mr := miniredis.RunT(t)
	ctx := context.Background()
	cfg := RedisConfig{
		URL:    "redis://" + mr.Addr() + "/0",
		Prefix: "test:auth:v1:",
	}
	a, err := OpenRedisStore(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := OpenRedisStore(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	if a.StoreID() == "" || a.StoreID() != b.StoreID() {
		t.Fatalf("store id not shared: %q / %q", a.StoreID(), b.StoreID())
	}

	exp := time.Now().Add(time.Hour)
	if err := a.Revoke(ctx, "https://issuer.test", "sid-1", "sub-1", exp); err != nil {
		t.Fatal(err)
	}
	// Instance B sees A's revocation immediately.
	revoked, err := b.IsRevoked(ctx, "https://issuer.test", "sid-1", "")
	if err != nil || !revoked {
		t.Fatalf("sid after revoke = %v, %v", revoked, err)
	}
	revoked, err = b.IsRevoked(ctx, "https://issuer.test", "", "sub-1")
	if err != nil || !revoked {
		t.Fatalf("sub after revoke = %v, %v", revoked, err)
	}
	revoked, err = b.IsRevoked(ctx, "https://other.test", "sid-1", "")
	if err != nil || revoked {
		t.Fatalf("cross-issuer = %v, %v", revoked, err)
	}

	// JTI anti-replay.
	ok, err := a.UseJTI(ctx, "https://issuer.test", "jti-1", exp)
	if err != nil || !ok {
		t.Fatalf("first jti = %v, %v", ok, err)
	}
	ok, err = b.UseJTI(ctx, "https://issuer.test", "jti-1", exp)
	if err != nil || ok {
		t.Fatalf("replayed jti = %v, %v", ok, err)
	}

	// Redis outage is an error (fail-closed in the proxy).
	mr.Close()
	if _, err := b.IsRevoked(ctx, "https://issuer.test", "sid-1", ""); err == nil {
		t.Fatal("IsRevoked after Redis shutdown = nil, want error")
	}
}

func TestAC_AUTH_18_RedisTTL(t *testing.T) {
	mr := miniredis.RunT(t)
	ctx := context.Background()
	s, err := OpenRedisStore(ctx, RedisConfig{
		URL: "redis://" + mr.Addr() + "/0",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	if err := s.Revoke(ctx, "iss", "sid-ttl", "",
		time.Now().Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	if ok, _ := s.IsRevoked(ctx, "iss", "sid-ttl", ""); !ok {
		t.Fatal("not revoked before TTL")
	}
	mr.FastForward(3 * time.Second)
	if ok, _ := s.IsRevoked(ctx, "iss", "sid-ttl", ""); ok {
		t.Fatal("still revoked after TTL")
	}
}

func TestAC_AUTH_24_SubjectRevocationTimestamp(t *testing.T) {
	mr := miniredis.RunT(t)
	ctx := context.Background()
	s, err := OpenRedisStore(ctx, RedisConfig{
		URL: "redis://" + mr.Addr() + "/0",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	revokedAt := time.Now().Truncate(time.Second)
	if err := s.RevokeSubject(ctx, "iss", "user-1",
		revokedAt, revokedAt.Add(24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	// Old sessions/tokens are revoked...
	old, err := s.IsSubjectRevoked(ctx, "iss", "user-1",
		revokedAt.Add(-time.Hour))
	if err != nil || !old {
		t.Fatalf("old token = %v, %v", old, err)
	}
	// ...but a login issued after the global logout is allowed.
	fresh, err := s.IsSubjectRevoked(ctx, "iss", "user-1",
		revokedAt.Add(time.Second))
	if err != nil || fresh {
		t.Fatalf("fresh token = %v, %v", fresh, err)
	}
	// A different user is untouched.
	other, err := s.IsSubjectRevoked(ctx, "iss", "user-2", time.Time{})
	if err != nil || other {
		t.Fatalf("other user = %v, %v", other, err)
	}
}
