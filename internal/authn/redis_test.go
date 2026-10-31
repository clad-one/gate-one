package authn

import (
	"context"
	"crypto/tls"
	"errors"
	"os"
	"path/filepath"
	"strings"
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

// TestAC_AUTH_18_RedisCheckRevokedCombined covers the combined
// sid+sub check used on the per-request hot path, including the
// issuedAt boundary that allows a new login after a global logout.
func TestAC_AUTH_18_RedisCheckRevokedCombined(t *testing.T) {
	mr := miniredis.RunT(t)
	ctx := context.Background()
	s, err := OpenRedisStore(ctx, RedisConfig{
		URL:    "redis://" + mr.Addr() + "/0",
		Prefix: "test:auth:v1:",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	const iss = "https://issuer.test"
	before := time.Now().Add(-time.Minute)

	// Nothing revoked.
	revoked, err := s.CheckRevoked(ctx, iss, "sid-1", "sub-1", before)
	if err != nil || revoked {
		t.Fatalf("clean = %v, %v", revoked, err)
	}

	// Session revocation wins even without a sub.
	if err := s.Revoke(ctx, iss, "sid-1", "", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	revoked, err = s.CheckRevoked(ctx, iss, "sid-1", "sub-1", before)
	if err != nil || !revoked {
		t.Fatalf("revoked sid = %v, %v", revoked, err)
	}

	// Subject revocation only applies to tokens issued before it.
	if err := s.RevokeSubject(
		ctx, iss, "sub-2", time.Now(), time.Now().Add(time.Hour),
	); err != nil {
		t.Fatal(err)
	}
	revoked, err = s.CheckRevoked(ctx, iss, "", "sub-2", before)
	if err != nil || !revoked {
		t.Fatalf("old token after sub logout = %v, %v", revoked, err)
	}
	revoked, err = s.CheckRevoked(
		ctx, iss, "", "sub-2", time.Now().Add(time.Minute))
	if err != nil || revoked {
		t.Fatalf("new token after sub logout = %v, %v", revoked, err)
	}
}

func TestRedisOptionsSentinelWiring(t *testing.T) {
	opts, err := redisOptions(RedisConfig{
		SentinelAddrs:    []string{"s1:26379", "s2:26379"},
		MasterName:       "authmaster",
		SentinelUsername: "sentinel-user",
		SentinelPassword: "sentinel-secret",
		Username:         "app",
		Password:         "acl-secret",
		Prefix:           "cladone:auth:v1:",
	})
	if err != nil {
		t.Fatal(err)
	}
	if opts.MasterName != "authmaster" {
		t.Errorf("master = %q", opts.MasterName)
	}
	if len(opts.Addrs) != 2 || opts.Addrs[0] != "s1:26379" {
		t.Errorf("addrs = %v", opts.Addrs)
	}
	if opts.SentinelUsername != "sentinel-user" ||
		opts.SentinelPassword != "sentinel-secret" {
		t.Errorf("sentinel auth = %q/%q",
			opts.SentinelUsername, opts.SentinelPassword)
	}
	if opts.Username != "app" || opts.Password != "acl-secret" {
		t.Errorf("acl = %q/%q", opts.Username, opts.Password)
	}
	if opts.TLSConfig != nil {
		t.Errorf("unexpected TLS config without tls=true")
	}
}

func TestRedisOptionsSentinelTLS(t *testing.T) {
	opts, err := redisOptions(RedisConfig{
		SentinelAddrs: []string{"s1:26379"},
		MasterName:    "authmaster",
		TLS:           true,
		TLSServerName: "redis.internal",
	})
	if err != nil {
		t.Fatal(err)
	}
	if opts.TLSConfig == nil {
		t.Fatal("TLS config not set")
	}
	if opts.TLSConfig.ServerName != "redis.internal" {
		t.Errorf("server name = %q", opts.TLSConfig.ServerName)
	}
	if opts.TLSConfig.MinVersion != tls.VersionTLS12 {
		t.Errorf("min version = %x", opts.TLSConfig.MinVersion)
	}
}

func TestRedisOptionsURLRejectsSentinelTLS(t *testing.T) {
	_, err := redisOptions(RedisConfig{
		URL: "redis://127.0.0.1:6379/0",
		TLS: true,
	})
	if err == nil || !strings.Contains(err.Error(), "only valid in sentinel mode") {
		t.Fatalf("err = %v, want sentinel-mode refusal", err)
	}
}

func TestRedisOptionsTLSCaInvalid(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, []byte("not a pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := redisOptions(RedisConfig{
		SentinelAddrs: []string{"s1:26379"},
		MasterName:    "authmaster",
		TLS:           true,
		TLSCaFile:     path,
	})
	if err == nil || !strings.Contains(err.Error(), "no PEM certificate") {
		t.Fatalf("err = %v, want invalid CA refusal", err)
	}
}

func TestRedisRetryable(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"readonly", errors.New("READONLY You can't write against a read only replica."), true},
		{"refused", errors.New("dial tcp 127.0.0.1:6379: connect: connection refused"), true},
		{"cancelled", context.Canceled, false},
		{"deadline", context.DeadlineExceeded, false},
	}
	for _, c := range cases {
		if got := redisRetryable(c.err); got != c.want {
			t.Errorf("%s: retryable = %t, want %t", c.name, got, c.want)
		}
	}
}
