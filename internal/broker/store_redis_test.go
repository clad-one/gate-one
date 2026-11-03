package broker

import (
	"context"
	"crypto/tls"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBrokerRedisOptionsSentinelWiring(t *testing.T) {
	opts, err := redisOptions(RedisConfig{
		SentinelAddrs:    []string{"s1:26379", "s2:26379"},
		MasterName:       "authmaster",
		SentinelUsername: "sentinel-user",
		SentinelPassword: "sentinel-secret",
		Username:         "app",
		Password:         "acl-secret",
	})
	if err != nil {
		t.Fatal(err)
	}
	if opts.MasterName != "authmaster" || len(opts.Addrs) != 2 {
		t.Fatalf("master/addrs = %q/%v", opts.MasterName, opts.Addrs)
	}
	if opts.SentinelUsername != "sentinel-user" ||
		opts.SentinelPassword != "sentinel-secret" {
		t.Errorf("sentinel auth = %q/%q",
			opts.SentinelUsername, opts.SentinelPassword)
	}
	if opts.Username != "app" || opts.Password != "acl-secret" {
		t.Errorf("acl = %q/%q", opts.Username, opts.Password)
	}
}

func TestBrokerRedisOptionsSentinelTLS(t *testing.T) {
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

func TestBrokerRedisOptionsURLRejectsSentinelTLS(t *testing.T) {
	_, err := redisOptions(RedisConfig{
		URL: "redis://127.0.0.1:6379/0",
		TLS: true,
	})
	if err == nil || !strings.Contains(err.Error(), "only valid in sentinel mode") {
		t.Fatalf("err = %v, want sentinel-mode refusal", err)
	}
}

func TestBrokerRedisOptionsTLSCaInvalid(t *testing.T) {
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

func TestBrokerRedisConfigSentinelValidation(t *testing.T) {
	base := func() *Config {
		return &Config{
			PublicURL: "https://broker.test",
			Tenants: []Tenant{{
				ID:           "mycompany",
				ClientID:     "gate-one",
				RedirectURIs: []string{"https://login.test/callback"},
				Google:       GoogleConfig{ClientID: "google-client"},
			}},
		}
	}

	// Sentinel auth is only meaningful in sentinel mode.
	cfg := base()
	cfg.Redis = &RedisConfig{
		URL:              "redis://127.0.0.1:6379/0",
		SentinelUsername: "sentinel-user",
	}
	if err := cfg.Validate(); err == nil ||
		!strings.Contains(err.Error(), "only valid in sentinel mode") {
		t.Fatalf("err = %v, want sentinel-mode refusal", err)
	}

	// TLS helpers require tls=true.
	cfg = base()
	cfg.Redis = &RedisConfig{
		SentinelAddrs: []string{"s1:26379"},
		MasterName:    "authmaster",
		TLSServerName: "redis.internal",
	}
	if err := cfg.Validate(); err == nil ||
		!strings.Contains(err.Error(), "require tls=true") {
		t.Fatalf("err = %v, want tls=true refusal", err)
	}

	// Missing CA file is a config error, not a startup surprise.
	cfg = base()
	cfg.Redis = &RedisConfig{
		SentinelAddrs: []string{"s1:26379"},
		MasterName:    "authmaster",
		TLS:           true,
		TLSCaFile:     filepath.Join(t.TempDir(), "missing.pem"),
	}
	if err := cfg.Validate(); err == nil ||
		!strings.Contains(err.Error(), "tlsCaFile") {
		t.Fatalf("err = %v, want missing CA refusal", err)
	}

	// Sentinel password env is resolved and required.
	t.Setenv("TEST_SENTINEL_PASSWORD", "sp")
	cfg = base()
	cfg.Redis = &RedisConfig{
		SentinelAddrs:       []string{"s1:26379"},
		MasterName:          "authmaster",
		SentinelUsername:    "sentinel-user",
		SentinelPasswordEnv: "TEST_SENTINEL_PASSWORD",
		TLS:                 true,
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("valid sentinel config rejected: %v", err)
	}
	if cfg.Redis.SentinelPassword != "sp" {
		t.Fatalf("sentinel password not resolved")
	}
}

func TestBrokerRedisRetryable(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"readonly", errors.New("READONLY You can't write against a read only replica."), true},
		{"refused", errors.New("dial tcp: connection refused"), true},
		{"cancelled", context.Canceled, false},
		{"deadline", context.DeadlineExceeded, false},
	}
	for _, c := range cases {
		if got := redisRetryable(c.err); got != c.want {
			t.Errorf("%s: retryable = %t, want %t", c.name, got, c.want)
		}
	}
}
