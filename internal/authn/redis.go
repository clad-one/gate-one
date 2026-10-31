package authn

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"cladone/gate-one/pkg/authstate"

	"github.com/redis/go-redis/v9"
)

// RedisConfig configures the shared revocation store. Sentinel mode is
// used when MasterName + SentinelAddrs are set; otherwise URL is a
// redis:// or rediss:// URL.
//
// SentinelUsername/SentinelPassword authenticate to the Sentinels
// themselves (separate from the Redis ACL user). TLS is only valid in
// Sentinel mode: in URL mode use a rediss:// URL.
type RedisConfig struct {
	URL              string
	SentinelAddrs    []string
	MasterName       string
	SentinelUsername string
	SentinelPassword string
	Username         string
	Password         string
	DB               int
	Prefix           string
	DialTimeout      time.Duration
	ReadTimeout      time.Duration
	WriteTimeout     time.Duration
	PoolSize         int
	TLS              bool
	TLSCaFile        string
	TLSServerName    string
}

// RedisStore is the shared, multi-instance RevocationStore. Every
// authenticated request performs an EXISTS/MGET on this store before
// reusing a cached identity: a revocation is visible on the next
// request on every instance.
type RedisStore struct {
	client  redis.UniversalClient
	prefix  string
	storeID string
}

// OpenRedisStore connects, pings, and initialises the shared store id.
// A Redis outage at startup is fail-closed: the provider is refused.
//
// In Sentinel mode the first resolution can race a topology change (for
// example right after the whole stack was recreated): Sentinel may
// still return the previous master, which is now a read-only replica.
// Writes then fail with READONLY. We retry with a fresh client so the
// client re-resolves the master instead of keeping a stale connection.
func OpenRedisStore(ctx context.Context, cfg RedisConfig) (*RedisStore, error) {
	opts, err := redisOptions(cfg)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(redisOpenTimeout)
	var lastErr error
	for {
		client := redis.NewUniversalClient(opts)
		s, err := initRedisStore(ctx, client, cfg)
		if err == nil {
			return s, nil
		}
		_ = client.Close()
		lastErr = err
		if !redisRetryable(err) || time.Now().After(deadline) {
			return nil, lastErr
		}
		select {
		case <-ctx.Done():
			return nil, lastErr
		case <-time.After(redisRetryDelay):
		}
	}
}

const (
	redisOpenTimeout = 8 * time.Second
	redisRetryDelay  = 200 * time.Millisecond
)

func initRedisStore(
	ctx context.Context, client redis.UniversalClient, cfg RedisConfig,
) (*RedisStore, error) {
	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("sessionStore.redis: ping: %w", err)
	}
	s := &RedisStore{client: client, prefix: authstate.Prefix(cfg.Prefix)}
	if err := s.initStoreID(ctx); err != nil {
		return nil, err
	}
	return s, nil
}

// redisRetryable reports whether opening the store should be retried.
// A READONLY error means Sentinel handed us a replica: retrying with a
// fresh client is exactly what makes the provider recover. Connection
// errors are retried too (the stack may still be coming up); a
// cancelled context is not.
func redisRetryable(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) ||
		errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	return true
}

// redisOptions builds the go-redis options for URL or Sentinel mode.
// It is separate from OpenRedisStore so the wiring (ACL user, sentinel
// auth, TLS) can be asserted without a live Sentinel.
func redisOptions(cfg RedisConfig) (*redis.UniversalOptions, error) {
	opts := &redis.UniversalOptions{
		Username:     cfg.Username,
		Password:     cfg.Password,
		DB:           cfg.DB,
		DialTimeout:  cfg.DialTimeout,
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
		PoolSize:     cfg.PoolSize,
	}
	if cfg.MasterName != "" {
		if len(cfg.SentinelAddrs) == 0 {
			return nil, fmt.Errorf(
				"sessionStore.redis: sentinelAddrs required with masterName")
		}
		opts.MasterName = cfg.MasterName
		opts.Addrs = cfg.SentinelAddrs
		opts.SentinelUsername = cfg.SentinelUsername
		opts.SentinelPassword = cfg.SentinelPassword
		if cfg.TLS {
			tlsCfg, err := tlsConfig(cfg)
			if err != nil {
				return nil, err
			}
			opts.TLSConfig = tlsCfg
		}
		return opts, nil
	}
	if cfg.TLS || cfg.TLSCaFile != "" || cfg.TLSServerName != "" {
		return nil, fmt.Errorf(
			"sessionStore.redis: tls options are only valid in sentinel mode; " +
				"use a rediss:// url otherwise")
	}
	if strings.TrimSpace(cfg.URL) == "" {
		return nil, fmt.Errorf(
			"sessionStore.redis: url or masterName/sentinelAddrs required")
	}
	parsed, err := redis.ParseURL(cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("sessionStore.redis.url: %w", err)
	}
	// Explicit fields override the URL.
	if cfg.Username != "" {
		parsed.Username = cfg.Username
	}
	if cfg.Password != "" {
		parsed.Password = cfg.Password
	}
	if cfg.DB != 0 {
		parsed.DB = cfg.DB
	}
	opts.Addrs = []string{parsed.Addr}
	opts.Username = parsed.Username
	opts.Password = parsed.Password
	opts.DB = parsed.DB
	opts.TLSConfig = parsed.TLSConfig
	return opts, nil
}

// tlsConfig builds the TLS configuration shared by the Sentinel
// connections and the discovered master/replica connections.
func tlsConfig(cfg RedisConfig) (*tls.Config, error) {
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: cfg.TLSServerName,
	}
	if cfg.TLSCaFile != "" {
		pem, err := os.ReadFile(cfg.TLSCaFile)
		if err != nil {
			return nil, fmt.Errorf(
				"sessionStore.redis.tlsCaFile: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf(
				"sessionStore.redis.tlsCaFile: no PEM certificate found")
		}
		tlsCfg.RootCAs = pool
	}
	return tlsCfg, nil
}

func (s *RedisStore) initStoreID(ctx context.Context) error {
	key := s.prefix + "meta:store_id"
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return err
	}
	id := hex.EncodeToString(raw)
	ok, err := s.client.SetNX(ctx, key, id, 0).Result()
	if err != nil {
		return fmt.Errorf("sessionStore.redis: store id: %w", err)
	}
	if ok {
		s.storeID = id
		return nil
	}
	got, err := s.client.Get(ctx, key).Result()
	if err != nil {
		return fmt.Errorf("sessionStore.redis: store id: %w", err)
	}
	s.storeID = got
	return nil
}

// StoreID is shared across instances; if Redis is flushed, a new id
// invalidates old cookies instead of reactivating revoked sessions.
func (s *RedisStore) StoreID() string { return s.storeID }

func (s *RedisStore) Close() error { return s.client.Close() }

func (s *RedisStore) Health(ctx context.Context) error {
	return s.client.Ping(ctx).Err()
}

func (s *RedisStore) key(kind, issuer, value string) string {
	return authstate.Key(s.prefix, kind, issuer, value)
}

func (s *RedisStore) Revoke(
	ctx context.Context,
	issuer, sid, sub string,
	expires time.Time,
) error {
	if sid == "" && sub == "" {
		return fmt.Errorf("sessionStore: empty sid and sub")
	}
	if expires.IsZero() {
		expires = time.Now().Add(24 * time.Hour)
	}
	if sid != "" {
		if err := s.revokeSID(ctx, issuer, sid, expires); err != nil {
			return err
		}
	}
	if sub != "" {
		if err := s.RevokeSubject(
			ctx, issuer, sub, time.Now(), expires,
		); err != nil {
			return err
		}
	}
	return nil
}

func (s *RedisStore) revokeSID(
	ctx context.Context, issuer, sid string, expires time.Time,
) error {
	ttl := time.Until(expires)
	if ttl <= 0 {
		return nil
	}
	if err := s.client.Set(
		ctx, s.key("revoked:sid", issuer, sid), "1", ttl,
	).Err(); err != nil {
		return fmt.Errorf("sessionStore.redis: revoke sid: %w", err)
	}
	return nil
}

func (s *RedisStore) RevokeSubject(
	ctx context.Context, issuer, sub string,
	revokedAt, expires time.Time,
) error {
	if sub == "" {
		return fmt.Errorf("sessionStore: empty sub")
	}
	if revokedAt.IsZero() {
		revokedAt = time.Now()
	}
	if expires.IsZero() {
		expires = revokedAt.Add(24 * time.Hour)
	}
	ttl := time.Until(expires)
	if ttl <= 0 {
		return nil
	}
	if err := s.client.Set(
		ctx, s.key("revoked:sub", issuer, sub),
		strconv.FormatInt(revokedAt.Unix(), 10), ttl,
	).Err(); err != nil {
		return fmt.Errorf("sessionStore.redis: revoke sub: %w", err)
	}
	return nil
}

func (s *RedisStore) IsRevoked(
	ctx context.Context,
	issuer, sid, sub string,
) (bool, error) {
	if sid != "" {
		n, err := s.client.Exists(
			ctx, s.key("revoked:sid", issuer, sid)).Result()
		if err != nil {
			return false, fmt.Errorf("sessionStore.redis: exists: %w", err)
		}
		if n > 0 {
			return true, nil
		}
	}
	if sub != "" {
		return s.IsSubjectRevoked(ctx, issuer, sub, time.Time{})
	}
	return false, nil
}

// CheckRevoked answers the sid and sub questions in ONE round trip
// (pipelined EXISTS + GET). This is the per-request hot path: two
// sequential round trips doubled the latency cost of every
// authenticated request against a remote Redis.
func (s *RedisStore) CheckRevoked(
	ctx context.Context,
	issuer, sid, sub string, issuedAt time.Time,
) (bool, error) {
	if sid == "" && sub == "" {
		return false, nil
	}

	pipe := s.client.Pipeline()
	var sidCmd *redis.IntCmd
	if sid != "" {
		sidCmd = pipe.Exists(ctx, s.key("revoked:sid", issuer, sid))
	}
	var subCmd *redis.StringCmd
	if sub != "" {
		subCmd = pipe.Get(ctx, s.key("revoked:sub", issuer, sub))
	}
	// A missing sub key (redis.Nil) is the normal "not revoked" case,
	// not a pipeline failure.
	if _, err := pipe.Exec(ctx); err != nil && err != redis.Nil {
		return false, fmt.Errorf(
			"sessionStore.redis: revocation check: %w", err)
	}

	if sidCmd != nil {
		n, err := sidCmd.Result()
		if err != nil {
			return false, fmt.Errorf(
				"sessionStore.redis: exists: %w", err)
		}
		if n > 0 {
			return true, nil
		}
	}
	if subCmd == nil {
		return false, nil
	}
	raw, err := subCmd.Result()
	if err == redis.Nil {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("sessionStore.redis: get sub: %w", err)
	}
	revokedAt, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return false, fmt.Errorf(
			"sessionStore.redis: bad sub timestamp: %w", err)
	}
	if issuedAt.IsZero() {
		return true, nil
	}
	return issuedAt.Unix() <= revokedAt, nil
}

func (s *RedisStore) IsSubjectRevoked(
	ctx context.Context, issuer, sub string, issuedAt time.Time,
) (bool, error) {
	if sub == "" {
		return false, nil
	}
	raw, err := s.client.Get(
		ctx, s.key("revoked:sub", issuer, sub)).Result()
	if err == redis.Nil {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("sessionStore.redis: get sub: %w", err)
	}
	revokedAt, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return false, fmt.Errorf("sessionStore.redis: bad sub timestamp: %w", err)
	}
	if issuedAt.IsZero() {
		return true, nil
	}
	return issuedAt.Unix() <= revokedAt, nil
}

func (s *RedisStore) UseJTI(
	ctx context.Context,
	issuer, jti string,
	expires time.Time,
) (bool, error) {
	if jti == "" {
		return false, fmt.Errorf("sessionStore: empty jti")
	}
	ttl := time.Until(expires)
	if expires.IsZero() || ttl <= 0 {
		return false, nil
	}
	ok, err := s.client.SetNX(
		ctx, s.key("jti", issuer, jti), "1", ttl).Result()
	if err != nil {
		return false, fmt.Errorf("sessionStore.redis: jti: %w", err)
	}
	return ok, nil
}

var _ RevocationStore = (*RedisStore)(nil)
