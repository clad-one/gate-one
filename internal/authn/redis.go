package authn

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"

	"cladone/gate-one/pkg/authstate"

	"github.com/redis/go-redis/v9"
)

// RedisConfig configures the shared revocation store. Sentinel mode is
// used when MasterName + SentinelAddrs are set; otherwise URL is a
// redis:// or rediss:// URL.
type RedisConfig struct {
	URL           string
	SentinelAddrs []string
	MasterName    string
	Username      string
	Password      string
	DB            int
	Prefix        string
	DialTimeout   time.Duration
	ReadTimeout   time.Duration
	WriteTimeout  time.Duration
	PoolSize      int
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
func OpenRedisStore(ctx context.Context, cfg RedisConfig) (*RedisStore, error) {
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
	} else {
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
	}
	client := redis.NewUniversalClient(opts)
	if err := client.Ping(ctx).Err(); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("sessionStore.redis: ping: %w", err)
	}
	prefix := authstate.Prefix(cfg.Prefix)
	s := &RedisStore{client: client, prefix: prefix}
	if err := s.initStoreID(ctx); err != nil {
		_ = client.Close()
		return nil, err
	}
	return s, nil
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
