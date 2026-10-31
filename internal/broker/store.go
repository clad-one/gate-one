package broker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"cladone/gate-one/pkg/authstate"

	"github.com/redis/go-redis/v9"
)

// store persists flows, codes and refresh tokens, and writes the
// shared revocation keys read by Gate One. Memory is the test/dev
// default; Redis is required for multi-instance and restart safety.
type store interface {
	PutFlow(ctx context.Context, tenant, id string, f *flow, ttl time.Duration) error
	GetFlow(ctx context.Context, tenant, id string) (*flow, error)
	TakeFlow(ctx context.Context, tenant, id string) (*flow, error)
	PutCode(ctx context.Context, tenant, id string, c *authCode, ttl time.Duration) error
	TakeCode(ctx context.Context, tenant, id string) (*authCode, error)
	PutRefresh(ctx context.Context, tenant, id string, g *refreshGrant, ttl time.Duration) error
	TakeRefresh(ctx context.Context, tenant, id string) (*refreshGrant, error)
	PutSession(ctx context.Context, tenant, id, sid, sub string, issuedAt time.Time, ttl time.Duration) error
	GetSession(ctx context.Context, tenant, id string) (sid, sub string, issuedAt time.Time, err error)
	DeleteSession(ctx context.Context, tenant, id string) error
	Revoke(ctx context.Context, issuer, sid, sub string, expires time.Time) error
	RevokeSubject(ctx context.Context, issuer, sub string, revokedAt, expires time.Time) error
	IsRevoked(ctx context.Context, issuer, sid, sub string) (bool, error)
	IsSubjectRevoked(ctx context.Context, issuer, sub string, issuedAt time.Time) (bool, error)
	Close() error
}

// RedisConfig configures the broker's shared store. AuthPrefix MUST
// match Gate One's sessionStore.redis.prefix so revocations are read
// by the gateway.
type RedisConfig struct {
	URL            string   `json:"url,omitempty"`
	SentinelAddrs  []string `json:"sentinelAddrs,omitempty"`
	MasterName     string   `json:"masterName,omitempty"`
	Username       string   `json:"username,omitempty"`
	PasswordEnv    string   `json:"passwordEnv,omitempty"`
	Password       string   `json:"-"`
	DB             int      `json:"db,omitempty"`
	Prefix         string   `json:"prefix,omitempty"`
	AuthPrefix     string   `json:"authPrefix,omitempty"`
	DialTimeoutMS  int      `json:"dialTimeoutMs,omitempty"`
	ReadTimeoutMS  int      `json:"readTimeoutMs,omitempty"`
	WriteTimeoutMS int      `json:"writeTimeoutMs,omitempty"`
	PoolSize       int      `json:"poolSize,omitempty"`
}

type memoryStore struct {
	mu         sync.Mutex
	flows      map[string]memEntry
	codes      map[string]memEntry
	refresh    map[string]memEntry
	sessions   map[string]memEntry
	revoked    map[string]time.Time
	subRevoked map[string]subRevocation
}

var errStoreNotFound = errors.New("broker: store entry not found")

type memEntry struct {
	value   []byte
	expires time.Time
}

type subRevocation struct {
	revokedAt time.Time
	expires   time.Time
}

func newMemoryStore() *memoryStore {
	return &memoryStore{
		flows: map[string]memEntry{}, codes: map[string]memEntry{},
		refresh: map[string]memEntry{}, sessions: map[string]memEntry{},
		revoked:    map[string]time.Time{},
		subRevoked: map[string]subRevocation{},
	}
}

func (s *memoryStore) put(
	m map[string]memEntry, key string, v any, ttl time.Duration,
) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gcLocked()
	m[key] = memEntry{value: raw, expires: time.Now().Add(ttl)}
	return nil
}

func (s *memoryStore) take(m map[string]memEntry, key string, out any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gcLocked()
	e, ok := m[key]
	if !ok {
		return errStoreNotFound
	}
	delete(m, key)
	return json.Unmarshal(e.value, out)
}

func (s *memoryStore) gcLocked() {
	now := time.Now()
	for _, m := range []map[string]memEntry{s.flows, s.codes, s.refresh, s.sessions} {
		for k, e := range m {
			if now.After(e.expires) {
				delete(m, k)
			}
		}
	}
	for k, exp := range s.revoked {
		if now.After(exp) {
			delete(s.revoked, k)
		}
	}
	for k, e := range s.subRevoked {
		if now.After(e.expires) {
			delete(s.subRevoked, k)
		}
	}
}

func (s *memoryStore) PutFlow(_ context.Context, tenant, id string, f *flow, ttl time.Duration) error {
	return s.put(s.flows, tenant+"\x00"+id, f, ttl)
}
func (s *memoryStore) GetFlow(_ context.Context, tenant, id string) (*flow, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.flows[tenant+"\x00"+id]
	if !ok || time.Now().After(e.expires) {
		return nil, nil
	}
	var f flow
	if err := json.Unmarshal(e.value, &f); err != nil {
		return nil, err
	}
	return &f, nil
}

func (s *memoryStore) TakeFlow(_ context.Context, tenant, id string) (*flow, error) {
	var f flow
	if err := s.take(s.flows, tenant+"\x00"+id, &f); err != nil {
		if errors.Is(err, errStoreNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &f, nil
}
func (s *memoryStore) PutCode(_ context.Context, tenant, id string, c *authCode, ttl time.Duration) error {
	return s.put(s.codes, tenant+"\x00"+id, c, ttl)
}
func (s *memoryStore) TakeCode(_ context.Context, tenant, id string) (*authCode, error) {
	var c authCode
	if err := s.take(s.codes, tenant+"\x00"+id, &c); err != nil {
		if errors.Is(err, errStoreNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &c, nil
}
func (s *memoryStore) PutRefresh(_ context.Context, tenant, id string, g *refreshGrant, ttl time.Duration) error {
	return s.put(s.refresh, tenant+"\x00"+id, g, ttl)
}
func (s *memoryStore) TakeRefresh(_ context.Context, tenant, id string) (*refreshGrant, error) {
	var g refreshGrant
	if err := s.take(s.refresh, tenant+"\x00"+id, &g); err != nil {
		if errors.Is(err, errStoreNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &g, nil
}

type sessionValue struct {
	SID      string    `json:"sid"`
	Sub      string    `json:"sub,omitempty"`
	IssuedAt time.Time `json:"iat,omitempty"`
}

func (s *memoryStore) PutSession(_ context.Context, tenant, id, sid, sub string, issuedAt time.Time, ttl time.Duration) error {
	return s.put(s.sessions, tenant+"\x00"+id,
		sessionValue{SID: sid, Sub: sub, IssuedAt: issuedAt}, ttl)
}
func (s *memoryStore) GetSession(_ context.Context, tenant, id string) (string, string, time.Time, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gcLocked()
	e, ok := s.sessions[tenant+"\x00"+id]
	if !ok {
		return "", "", time.Time{}, nil
	}
	var v sessionValue
	if err := json.Unmarshal(e.value, &v); err != nil {
		return "", "", time.Time{}, err
	}
	return v.SID, v.Sub, v.IssuedAt, nil
}
func (s *memoryStore) DeleteSession(_ context.Context, tenant, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, tenant+"\x00"+id)
	return nil
}

func (s *memoryStore) Revoke(_ context.Context, issuer, sid, sub string, expires time.Time) error {
	if sid == "" && sub == "" {
		return fmt.Errorf("revoke: empty sid and sub")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if sid != "" {
		s.revoked[authstate.Key("", "revoked:sid", issuer, sid)] = expires
	}
	if sub != "" {
		if err := s.revokeSubjectLocked(issuer, sub, time.Now(), expires); err != nil {
			return err
		}
	}
	return nil
}
func (s *memoryStore) RevokeSubject(_ context.Context, issuer, sub string, revokedAt, expires time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.revokeSubjectLocked(issuer, sub, revokedAt, expires)
}
func (s *memoryStore) revokeSubjectLocked(issuer, sub string, revokedAt, expires time.Time) error {
	if sub == "" {
		return fmt.Errorf("revoke: empty sub")
	}
	if revokedAt.IsZero() {
		revokedAt = time.Now()
	}
	if expires.IsZero() {
		expires = revokedAt.Add(24 * time.Hour)
	}
	s.subRevoked[authstate.Key("", "revoked:sub", issuer, sub)] = subRevocation{
		revokedAt: revokedAt, expires: expires,
	}
	return nil
}
func (s *memoryStore) IsRevoked(_ context.Context, issuer, sid, sub string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gcLocked()
	now := time.Now()
	if sid != "" {
		if exp, ok := s.revoked[authstate.Key("", "revoked:sid", issuer, sid)]; ok && now.Before(exp) {
			return true, nil
		}
	}
	if sub != "" {
		return s.isSubjectRevokedLocked(issuer, sub, time.Time{})
	}
	return false, nil
}
func (s *memoryStore) IsSubjectRevoked(_ context.Context, issuer, sub string, issuedAt time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gcLocked()
	return s.isSubjectRevokedLocked(issuer, sub, issuedAt)
}
func (s *memoryStore) isSubjectRevokedLocked(issuer, sub string, issuedAt time.Time) (bool, error) {
	now := time.Now()
	e, ok := s.subRevoked[authstate.Key("", "revoked:sub", issuer, sub)]
	if !ok || !now.Before(e.expires) {
		return false, nil
	}
	if issuedAt.IsZero() {
		return true, nil
	}
	return !issuedAt.After(e.revokedAt), nil
}

func (s *memoryStore) Close() error { return nil }

type redisStore struct {
	client     redis.UniversalClient
	dataPrefix string
	authPrefix string
}

func newRedisStore(ctx context.Context, cfg RedisConfig) (*redisStore, error) {
	opts := &redis.UniversalOptions{
		Username:     cfg.Username,
		Password:     cfg.Password,
		DB:           cfg.DB,
		DialTimeout:  durationMS(cfg.DialTimeoutMS, 500),
		ReadTimeout:  durationMS(cfg.ReadTimeoutMS, 300),
		WriteTimeout: durationMS(cfg.WriteTimeoutMS, 300),
		PoolSize:     intOrDefault(cfg.PoolSize, 64),
	}
	if cfg.MasterName != "" {
		if len(cfg.SentinelAddrs) == 0 {
			return nil, fmt.Errorf("broker.redis: sentinelAddrs required")
		}
		opts.MasterName = cfg.MasterName
		opts.Addrs = cfg.SentinelAddrs
	} else {
		if strings.TrimSpace(cfg.URL) == "" {
			return nil, fmt.Errorf("broker.redis: url required")
		}
		parsed, err := redis.ParseURL(cfg.URL)
		if err != nil {
			return nil, fmt.Errorf("broker.redis.url: %w", err)
		}
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
		return nil, fmt.Errorf("broker.redis: ping: %w", err)
	}
	data := strings.TrimSpace(cfg.Prefix)
	if data == "" {
		data = "cladone:broker:v1:"
	}
	if !strings.HasSuffix(data, ":") {
		data += ":"
	}
	return &redisStore{
		client:     client,
		dataPrefix: data,
		authPrefix: authstate.Prefix(cfg.AuthPrefix),
	}, nil
}

func (s *redisStore) put(
	ctx context.Context, kind, tenant, id string, v any, ttl time.Duration,
) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	key := s.dataPrefix + kind + ":" + tenant + ":" + id
	return s.client.Set(ctx, key, raw, ttl).Err()
}

func (s *redisStore) get(
	ctx context.Context, kind, tenant, id string, out any,
) error {
	key := s.dataPrefix + kind + ":" + tenant + ":" + id
	raw, err := s.client.Get(ctx, key).Bytes()
	if err == redis.Nil {
		return errStoreNotFound
	}
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, out)
}

var getDelScript = redis.NewScript(`
local v = redis.call('GET', KEYS[1])
if v then redis.call('DEL', KEYS[1]) end
return v
`)

func (s *redisStore) take(
	ctx context.Context, kind, tenant, id string, out any,
) error {
	key := s.dataPrefix + kind + ":" + tenant + ":" + id
	text, err := getDelScript.Run(ctx, s.client, []string{key}).Text()
	if err == redis.Nil {
		return errStoreNotFound
	}
	if err != nil {
		return err
	}
	return json.Unmarshal([]byte(text), out)
}

func (s *redisStore) PutFlow(ctx context.Context, tenant, id string, f *flow, ttl time.Duration) error {
	return s.put(ctx, "flow", tenant, id, f, ttl)
}
func (s *redisStore) GetFlow(ctx context.Context, tenant, id string) (*flow, error) {
	var f flow
	if err := s.get(ctx, "flow", tenant, id, &f); err != nil {
		if errors.Is(err, errStoreNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &f, nil
}

func (s *redisStore) TakeFlow(ctx context.Context, tenant, id string) (*flow, error) {
	var f flow
	if err := s.take(ctx, "flow", tenant, id, &f); err != nil {
		if errors.Is(err, errStoreNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &f, nil
}
func (s *redisStore) PutCode(ctx context.Context, tenant, id string, c *authCode, ttl time.Duration) error {
	return s.put(ctx, "code", tenant, id, c, ttl)
}
func (s *redisStore) TakeCode(ctx context.Context, tenant, id string) (*authCode, error) {
	var c authCode
	if err := s.take(ctx, "code", tenant, id, &c); err != nil {
		if errors.Is(err, errStoreNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &c, nil
}
func (s *redisStore) PutRefresh(ctx context.Context, tenant, id string, g *refreshGrant, ttl time.Duration) error {
	return s.put(ctx, "refresh", tenant, id, g, ttl)
}
func (s *redisStore) TakeRefresh(ctx context.Context, tenant, id string) (*refreshGrant, error) {
	var g refreshGrant
	if err := s.take(ctx, "refresh", tenant, id, &g); err != nil {
		if errors.Is(err, errStoreNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &g, nil
}

func (s *redisStore) PutSession(ctx context.Context, tenant, id, sid, sub string, issuedAt time.Time, ttl time.Duration) error {
	raw, err := json.Marshal(sessionValue{SID: sid, Sub: sub, IssuedAt: issuedAt})
	if err != nil {
		return err
	}
	return s.client.Set(ctx, s.dataPrefix+"session:"+tenant+":"+id, raw, ttl).Err()
}
func (s *redisStore) GetSession(ctx context.Context, tenant, id string) (string, string, time.Time, error) {
	raw, err := s.client.Get(ctx, s.dataPrefix+"session:"+tenant+":"+id).Bytes()
	if err == redis.Nil {
		return "", "", time.Time{}, nil
	}
	if err != nil {
		return "", "", time.Time{}, err
	}
	var v sessionValue
	if err := json.Unmarshal(raw, &v); err != nil {
		return "", "", time.Time{}, err
	}
	return v.SID, v.Sub, v.IssuedAt, nil
}
func (s *redisStore) DeleteSession(ctx context.Context, tenant, id string) error {
	return s.client.Del(ctx, s.dataPrefix+"session:"+tenant+":"+id).Err()
}

func (s *redisStore) Revoke(
	ctx context.Context, issuer, sid, sub string, expires time.Time,
) error {
	if sid == "" && sub == "" {
		return fmt.Errorf("revoke: empty sid and sub")
	}
	if sid != "" {
		ttl := time.Until(expires)
		if ttl > 0 {
			if err := s.client.Set(ctx,
				authstate.Key(s.authPrefix, "revoked:sid", issuer, sid),
				"1", ttl).Err(); err != nil {
				return err
			}
		}
	}
	if sub != "" {
		if err := s.RevokeSubject(ctx, issuer, sub, time.Now(), expires); err != nil {
			return err
		}
	}
	return nil
}

func (s *redisStore) RevokeSubject(
	ctx context.Context, issuer, sub string, revokedAt, expires time.Time,
) error {
	if sub == "" {
		return fmt.Errorf("revoke: empty sub")
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
	return s.client.Set(ctx,
		authstate.Key(s.authPrefix, "revoked:sub", issuer, sub),
		strconv.FormatInt(revokedAt.Unix(), 10), ttl).Err()
}

func (s *redisStore) IsRevoked(
	ctx context.Context, issuer, sid, sub string,
) (bool, error) {
	if sid != "" {
		n, err := s.client.Exists(ctx,
			authstate.Key(s.authPrefix, "revoked:sid", issuer, sid)).Result()
		if err != nil {
			return false, err
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

func (s *redisStore) IsSubjectRevoked(
	ctx context.Context, issuer, sub string, issuedAt time.Time,
) (bool, error) {
	if sub == "" {
		return false, nil
	}
	raw, err := s.client.Get(ctx,
		authstate.Key(s.authPrefix, "revoked:sub", issuer, sub)).Result()
	if err == redis.Nil {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	revokedAt, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return false, err
	}
	if issuedAt.IsZero() {
		return true, nil
	}
	return issuedAt.Unix() <= revokedAt, nil
}

func (s *redisStore) Close() error { return s.client.Close() }

func durationMS(ms, fallback int) time.Duration {
	if ms <= 0 {
		ms = fallback
	}
	return time.Duration(ms) * time.Millisecond
}

func intOrDefault(v, fallback int) int {
	if v <= 0 {
		return fallback
	}
	return v
}
