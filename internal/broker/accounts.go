package broker

import (
	"context"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/mail"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

// localUser is a broker-owned account (local email/password identity).
// Federated identities are linked separately in a later slice.
type localUser struct {
	ID            string    `json:"id"`
	Tenant        string    `json:"tenant"`
	Email         string    `json:"email"`
	Name          string    `json:"name,omitempty"`
	PasswordHash  string    `json:"passwordHash"`
	EmailVerified bool      `json:"emailVerified"`
	Roles         []string  `json:"roles,omitempty"`
	CreatedAt     time.Time `json:"createdAt"`
}

// verifyToken is the server-side state of an email verification link.
// The raw token is only in the email; only its SHA-256 is stored.
type verifyToken struct {
	Email       string    `json:"email"`
	ContinueURL string    `json:"continueUrl,omitempty"`
	Expires     time.Time `json:"expires"`
}

var errAccountNotFound = errors.New("broker: account not found")
var errVerifyTokenNotFound = errors.New("broker: verification token not found")

type accountsStore interface {
	PutUser(ctx context.Context, u *localUser) error
	GetUserByEmail(ctx context.Context, tenant, email string) (*localUser, error)
	SetUserVerified(ctx context.Context, tenant, id string) error
	PutVerifyToken(ctx context.Context, tenant, tokenHash string, v *verifyToken, ttl time.Duration) error
	TakeVerifyToken(ctx context.Context, tenant, tokenHash string) (*verifyToken, error)
	Close() error
}

// ---- memory (tests / single instance without Redis) ----

type memoryAccounts struct {
	mu     sync.Mutex
	users  map[string]localUser // tenant\x00email
	byID   map[string]string    // tenant\x00id -> email
	tokens map[string]verifyToken
}

func newMemoryAccounts() *memoryAccounts {
	return &memoryAccounts{
		users:  map[string]localUser{},
		byID:   map[string]string{},
		tokens: map[string]verifyToken{},
	}
}

func acctKey(tenant, v string) string { return tenant + "\x00" + v }

func (m *memoryAccounts) PutUser(_ context.Context, u *localUser) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.users[acctKey(u.Tenant, u.Email)] = *u
	m.byID[acctKey(u.Tenant, u.ID)] = u.Email
	return nil
}

func (m *memoryAccounts) GetUserByEmail(_ context.Context, tenant, email string) (*localUser, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[acctKey(tenant, email)]
	if !ok {
		return nil, errAccountNotFound
	}
	return &u, nil
}

func (m *memoryAccounts) SetUserVerified(_ context.Context, tenant, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	email, ok := m.byID[acctKey(tenant, id)]
	if !ok {
		return errAccountNotFound
	}
	u := m.users[acctKey(tenant, email)]
	u.EmailVerified = true
	m.users[acctKey(tenant, email)] = u
	return nil
}

func (m *memoryAccounts) PutVerifyToken(_ context.Context, tenant, tokenHash string, v *verifyToken, _ time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tokens[acctKey(tenant, tokenHash)] = *v
	return nil
}

func (m *memoryAccounts) TakeVerifyToken(_ context.Context, tenant, tokenHash string) (*verifyToken, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := acctKey(tenant, tokenHash)
	v, ok := m.tokens[key]
	if !ok {
		return nil, errVerifyTokenNotFound
	}
	delete(m.tokens, key)
	if !v.Expires.IsZero() && time.Now().After(v.Expires) {
		return nil, errVerifyTokenNotFound
	}
	return &v, nil
}

func (m *memoryAccounts) Close() error { return nil }

// ---- Redis (shared, multi-instance) ----

type redisAccounts struct {
	client redis.UniversalClient
	prefix string
}

func (r *redisAccounts) key(parts ...string) string {
	return r.prefix + strings.Join(parts, ":")
}

func (r *redisAccounts) PutUser(ctx context.Context, u *localUser) error {
	raw, err := json.Marshal(u)
	if err != nil {
		return err
	}
	pipe := r.client.Pipeline()
	pipe.Set(ctx, r.key("user", "email", u.Tenant, u.Email), raw, 0)
	pipe.Set(ctx, r.key("user", "id", u.Tenant, u.ID), raw, 0)
	_, err = pipe.Exec(ctx)
	return err
}

func (r *redisAccounts) GetUserByEmail(ctx context.Context, tenant, email string) (*localUser, error) {
	raw, err := r.client.Get(ctx, r.key("user", "email", tenant, email)).Bytes()
	if err == redis.Nil {
		return nil, errAccountNotFound
	}
	if err != nil {
		return nil, err
	}
	var u localUser
	if err := json.Unmarshal(raw, &u); err != nil {
		return nil, err
	}
	return &u, nil
}

func (r *redisAccounts) SetUserVerified(ctx context.Context, tenant, id string) error {
	raw, err := r.client.Get(ctx, r.key("user", "id", tenant, id)).Bytes()
	if err == redis.Nil {
		return errAccountNotFound
	}
	if err != nil {
		return err
	}
	var u localUser
	if err := json.Unmarshal(raw, &u); err != nil {
		return err
	}
	u.EmailVerified = true
	return r.PutUser(ctx, &u)
}

func (r *redisAccounts) PutVerifyToken(ctx context.Context, tenant, tokenHash string, v *verifyToken, ttl time.Duration) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return r.client.Set(ctx, r.key("verify", tenant, tokenHash), raw, ttl).Err()
}

func (r *redisAccounts) TakeVerifyToken(ctx context.Context, tenant, tokenHash string) (*verifyToken, error) {
	raw, err := r.client.GetDel(ctx, r.key("verify", tenant, tokenHash)).Bytes()
	if err == redis.Nil {
		return nil, errVerifyTokenNotFound
	}
	if err != nil {
		return nil, err
	}
	var v verifyToken
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, err
	}
	if !v.Expires.IsZero() && time.Now().After(v.Expires) {
		return nil, errVerifyTokenNotFound
	}
	return &v, nil
}

func (r *redisAccounts) Close() error { return nil }

// ---- password hashing (PBKDF2-HMAC-SHA256) ----

// pbkdf2Iterations is a variable so tests can lower the cost.
var pbkdf2Iterations = 600000

const pbkdf2KeyLen = 32

func hashPassword(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key, err := pbkdf2.Key(sha256.New, password, salt, pbkdf2Iterations, pbkdf2KeyLen)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("pbkdf2-sha256$%d$%s$%s",
		pbkdf2Iterations,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key)), nil
}

func verifyPassword(encoded, password string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 4 || parts[0] != "pbkdf2-sha256" {
		return false
	}
	var iter int
	if _, err := fmt.Sscanf(parts[1], "%d", &iter); err != nil || iter <= 0 {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[2])
	if err != nil {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil {
		return false
	}
	got, err := pbkdf2.Key(sha256.New, password, salt, iter, len(want))
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(got, want) == 1
}

// ---- verification tokens ----

func newVerifyToken() (raw, hash string, err error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", "", err
	}
	raw = base64.RawURLEncoding.EncodeToString(buf)
	return raw, verifyTokenHash(raw), nil
}

func verifyTokenHash(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// ---- validation ----

func normalizeEmail(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	addr, err := mail.ParseAddress(raw)
	if err != nil || addr.Address != raw {
		return "", fmt.Errorf("invalid email address")
	}
	return strings.ToLower(raw), nil
}

// continueURLAllowed: the URL must be an absolute http(s) URL whose
// origin is one of the tenant's appOrigins (path allowed).
func (rt *tenantRuntime) continueURLAllowed(raw string) bool {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil ||
		(u.Scheme != "http" && u.Scheme != "https") {
		return false
	}
	origin := strings.ToLower(u.Scheme + "://" + u.Host)
	for _, allowed := range rt.cfg.AppOrigins {
		if strings.EqualFold(strings.TrimRight(allowed, "/"), origin) {
			return true
		}
	}
	return false
}
