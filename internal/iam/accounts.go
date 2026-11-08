package iam

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
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

// User is an IAM-owned authorization profile. A local user has a
// password; a federated user has exactly one external identity link
// (issuer, subject). Roles/scopes/claims are always managed on this
// object, for both kinds.
type User struct {
	ID            string         `json:"id"`
	Tenant        string         `json:"tenant"`
	Kind          string         `json:"kind,omitempty"` // local | federated
	Email         string         `json:"email"`
	Name          string         `json:"name,omitempty"`
	PasswordHash  string         `json:"passwordHash,omitempty"`
	EmailVerified bool           `json:"emailVerified,omitempty"`
	Issuer        string         `json:"issuer,omitempty"`
	Subject       string         `json:"subject,omitempty"`
	Roles         []string       `json:"roles,omitempty"`
	Scopes        []string       `json:"scopes,omitempty"`
	Claims        map[string]any `json:"claims,omitempty"`
	Disabled      bool           `json:"disabled,omitempty"`
	CreatedAt     time.Time      `json:"createdAt"`
	UpdatedAt     time.Time      `json:"updatedAt,omitempty"`
}

// localUser is kept as an alias for existing tests and callers.
type localUser = User

func (u *User) normalize() {
	if u.Kind == "" {
		u.Kind = "local"
	}
	u.Email = strings.ToLower(strings.TrimSpace(u.Email))
	u.Issuer = strings.TrimSpace(u.Issuer)
	u.Subject = strings.TrimSpace(u.Subject)
	u.Roles = uniqueSorted(u.Roles)
	u.Scopes = uniqueSorted(u.Scopes)
}

func uniqueSorted(items []string) []string {
	set := map[string]bool{}
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item != "" {
			set[item] = true
		}
	}
	out := make([]string, 0, len(set))
	for item := range set {
		out = append(out, item)
	}
	sort.Strings(out)
	return out
}

func (u *User) identityKey() string {
	if u == nil || u.Kind != "federated" || u.Issuer == "" || u.Subject == "" {
		return ""
	}
	return u.Issuer + "\x00" + u.Subject
}

// verifyToken is the server-side state of an email verification link.
// The raw token is only in the email; only its SHA-256 is stored.
type verifyToken struct {
	Email       string    `json:"email"`
	ContinueURL string    `json:"continueUrl,omitempty"`
	Expires     time.Time `json:"expires"`
}

var errAccountNotFound = errors.New("iam: account not found")
var errVerifyTokenNotFound = errors.New("iam: verification token not found")

type accountsStore interface {
	PutUser(ctx context.Context, u *User) error
	GetUserByEmail(ctx context.Context, tenant, email string) (*User, error)
	GetUserByID(ctx context.Context, tenant, id string) (*User, error)
	GetUserByIdentity(ctx context.Context, tenant, issuer, subject string) (*User, error)
	ListUsers(ctx context.Context, tenant string) ([]*User, error)
	DeleteUser(ctx context.Context, tenant, id string) error
	SetUserVerified(ctx context.Context, tenant, id string) error
	PutVerifyToken(ctx context.Context, tenant, tokenHash string, v *verifyToken, ttl time.Duration) error
	TakeVerifyToken(ctx context.Context, tenant, tokenHash string) (*verifyToken, error)
	Close() error
}

func acctKey(tenant, v string) string { return tenant + "\x00" + v }
func identityKey(tenant, issuer, subject string) string {
	return tenant + "\x00" + issuer + "\x00" + subject
}

// ---- memory (tests / single instance without Redis) ----

type memoryAccounts struct {
	mu         sync.Mutex
	users      map[string]User   // tenant\x00id
	byEmail    map[string]string // tenant\x00email -> id
	byIdentity map[string]string // tenant\x00issuer\x00subject -> id
	tokens     map[string]verifyToken
}

func newMemoryAccounts() *memoryAccounts {
	return &memoryAccounts{
		users:      map[string]User{},
		byEmail:    map[string]string{},
		byIdentity: map[string]string{},
		tokens:     map[string]verifyToken{},
	}
}

func (m *memoryAccounts) PutUser(_ context.Context, u *User) error {
	if u == nil {
		return errAccountNotFound
	}
	u.normalize()
	u.UpdatedAt = time.Now().UTC()
	m.mu.Lock()
	defer m.mu.Unlock()
	key := acctKey(u.Tenant, u.ID)
	if old, ok := m.users[key]; ok {
		if old.Kind == "local" && old.Email != u.Email {
			delete(m.byEmail, acctKey(old.Tenant, old.Email))
		}
		if old.identityKey() != "" && old.identityKey() != u.identityKey() {
			delete(m.byIdentity, identityKey(old.Tenant, old.Issuer, old.Subject))
		}
	}
	m.users[key] = *u
	// Email is the local-login key; a federated profile is resolved by
	// (issuer, subject), so it must not overwrite a local email index.
	if u.Kind == "local" {
		m.byEmail[acctKey(u.Tenant, u.Email)] = u.ID
	}
	if u.identityKey() != "" {
		m.byIdentity[identityKey(u.Tenant, u.Issuer, u.Subject)] = u.ID
	}
	return nil
}

func (m *memoryAccounts) GetUserByEmail(_ context.Context, tenant, email string) (*User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id, ok := m.byEmail[acctKey(tenant, strings.ToLower(email))]
	if !ok {
		return nil, errAccountNotFound
	}
	u, ok := m.users[acctKey(tenant, id)]
	if !ok {
		return nil, errAccountNotFound
	}
	return &u, nil
}

func (m *memoryAccounts) GetUserByID(_ context.Context, tenant, id string) (*User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[acctKey(tenant, id)]
	if !ok {
		return nil, errAccountNotFound
	}
	return &u, nil
}

func (m *memoryAccounts) GetUserByIdentity(_ context.Context, tenant, issuer, subject string) (*User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id, ok := m.byIdentity[identityKey(tenant, issuer, subject)]
	if !ok {
		return nil, errAccountNotFound
	}
	u, ok := m.users[acctKey(tenant, id)]
	if !ok {
		return nil, errAccountNotFound
	}
	return &u, nil
}

func (m *memoryAccounts) ListUsers(_ context.Context, tenant string) ([]*User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*User, 0)
	for key, u := range m.users {
		if strings.HasPrefix(key, tenant+"\x00") {
			cp := u
			out = append(out, &cp)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Email < out[j].Email })
	return out, nil
}

func (m *memoryAccounts) DeleteUser(_ context.Context, tenant, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := acctKey(tenant, id)
	u, ok := m.users[key]
	if !ok {
		return errAccountNotFound
	}
	delete(m.users, key)
	if u.Kind == "local" {
		delete(m.byEmail, acctKey(tenant, u.Email))
	}
	if u.identityKey() != "" {
		delete(m.byIdentity, identityKey(tenant, u.Issuer, u.Subject))
	}
	return nil
}

func (m *memoryAccounts) SetUserVerified(ctx context.Context, tenant, id string) error {
	u, err := m.GetUserByID(ctx, tenant, id)
	if err != nil {
		return err
	}
	u.EmailVerified = true
	return m.PutUser(ctx, u)
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

func keyPart(v string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(v))
}

func (r *redisAccounts) PutUser(ctx context.Context, u *User) error {
	if u == nil {
		return errAccountNotFound
	}
	u.normalize()
	u.UpdatedAt = time.Now().UTC()
	raw, err := json.Marshal(u)
	if err != nil {
		return err
	}
	old, _ := r.GetUserByID(ctx, u.Tenant, u.ID)
	pipe := r.client.Pipeline()
	pipe.Set(ctx, r.key("user", "id", u.Tenant, u.ID), raw, 0)
	if u.Kind == "local" {
		pipe.Set(ctx, r.key("user", "email", u.Tenant, u.Email), raw, 0)
	}
	if old != nil && old.Kind == "local" && old.Email != u.Email {
		pipe.Del(ctx, r.key("user", "email", u.Tenant, old.Email))
	}
	if old != nil && old.Kind == "local" && u.Kind != "local" {
		pipe.Del(ctx, r.key("user", "email", u.Tenant, old.Email))
	}
	if old != nil && old.identityKey() != "" &&
		old.identityKey() != u.identityKey() {
		pipe.Del(ctx, r.key("user", "identity", u.Tenant,
			keyPart(old.Issuer), keyPart(old.Subject)))
	}
	if u.identityKey() != "" {
		pipe.Set(ctx, r.key("user", "identity", u.Tenant,
			keyPart(u.Issuer), keyPart(u.Subject)), u.ID, 0)
	}
	_, err = pipe.Exec(ctx)
	return err
}

func (r *redisAccounts) GetUserByEmail(ctx context.Context, tenant, email string) (*User, error) {
	raw, err := r.client.Get(ctx, r.key("user", "email", tenant, email)).Bytes()
	if err == redis.Nil {
		return nil, errAccountNotFound
	}
	if err != nil {
		return nil, err
	}
	return decodeUser(raw)
}

func (r *redisAccounts) GetUserByID(ctx context.Context, tenant, id string) (*User, error) {
	raw, err := r.client.Get(ctx, r.key("user", "id", tenant, id)).Bytes()
	if err == redis.Nil {
		return nil, errAccountNotFound
	}
	if err != nil {
		return nil, err
	}
	return decodeUser(raw)
}

func (r *redisAccounts) GetUserByIdentity(ctx context.Context, tenant, issuer, subject string) (*User, error) {
	id, err := r.client.Get(ctx, r.key("user", "identity", tenant,
		keyPart(issuer), keyPart(subject))).Result()
	if err == redis.Nil {
		return nil, errAccountNotFound
	}
	if err != nil {
		return nil, err
	}
	return r.GetUserByID(ctx, tenant, id)
}

func (r *redisAccounts) ListUsers(ctx context.Context, tenant string) ([]*User, error) {
	pattern := r.key("user", "id", tenant, "*")
	iter := r.client.Scan(ctx, 0, pattern, 200).Iterator()
	out := make([]*User, 0)
	for iter.Next(ctx) {
		raw, err := r.client.Get(ctx, iter.Val()).Bytes()
		if err != nil {
			return nil, err
		}
		u, err := decodeUser(raw)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	if err := iter.Err(); err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Email < out[j].Email })
	return out, nil
}

func (r *redisAccounts) DeleteUser(ctx context.Context, tenant, id string) error {
	u, err := r.GetUserByID(ctx, tenant, id)
	if err != nil {
		return err
	}
	pipe := r.client.Pipeline()
	pipe.Del(ctx, r.key("user", "id", tenant, id))
	if u.Kind == "local" {
		pipe.Del(ctx, r.key("user", "email", tenant, u.Email))
	}
	if u.identityKey() != "" {
		pipe.Del(ctx, r.key("user", "identity", tenant,
			keyPart(u.Issuer), keyPart(u.Subject)))
	}
	_, err = pipe.Exec(ctx)
	return err
}

func decodeUser(raw []byte) (*User, error) {
	var u User
	if err := json.Unmarshal(raw, &u); err != nil {
		return nil, err
	}
	u.normalize()
	return &u, nil
}

func (r *redisAccounts) SetUserVerified(ctx context.Context, tenant, id string) error {
	u, err := r.GetUserByID(ctx, tenant, id)
	if err != nil {
		return err
	}
	u.EmailVerified = true
	return r.PutUser(ctx, u)
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
