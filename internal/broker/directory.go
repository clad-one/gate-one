package broker

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// Directory is the administrative view of the broker user store. It
// does not discover upstream IdPs and never issues tokens.
type Directory struct {
	cfg      *Config
	accounts accountsStore
	store    store
}

// OpenDirectory opens the configured user store without starting the
// OIDC server or discovering upstream providers.
func OpenDirectory(ctx context.Context, cfg *Config) (*Directory, error) {
	if cfg == nil {
		return nil, fmt.Errorf("broker: nil config")
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	var st store = newMemoryStore()
	var accounts accountsStore = newMemoryAccounts()
	if cfg.Redis != nil {
		rs, err := newRedisStore(ctx, *cfg.Redis)
		if err != nil {
			return nil, err
		}
		st = rs
		accounts = &redisAccounts{
			client: rs.client,
			prefix: cfg.Redis.Prefix + "accounts:",
		}
	}
	return &Directory{cfg: cfg, accounts: accounts, store: st}, nil
}

// Close releases the store.
func (d *Directory) Close() error {
	if d == nil {
		return nil
	}
	if d.accounts != nil {
		_ = d.accounts.Close()
	}
	if d.store != nil {
		return d.store.Close()
	}
	return nil
}

func (d *Directory) tenant(id string) (*Tenant, error) {
	for i := range d.cfg.Tenants {
		if d.cfg.Tenants[i].ID == id {
			return &d.cfg.Tenants[i], nil
		}
	}
	return nil, fmt.Errorf("broker: unknown tenant %q", id)
}

// NewUserID returns a random broker user id.
func NewUserID() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// HashPassword is the exported form used by the admin CLI.
func HashPassword(password string) (string, error) { return hashPassword(password) }

// NormalizeEmail is the exported form used by the admin CLI.
func NormalizeEmail(raw string) (string, error) { return normalizeEmail(raw) }

func validateUser(u *User) error {
	if u == nil {
		return fmt.Errorf("broker: nil user")
	}
	if u.ID == "" {
		return fmt.Errorf("broker: user id is required")
	}
	if u.Tenant == "" {
		return fmt.Errorf("broker: user tenant is required")
	}
	u.normalize()
	switch u.Kind {
	case "local":
		if u.Email == "" {
			return fmt.Errorf("broker: local user email is required")
		}
		email, err := normalizeEmail(u.Email)
		if err != nil {
			return fmt.Errorf("broker: %w", err)
		}
		u.Email = email
		if u.Issuer != "" || u.Subject != "" {
			return fmt.Errorf("broker: local user cannot have an external identity")
		}
	case "federated":
		if u.Issuer == "" || u.Subject == "" {
			return fmt.Errorf("broker: federated user requires issuer and subject")
		}
	default:
		return fmt.Errorf("broker: user kind must be local or federated")
	}
	for _, role := range u.Roles {
		if strings.TrimSpace(role) == "" {
			return fmt.Errorf("broker: empty role")
		}
	}
	for _, scope := range u.Scopes {
		if strings.TrimSpace(scope) == "" {
			return fmt.Errorf("broker: empty scope")
		}
	}
	for name := range u.Claims {
		if reservedClaim(name) {
			return fmt.Errorf("broker: reserved claim %q", name)
		}
	}
	return nil
}

// PutUser creates or updates a user and its grants.
func (d *Directory) PutUser(ctx context.Context, u *User) error {
	if d == nil {
		return fmt.Errorf("broker: nil directory")
	}
	if _, err := d.tenant(u.Tenant); err != nil {
		return err
	}
	if u.CreatedAt.IsZero() {
		u.CreatedAt = time.Now().UTC()
	}
	if err := validateUser(u); err != nil {
		return err
	}
	return d.accounts.PutUser(ctx, u)
}

// CreateUser creates a user, hashing a plaintext password for local
// accounts. Federated users must supply issuer/subject and no password.
func (d *Directory) CreateUser(
	ctx context.Context, u *User, password string,
) (*User, error) {
	if u.ID == "" {
		id, err := NewUserID()
		if err != nil {
			return nil, err
		}
		u.ID = id
	}
	if u.Kind == "" {
		u.Kind = "local"
	}
	if password != "" {
		if u.Kind != "local" {
			return nil, fmt.Errorf("broker: a federated user has no password")
		}
		hash, err := hashPassword(password)
		if err != nil {
			return nil, err
		}
		u.PasswordHash = hash
	}
	if u.Kind == "local" && u.PasswordHash == "" {
		return nil, fmt.Errorf("broker: local user password is required")
	}
	if err := d.PutUser(ctx, u); err != nil {
		return nil, err
	}
	return u, nil
}

func (d *Directory) GetUserByID(ctx context.Context, tenant, id string) (*User, error) {
	if _, err := d.tenant(tenant); err != nil {
		return nil, err
	}
	return d.accounts.GetUserByID(ctx, tenant, id)
}

func (d *Directory) GetUserByEmail(ctx context.Context, tenant, email string) (*User, error) {
	if _, err := d.tenant(tenant); err != nil {
		return nil, err
	}
	email, err := normalizeEmail(email)
	if err != nil {
		return nil, err
	}
	return d.accounts.GetUserByEmail(ctx, tenant, email)
}

func (d *Directory) GetUserByIdentity(
	ctx context.Context, tenant, issuer, subject string,
) (*User, error) {
	if _, err := d.tenant(tenant); err != nil {
		return nil, err
	}
	return d.accounts.GetUserByIdentity(ctx, tenant, issuer, subject)
}

func (d *Directory) ListUsers(ctx context.Context, tenant string) ([]*User, error) {
	if _, err := d.tenant(tenant); err != nil {
		return nil, err
	}
	return d.accounts.ListUsers(ctx, tenant)
}

func (d *Directory) DeleteUser(ctx context.Context, tenant, id string) error {
	if _, err := d.tenant(tenant); err != nil {
		return err
	}
	return d.accounts.DeleteUser(ctx, tenant, id)
}

func (d *Directory) SetVerified(ctx context.Context, tenant, id string) error {
	if _, err := d.tenant(tenant); err != nil {
		return err
	}
	return d.accounts.SetUserVerified(ctx, tenant, id)
}
