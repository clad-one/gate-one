// Package broker implements a small multi-tenant OIDC issuer. It
// federates an upstream identity provider (Google in V1), applies a
// local policy (tenant, roles, audiences), and re-emits its own
// Ed25519-signed JWTs. Gate One trusts only this issuer.
package broker

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Config is the broker configuration file.
type Config struct {
	// PublicURL is the external origin of the broker, without a
	// trailing slash (e.g. https://auth.example.com).
	PublicURL string `json:"publicUrl"`
	// Listen is the default listen address for cmd/cladone-auth.
	Listen string `json:"listen,omitempty"`
	// SessionCookieName is the broker SSO cookie shared by all apps
	// in one browser. Default cladone_broker_sid.
	SessionCookieName string `json:"sessionCookieName,omitempty"`
	// Tenants is the list of isolated issuers.
	Tenants []Tenant `json:"tenants"`
	// Redis is the shared store for flows/codes/refresh tokens and
	// the revocation keyspace read by Gate One. Absent = memory
	// (single instance, tests).
	Redis *RedisConfig `json:"redis,omitempty"`
}

// Tenant is one issuer: its own key, client, upstream IdP and policy.
type Tenant struct {
	ID string `json:"id"`

	// ClientID/ClientSecret are the Gate One client credentials.
	ClientID        string   `json:"clientId"`
	ClientSecret    string   `json:"clientSecret,omitempty"`
	ClientSecretEnv string   `json:"clientSecretEnv,omitempty"`
	RedirectURIs    []string `json:"redirectUris"`
	// PostLogoutRedirectURIs are the allowed post-logout targets.
	// Empty = RedirectURIs (safe default).
	PostLogoutRedirectURIs []string `json:"postLogoutRedirectUris,omitempty"`

	// Audiences allowed for access tokens. Empty = the tenant id.
	Audiences []string `json:"audiences,omitempty"`

	// Google is the upstream OIDC provider.
	Google GoogleConfig `json:"google"`

	// KeyFile holds the active Ed25519 private key (base64 raw seed).
	// KeyFiles publishes several keys (oldest first, newest active) so
	// tokens can be rotated without invalidating old tokens. Mutually
	// exclusive with KeyFile. Empty = an ephemeral key (tests/dev only).
	KeyFile  string   `json:"keyFile,omitempty"`
	KeyFiles []string `json:"keyFiles,omitempty"`

	// DefaultRoles applied to every authenticated user.
	DefaultRoles []string `json:"defaultRoles,omitempty"`
	// AllowedDomains restricts Google Workspace domains (hd) and
	// email domains. Empty = no restriction.
	AllowedDomains []string `json:"allowedDomains,omitempty"`
	// AdminEmails receive the "admin" role.
	AdminEmails []string `json:"adminEmails,omitempty"`
	// GroupRoles maps an upstream group/claim value to broker roles.
	GroupRoles map[string][]string `json:"groupRoles,omitempty"`

	AccessTokenTTL  int `json:"accessTokenTtlSeconds,omitempty"`
	IDTokenTTL      int `json:"idTokenTtlSeconds,omitempty"`
	RefreshTokenTTL int `json:"refreshTokenTtlSeconds,omitempty"`
	// SessionTTLSeconds is the broker SSO cookie/session lifetime.
	// Default 43200 (12h).
	SessionTTLSeconds int `json:"sessionTtlSeconds,omitempty"`
}

// GoogleConfig configures the upstream OIDC client.
type GoogleConfig struct {
	Issuer          string `json:"issuer,omitempty"` // default https://accounts.google.com
	ClientID        string `json:"clientId,omitempty"`
	ClientIDEnv     string `json:"clientIdEnv,omitempty"`
	ClientSecret    string `json:"clientSecret,omitempty"`
	ClientSecretEnv string `json:"clientSecretEnv,omitempty"`
	// Prompt is forwarded to the upstream authorize endpoint. The
	// canary uses "select_account" so a logout is not silently undone
	// by the Google account session.
	Prompt       string   `json:"prompt,omitempty"`
	HostedDomain string   `json:"hostedDomain,omitempty"`
	Scopes       []string `json:"scopes,omitempty"`
}

// Load reads and validates a broker configuration.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	for i := range cfg.Tenants {
		kf := strings.TrimSpace(cfg.Tenants[i].KeyFile)
		if kf != "" && !filepath.IsAbs(kf) {
			cfg.Tenants[i].KeyFile = filepath.Join(filepath.Dir(path), kf)
		}
		for j, name := range cfg.Tenants[i].KeyFiles {
			name = strings.TrimSpace(name)
			if name != "" && !filepath.IsAbs(name) {
				name = filepath.Join(filepath.Dir(path), name)
			}
			cfg.Tenants[i].KeyFiles[j] = name
		}
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &cfg, nil
}

// Validate checks the multi-tenant invariants.
func (c *Config) Validate() error {
	c.PublicURL = strings.TrimRight(strings.TrimSpace(c.PublicURL), "/")
	if c.PublicURL == "" {
		return fmt.Errorf("publicUrl is required")
	}
	c.SessionCookieName = strings.TrimSpace(c.SessionCookieName)
	if c.SessionCookieName == "" {
		c.SessionCookieName = "cladone_broker_sid"
	}
	if len(c.Tenants) == 0 {
		return fmt.Errorf("at least one tenant is required")
	}
	if c.Redis != nil {
		if c.Redis.PasswordEnv != "" {
			secret, ok := os.LookupEnv(c.Redis.PasswordEnv)
			if !ok || secret == "" {
				return fmt.Errorf(
					"redis: environment variable %s is empty",
					c.Redis.PasswordEnv)
			}
			c.Redis.Password = secret
		}
		if c.Redis.MasterName == "" && c.Redis.URL == "" {
			return fmt.Errorf("redis: url or masterName/sentinelAddrs required")
		}
		if c.Redis.MasterName != "" && len(c.Redis.SentinelAddrs) == 0 {
			return fmt.Errorf("redis: sentinelAddrs required with masterName")
		}
	}
	seen := map[string]bool{}
	for i := range c.Tenants {
		t := &c.Tenants[i]
		t.ID = strings.TrimSpace(t.ID)
		if t.ID == "" {
			return fmt.Errorf("tenants[%d]: id is required", i)
		}
		if seen[t.ID] {
			return fmt.Errorf("tenants: duplicate id %q", t.ID)
		}
		seen[t.ID] = true
		if t.ClientID == "" {
			return fmt.Errorf("tenants[%s]: clientId is required", t.ID)
		}
		if t.ClientSecretEnv != "" {
			secret, ok := os.LookupEnv(t.ClientSecretEnv)
			if !ok || secret == "" {
				return fmt.Errorf(
					"tenants[%s]: environment variable %s is empty",
					t.ID, t.ClientSecretEnv)
			}
			t.ClientSecret = secret
		}
		if len(t.RedirectURIs) == 0 {
			return fmt.Errorf("tenants[%s]: at least one redirectUri is required", t.ID)
		}
		for _, u := range t.RedirectURIs {
			if !isLocalRedirect(u) {
				return fmt.Errorf(
					"tenants[%s]: redirectUri %q must be https (or localhost for tests)",
					t.ID, u)
			}
		}
		if len(t.PostLogoutRedirectURIs) == 0 {
			t.PostLogoutRedirectURIs = append(
				[]string(nil), t.RedirectURIs...)
		}
		for _, u := range t.PostLogoutRedirectURIs {
			if !isLocalRedirect(u) {
				return fmt.Errorf(
					"tenants[%s]: postLogoutRedirectUri %q must be https (or localhost for tests)",
					t.ID, u)
			}
		}
		if t.KeyFile != "" && len(t.KeyFiles) > 0 {
			return fmt.Errorf(
				"tenants[%s]: keyFile and keyFiles are mutually exclusive",
				t.ID)
		}
		for _, kf := range t.KeyFiles {
			if strings.TrimSpace(kf) == "" {
				return fmt.Errorf("tenants[%s]: empty keyFiles entry", t.ID)
			}
		}
		if t.Google.Issuer == "" {
			t.Google.Issuer = "https://accounts.google.com"
		}
		if t.Google.ClientIDEnv != "" {
			id, ok := os.LookupEnv(t.Google.ClientIDEnv)
			if !ok || id == "" {
				return fmt.Errorf(
					"tenants[%s]: environment variable %s is empty",
					t.ID, t.Google.ClientIDEnv)
			}
			t.Google.ClientID = id
		}
		if t.Google.ClientID == "" {
			return fmt.Errorf("tenants[%s]: google.clientId is required", t.ID)
		}
		if t.Google.ClientSecretEnv != "" {
			secret, ok := os.LookupEnv(t.Google.ClientSecretEnv)
			if !ok || secret == "" {
				return fmt.Errorf(
					"tenants[%s]: environment variable %s is empty",
					t.ID, t.Google.ClientSecretEnv)
			}
			t.Google.ClientSecret = secret
		}
		if len(t.Google.Scopes) == 0 {
			t.Google.Scopes = []string{"openid", "profile", "email"}
		}
		if t.AccessTokenTTL <= 0 {
			t.AccessTokenTTL = 600 // 10 minutes
		}
		if t.IDTokenTTL <= 0 {
			t.IDTokenTTL = 600
		}
		if t.RefreshTokenTTL <= 0 {
			t.RefreshTokenTTL = 30 * 24 * 3600
		}
		if t.SessionTTLSeconds <= 0 {
			t.SessionTTLSeconds = 12 * 3600
		}
	}
	return nil
}

func (t *Tenant) accessTTL() time.Duration {
	return time.Duration(t.AccessTokenTTL) * time.Second
}

func (t *Tenant) idTTL() time.Duration {
	return time.Duration(t.IDTokenTTL) * time.Second
}

func (t *Tenant) sessionTTL() time.Duration {
	return time.Duration(t.SessionTTLSeconds) * time.Second
}

// logoutRevocationTTL must cover refresh tokens: a logout that revokes
// only the access-token lifetime would let a refresh mint a new token.
func (t *Tenant) logoutRevocationTTL() time.Duration {
	ttl := t.sessionTTL()
	if d := time.Duration(t.AccessTokenTTL) * time.Second; d > ttl {
		ttl = d
	}
	if d := t.idTTL(); d > ttl {
		ttl = d
	}
	if d := time.Duration(t.RefreshTokenTTL) * time.Second; d > ttl {
		ttl = d
	}
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	return ttl
}

// isLocalRedirect accepts HTTPS anywhere, or HTTP on a loopback or
// .localhost name (RFC 6761). The .localhost form is what lets the
// local Compose stack use real cookie domains (app.acme.localhost)
// without TLS.
func isLocalRedirect(raw string) bool {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return false
	}
	if u.Scheme == "https" {
		return true
	}
	if u.Scheme != "http" {
		return false
	}
	host := strings.ToLower(u.Hostname())
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	return host == "127.0.0.1" || host == "::1"
}
