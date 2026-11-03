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

	// SMTP sends the account-lifecycle emails (verification). Required
	// only when a tenant enables localAccounts.
	SMTP *SMTPConfig `json:"smtp,omitempty"`
}

// SMTPConfig is the outbound mail relay used for verification emails.
// The password is read from PasswordEnv at load and never serialized.
type SMTPConfig struct {
	Host        string `json:"host"`
	Port        int    `json:"port,omitempty"` // default 587 (STARTTLS)
	Username    string `json:"username,omitempty"`
	UsernameEnv string `json:"usernameEnv,omitempty"`
	PasswordEnv string `json:"passwordEnv,omitempty"`
	Password    string `json:"-"`
	From        string `json:"from"`
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

	// Google is the legacy single-upstream block. It is normalized
	// into Upstreams["google"] when Upstreams is absent.
	Google GoogleConfig `json:"google"`

	// Upstreams maps an IdP key (google, microsoft, …) to its OIDC
	// configuration. The key is the value of the `idp` authorize
	// parameter and the label on the chooser page.
	Upstreams map[string]GoogleConfig `json:"upstreams,omitempty"`

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
	// GroupRoles maps an upstream group/claim value to broker roles
	// (legacy, groups claim only). Prefer Mappings.
	GroupRoles map[string][]string `json:"groupRoles,omitempty"`

	// Mappings translates upstream claims into broker roles/scopes/
	// claims. It is evaluated on every federated login; the results are
	// not persisted on the user.
	Mappings []MappingRule `json:"mappings,omitempty"`

	AccessTokenTTL  int `json:"accessTokenTtlSeconds,omitempty"`
	IDTokenTTL      int `json:"idTokenTtlSeconds,omitempty"`
	RefreshTokenTTL int `json:"refreshTokenTtlSeconds,omitempty"`
	// SessionTTLSeconds is the broker SSO cookie/session lifetime.
	// Default 43200 (12h).
	SessionTTLSeconds int `json:"sessionTtlSeconds,omitempty"`

	// LocalAccounts enables the account lifecycle endpoints
	// (register + verify-email) for this tenant.
	LocalAccounts bool `json:"localAccounts,omitempty"`
	// AppOrigins is the allowlist of application origins accepted as
	// a verification continueUrl (e.g. https://vers.cladone.com).
	AppOrigins []string `json:"appOrigins,omitempty"`
	// RegistrationSecretEnv gates POST /register (server-to-server).
	RegistrationSecretEnv string `json:"registrationSecretEnv,omitempty"`
	RegistrationSecret    string `json:"-"`
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
	// DisplayName is shown on the IdP chooser (default: the idp key).
	DisplayName string `json:"displayName,omitempty"`
	// Optional upstreams are skipped (not shown, not validated) when
	// their clientIdEnv/clientSecretEnv is empty. Useful to ship a
	// provider before its credentials exist.
	Optional bool `json:"optional,omitempty"`
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
		c.Redis.MasterName = strings.TrimSpace(c.Redis.MasterName)
		c.Redis.URL = strings.TrimSpace(c.Redis.URL)
		c.Redis.SentinelUsername = strings.TrimSpace(c.Redis.SentinelUsername)
		c.Redis.SentinelPasswordEnv = strings.TrimSpace(c.Redis.SentinelPasswordEnv)
		c.Redis.TLSCaFile = strings.TrimSpace(c.Redis.TLSCaFile)
		c.Redis.TLSServerName = strings.TrimSpace(c.Redis.TLSServerName)
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
		if c.Redis.MasterName == "" && (c.Redis.SentinelUsername != "" ||
			c.Redis.SentinelPasswordEnv != "" || c.Redis.TLS ||
			c.Redis.TLSCaFile != "" || c.Redis.TLSServerName != "") {
			return fmt.Errorf(
				"redis: sentinelUsername/sentinelPasswordEnv/tls are only " +
					"valid in sentinel mode (masterName + sentinelAddrs)")
		}
		if !c.Redis.TLS && (c.Redis.TLSCaFile != "" || c.Redis.TLSServerName != "") {
			return fmt.Errorf(
				"redis: tlsCaFile/tlsServerName require tls=true")
		}
		if c.Redis.SentinelPasswordEnv != "" {
			secret, ok := os.LookupEnv(c.Redis.SentinelPasswordEnv)
			if !ok || secret == "" {
				return fmt.Errorf(
					"redis: environment variable %s is empty",
					c.Redis.SentinelPasswordEnv)
			}
			c.Redis.SentinelPassword = secret
		}
		if c.Redis.TLSCaFile != "" {
			if _, err := os.Stat(c.Redis.TLSCaFile); err != nil {
				return fmt.Errorf("redis.tlsCaFile: %w", err)
			}
		}
	}
	if c.SMTP != nil {
		c.SMTP.Host = strings.TrimSpace(c.SMTP.Host)
		c.SMTP.From = strings.TrimSpace(c.SMTP.From)
		if c.SMTP.Port == 0 {
			c.SMTP.Port = 587
		}
		if c.SMTP.UsernameEnv != "" {
			name, ok := os.LookupEnv(c.SMTP.UsernameEnv)
			if !ok || name == "" {
				return fmt.Errorf(
					"smtp: environment variable %s is empty",
					c.SMTP.UsernameEnv)
			}
			c.SMTP.Username = name
		}
		if c.SMTP.PasswordEnv != "" {
			secret, ok := os.LookupEnv(c.SMTP.PasswordEnv)
			if !ok || secret == "" {
				return fmt.Errorf(
					"smtp: environment variable %s is empty",
					c.SMTP.PasswordEnv)
			}
			c.SMTP.Password = secret
		}
		if c.SMTP.Host == "" || c.SMTP.From == "" {
			return fmt.Errorf("smtp: host and from are required")
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
		// Normalize the legacy google block into Upstreams.
		if len(t.Upstreams) == 0 {
			t.Upstreams = map[string]GoogleConfig{}
			if t.Google.ClientID != "" || t.Google.ClientIDEnv != "" {
				t.Upstreams["google"] = t.Google
			}
		} else if t.Google.ClientID != "" || t.Google.ClientIDEnv != "" {
			if _, ok := t.Upstreams["google"]; !ok {
				t.Upstreams["google"] = t.Google
			}
		}
		for id, up := range t.Upstreams {
			id = strings.TrimSpace(id)
			if id == "" {
				return fmt.Errorf("tenants[%s]: empty upstream id", t.ID)
			}
			if up.Issuer == "" {
				if id == "google" {
					up.Issuer = "https://accounts.google.com"
				} else {
					return fmt.Errorf(
						"tenants[%s]: upstreams[%s].issuer is required",
						t.ID, id)
				}
			}
			if up.ClientIDEnv != "" {
				v, ok := os.LookupEnv(up.ClientIDEnv)
				if !ok || v == "" {
					if up.Optional {
						delete(t.Upstreams, id)
						continue
					}
					return fmt.Errorf(
						"tenants[%s]: environment variable %s is empty",
						t.ID, up.ClientIDEnv)
				}
				up.ClientID = v
			}
			if up.ClientID == "" {
				if up.Optional {
					delete(t.Upstreams, id)
					continue
				}
				return fmt.Errorf(
					"tenants[%s]: upstreams[%s].clientId is required",
					t.ID, id)
			}
			if up.ClientSecretEnv != "" {
				v, ok := os.LookupEnv(up.ClientSecretEnv)
				if !ok || v == "" {
					if up.Optional {
						delete(t.Upstreams, id)
						continue
					}
					return fmt.Errorf(
						"tenants[%s]: environment variable %s is empty",
						t.ID, up.ClientSecretEnv)
				}
				up.ClientSecret = v
			}
			if len(up.Scopes) == 0 {
				up.Scopes = []string{"openid", "profile", "email"}
			}
			if up.DisplayName == "" {
				switch id {
				case "google":
					up.DisplayName = "Google"
				case "microsoft":
					up.DisplayName = "Microsoft"
				default:
					up.DisplayName = id
				}
			}
			t.Upstreams[id] = up
		}
		if len(t.Upstreams) == 0 && !t.LocalAccounts {
			return fmt.Errorf(
				"tenants[%s]: at least one upstream or localAccounts is required",
				t.ID)
		}
		if g, ok := t.Upstreams["google"]; ok {
			t.Google = g // legacy accessor (tests / old callers)
		}
		if t.LocalAccounts {
			if c.SMTP == nil {
				return fmt.Errorf(
					"tenants[%s]: localAccounts requires the smtp block", t.ID)
			}
			if len(t.AppOrigins) == 0 {
				return fmt.Errorf(
					"tenants[%s]: localAccounts requires appOrigins", t.ID)
			}
			for j, origin := range t.AppOrigins {
				origin = strings.TrimRight(strings.TrimSpace(origin), "/")
				u, err := url.Parse(origin)
				if err != nil || u.Host == "" ||
					(u.Scheme != "http" && u.Scheme != "https") {
					return fmt.Errorf(
						"tenants[%s]: appOrigins[%d] %q: absolute http(s) URL required",
						t.ID, j, origin)
				}
				t.AppOrigins[j] = origin
			}
			if t.RegistrationSecretEnv == "" {
				return fmt.Errorf(
					"tenants[%s]: localAccounts requires registrationSecretEnv",
					t.ID)
			}
			secret, ok := os.LookupEnv(t.RegistrationSecretEnv)
			if !ok || secret == "" {
				return fmt.Errorf(
					"tenants[%s]: environment variable %s is empty",
					t.ID, t.RegistrationSecretEnv)
			}
			t.RegistrationSecret = secret
		}
		if err := validateMappingRules(t.Mappings); err != nil {
			return fmt.Errorf("tenants[%s]: %w", t.ID, err)
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

// revocationTTL is the lifetime of a revocation written without an
// explicit TTL (CLI `revoke`): the refresh token TTL is the source of
// truth — it is the longest replayable credential. A revocation that
// expires before the refresh token would let a refresh mint a new
// session after the logout. Never shorter than the session TTL.
func (t *Tenant) revocationTTL() time.Duration {
	ttl := time.Duration(t.RefreshTokenTTL) * time.Second
	if s := t.sessionTTL(); s > ttl {
		ttl = s
	}
	if ttl <= 0 {
		ttl = 30 * 24 * time.Hour
	}
	return ttl
}

// TenantRevocationTTL returns the revocation lifetime for a tenant:
// the refresh token TTL (never shorter than the session TTL).
func TenantRevocationTTL(
	cfg *Config, tenantID string,
) (time.Duration, error) {
	if cfg == nil {
		return 0, fmt.Errorf("broker: nil config")
	}
	for i := range cfg.Tenants {
		if cfg.Tenants[i].ID == tenantID {
			return cfg.Tenants[i].revocationTTL(), nil
		}
	}
	return 0, fmt.Errorf("broker: unknown tenant %q", tenantID)
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
// local Compose stack use real cookie domains (app.mycompany.localhost)
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
