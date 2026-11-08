package authn

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

// JWTConfig configures a stateless JWKS bearer verifier. It never
// hosts a login page: use it for API/MCP routes, while browser routes
// use an OIDC provider.
type JWTConfig struct {
	Issuer      string
	Audience    string
	JWKSURL     string
	Algorithms  []string
	RoleClaims  []string
	ScopesClaim string
	Header      string
	CookieName  string
	Now         func() time.Time
	HTTPClient  *http.Client
	CacheTTL    time.Duration
	Store       RevocationStore
}

// JWT implements Provider for a remote JWKS issuer.
type JWT struct {
	issuer     string
	audience   string
	header     string
	cookieName string
	roleClaims []string
	scopes     string
	verifier   *oidc.IDTokenVerifier
	keys       *remoteKeySet
	store      RevocationStore
}

// NewJWT builds the verifier. It does not fetch the JWKS at startup:
// an IAM outage must not prevent other tenants from starting. The
// first verification (or Health) fetches and caches the keys.
func NewJWT(ctx context.Context, cfg JWTConfig) (*JWT, error) {
	issuer := strings.TrimRight(strings.TrimSpace(cfg.Issuer), "/")
	if issuer == "" {
		return nil, fmt.Errorf("authProvider.type jwt: issuer is required")
	}
	jwksURL := strings.TrimSpace(cfg.JWKSURL)
	if jwksURL == "" {
		return nil, fmt.Errorf("authProvider.type jwt: jwksUrl is required")
	}
	algs := cfg.Algorithms
	if len(algs) == 0 {
		algs = []string{"EdDSA"}
	}
	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 5 * time.Second}
	}
	if cfg.HTTPClient != nil {
		ctx = oidc.ClientContext(ctx, cfg.HTTPClient)
	}
	keySet := newRemoteKeySet(
		jwksURL, hc, algs, cfg.CacheTTL, cfg.Now)
	verifier := oidc.NewVerifier(issuer, keySet, &oidc.Config{
		SkipClientIDCheck:    true,
		SupportedSigningAlgs: algs,
		Now:                  cfg.Now,
	})
	header := strings.TrimSpace(cfg.Header)
	if header == "" {
		header = "Authorization"
	}
	scopesClaim := strings.TrimSpace(cfg.ScopesClaim)
	if scopesClaim == "" {
		scopesClaim = "scope"
	}
	return &JWT{
		issuer:     issuer,
		audience:   strings.TrimSpace(cfg.Audience),
		header:     header,
		cookieName: strings.TrimSpace(cfg.CookieName),
		roleClaims: cfg.RoleClaims,
		scopes:     scopesClaim,
		verifier:   verifier,
		keys:       keySet,
		store:      cfg.Store,
	}, nil
}

func (j *JWT) Name() string   { return "jwt" }
func (j *JWT) Issuer() string { return j.issuer }
func (j *JWT) LoginURL() string {
	return ""
}

// Verify authenticates an API request from its Bearer token (or the
// configured cookie). There is no browser login: a missing token is
// a 401, never a redirect.
func (j *JWT) Verify(
	ctx context.Context,
	r *http.Request,
) (*Result, error) {
	return j.verify(ctx, r, "", "")
}

func (j *JWT) VerifyMCP(
	ctx context.Context,
	r *http.Request,
	scope, resource string,
) (*Result, error) {
	return j.verify(ctx, r, scope, resource)
}

func (j *JWT) verify(
	ctx context.Context,
	r *http.Request,
	scope, resource string,
) (*Result, error) {
	raw := j.token(r)
	if raw == "" {
		return nil, ErrUnauthenticated
	}
	if !jwtHasKID(raw) {
		// Key rotation and tenant isolation require an explicit key
		// id. A single-key JWKS without kid is accepted by go-oidc,
		// but we deliberately refuse it: a key swap would otherwise
		// be silently accepted.
		return nil, ErrUnauthenticated
	}
	ctx, status := withKeyStatus(ctx)
	tok, err := j.verifier.Verify(ctx, raw)
	if err != nil {
		if status.unavailable {
			return nil, ErrProviderUnavailable
		}
		return nil, ErrUnauthenticated
	}
	var claims map[string]any
	if err := tok.Claims(&claims); err != nil {
		return nil, ErrUnauthenticated
	}

	wantAud := j.audience
	if wantAud == "" && resource != "" {
		wantAud = resource
	}
	if wantAud != "" && !audienceContains(tok.Audience, wantAud) {
		return nil, ErrUnauthenticated
	}

	scopes := scopesFromClaims(claims, j.scopes)
	if scope != "" && !contains(scopes, scope) {
		return nil, ErrInsufficientScope
	}

	id := Identity{
		UserID:    stringClaim(claims, "sub"),
		SessionID: stringClaim(claims, "sid"),
		IssuedAt:  timeClaim(claims, "iat"),
		Username:  stringClaim(claims, "preferred_username"),
		Email:     stringClaim(claims, "email"),
		Roles:     rolesFromClaims(claims, j.roleClaims),
		Scopes:    scopes,
		Claims:    claims,
	}
	if id.Username == "" {
		id.Username = id.Email
	}
	if id.Username == "" {
		id.Username = id.UserID
	}
	if id.UserID == "" {
		return nil, ErrUnauthenticated
	}
	revoked, err := j.CheckRevoked(ctx, id)
	if err != nil {
		return nil, err
	}
	if revoked {
		return nil, ErrUnauthenticated
	}
	return &Result{Identity: id}, nil
}

func (j *JWT) token(r *http.Request) string {
	if j.cookieName != "" {
		if c, err := r.Cookie(j.cookieName); err == nil && c.Value != "" {
			return c.Value
		}
	}
	raw := strings.TrimSpace(r.Header.Get(j.header))
	if raw == "" {
		return ""
	}
	if strings.EqualFold(j.header, "Authorization") {
		parts := strings.Fields(raw)
		if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
			return parts[1]
		}
		return ""
	}
	if strings.HasPrefix(strings.ToLower(raw), "bearer ") {
		return strings.TrimSpace(raw[7:])
	}
	return raw
}

func (j *JWT) CheckRevoked(
	ctx context.Context, id Identity,
) (bool, error) {
	if j.store == nil {
		return false, nil
	}
	revoked, err := j.store.CheckRevoked(
		ctx, j.issuer, id.SessionID, id.UserID, id.IssuedAt)
	if err != nil {
		return false, fmt.Errorf("%w: %v", ErrProviderUnavailable, err)
	}
	return revoked, nil
}

// Close releases a Redis client. The shared bbolt store is
// process-lifetime by design and must not be closed on reload.
func (j *JWT) Close() error {
	if s, ok := j.store.(*RedisStore); ok {
		return s.Close()
	}
	return nil
}

func (j *JWT) Health(ctx context.Context) error {
	if s, ok := j.store.(*RedisStore); ok {
		if err := s.Health(ctx); err != nil {
			return fmt.Errorf("%w: %v", ErrProviderUnavailable, err)
		}
	}
	return j.keys.refresh(ctx)
}

// jwtHasKID checks the JOSE header without trusting any claim.
func jwtHasKID(raw string) bool {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return false
	}
	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return false
	}
	var h struct {
		KID string `json:"kid"`
	}
	if err := json.Unmarshal(header, &h); err != nil {
		return false
	}
	return strings.TrimSpace(h.KID) != ""
}
