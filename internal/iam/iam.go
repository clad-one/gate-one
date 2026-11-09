package iam

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"cladone/gate-one/pkg/identityadapter"

	"github.com/go-jose/go-jose/v4"
)

// IAM is a multi-tenant OIDC issuer federating an upstream IdP.
type IAM struct {
	cfg      *Config
	tenants  map[string]*tenantRuntime
	store    store
	accounts accountsStore
	mailer   Mailer
	now      func() time.Time
	rand     io.Reader
}

type tenantRuntime struct {
	cfg          Tenant
	adapter      identityadapter.Adapter // legacy default (google)
	adapters     map[string]identityadapter.Adapter
	adapterOrder []string
	keys         []*signingKey
}

// loginMethods is the ordered list shown on the IdP chooser: local
// first, then the configured upstreams.
func (rt *tenantRuntime) loginMethods() []string {
	out := make([]string, 0, len(rt.adapterOrder)+1)
	if rt.cfg.LocalAccounts {
		out = append(out, "local")
	}
	out = append(out, rt.adapterOrder...)
	return out
}

func (rt *tenantRuntime) adapterFor(idp string) identityadapter.Adapter {
	if rt.adapters != nil {
		return rt.adapters[idp]
	}
	if idp == "" || idp == "google" {
		return rt.adapter
	}
	return nil
}

func (rt *tenantRuntime) activeKey() *signingKey {
	if rt == nil || len(rt.keys) == 0 {
		return nil
	}
	return rt.keys[len(rt.keys)-1]
}

type flow struct {
	Tenant            string
	ClientID          string
	RedirectURI       string
	State             string
	Nonce             string
	BrowserID         string
	SID               string
	Sub               string
	SessionIssuedAt   time.Time
	AdapterState      []byte
	Scope             string
	CodeChallenge     string
	CodeChallengeMeth string
	AdapterID         string
	AuthorizeQuery    string
	CSRF              string
	Expires           time.Time
}

// flowTTL is the authorize-to-callback window. It must be at least
// the Gate One OIDC transaction TTL so a slow upstream login (email
// verification, MFA) does not expire one side before the other.
const flowTTL = 15 * time.Minute

// upstreamSession keeps the upstream IdP facts needed for an
// RP-initiated logout (id_token_hint, end_session_endpoint).
type upstreamSession struct {
	AdapterID  string `json:"adapterId"`
	IDToken    string `json:"idToken,omitempty"`
	EndSession string `json:"endSession,omitempty"`
	ClientID   string `json:"clientId,omitempty"`
}

type authCode struct {
	Tenant            string
	ClientID          string
	RedirectURI       string
	Scope             string
	Nonce             string
	CodeChallenge     string
	CodeChallengeMeth string
	Subject           string
	Username          string
	Email             string
	Roles             []string
	Scopes            []string
	Claims            map[string]any
	SID               string
	IssuedAt          time.Time
	Expires           time.Time
}

type refreshGrant struct {
	Tenant   string
	ClientID string
	Subject  string
	Username string
	Email    string
	Roles    []string
	Scopes   []string
	Claims   map[string]any
	SID      string
	IssuedAt time.Time
	Scope    string
	Audience string
	Expires  time.Time
}

// Option customizes the IAM (tests).
type Option func(*IAM)

// WithClock replaces time.Now.
func WithClock(now func() time.Time) Option {
	return func(b *IAM) {
		if now != nil {
			b.now = now
		}
	}
}

// WithMailer replaces the SMTP mailer (tests, alternative relay).
func WithMailer(m Mailer) Option {
	return func(b *IAM) {
		if m != nil {
			b.mailer = m
		}
	}
}

// WithRand replaces crypto/rand.Reader.
func WithRand(r io.Reader) Option {
	return func(b *IAM) {
		if r != nil {
			b.rand = r
		}
	}
}

// New discovers the upstream IdP and builds every tenant.
func New(ctx context.Context, cfg *Config, opts ...Option) (*IAM, error) {
	if cfg == nil {
		return nil, fmt.Errorf("iam: nil config")
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	b := &IAM{
		cfg:     cfg,
		tenants: map[string]*tenantRuntime{},
		now:     time.Now,
		rand:    rand.Reader,
	}
	var st store = newMemoryStore()
	if cfg.Redis != nil {
		rs, err := newRedisStore(ctx, *cfg.Redis)
		if err != nil {
			return nil, err
		}
		st = rs
	}
	b.store = st
	if rs, ok := st.(*redisStore); ok && cfg.Redis != nil {
		b.accounts = &redisAccounts{
			client: rs.client,
			prefix: cfg.Redis.Prefix + "accounts:",
		}
	} else {
		b.accounts = newMemoryAccounts()
	}
	if cfg.SMTP != nil {
		b.mailer = newSMTPMailer(*cfg.SMTP)
	}
	ok := false
	defer func() {
		if !ok {
			_ = st.Close()
		}
	}()
	for _, opt := range opts {
		opt(b)
	}
	for i := range cfg.Tenants {
		t := cfg.Tenants[i]
		adapters := make(map[string]identityadapter.Adapter, len(t.Upstreams))
		order := make([]string, 0, len(t.Upstreams))
		for id, up := range t.Upstreams {
			a, err := newUpstreamAdapter(
				ctx, t.ID, id, up, cfg.PublicURL, nil, b.now, b.rand)
			if err != nil {
				return nil, err
			}
			adapters[id] = a
			order = append(order, id)
		}
		sort.Strings(order)
		var keyFiles []string
		if len(t.KeyFiles) > 0 {
			keyFiles = append(keyFiles, t.KeyFiles...)
		} else {
			keyFiles = []string{t.KeyFile}
		}
		keys := make([]*signingKey, 0, len(keyFiles))
		seenKID := map[string]bool{}
		for _, kf := range keyFiles {
			key, err := loadSigningKey(t.ID, kf)
			if err != nil {
				return nil, err
			}
			if seenKID[key.kid] {
				return nil, fmt.Errorf(
					"tenant %s: duplicate signing key %s", t.ID, key.kid)
			}
			seenKID[key.kid] = true
			keys = append(keys, key)
		}
		rt := &tenantRuntime{
			cfg:          t,
			adapters:     adapters,
			adapterOrder: order,
			keys:         keys,
		}
		if g, ok := adapters["google"]; ok {
			rt.adapter = g
		}
		b.tenants[t.ID] = rt
	}
	ok = true
	return b, nil
}

// Revoke writes a shared revocation key for a tenant session/user.
// Gate One reads the same key (same authPrefix) on the next request.
func (b *IAM) Revoke(
	ctx context.Context, tenantID, sid, sub string, expires time.Time,
) error {
	rt := b.tenants[tenantID]
	if rt == nil {
		return fmt.Errorf("iam: unknown tenant %q", tenantID)
	}
	return b.store.Revoke(ctx, b.issuer(rt), sid, sub, expires)
}

// RevokeWithConfig writes a revocation without starting the IAM or
// discovering Google. It is used by the `cladone-auth revoke` CLI and
// requires Redis (a memory store would not be shared).
func RevokeWithConfig(
	ctx context.Context, cfg *Config,
	tenantID, sid, sub string, ttl time.Duration,
) error {
	if cfg == nil {
		return fmt.Errorf("iam: nil config")
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	if cfg.Redis == nil {
		return fmt.Errorf("iam revoke: redis configuration is required")
	}
	var found *Tenant
	for i := range cfg.Tenants {
		if cfg.Tenants[i].ID == tenantID {
			found = &cfg.Tenants[i]
			break
		}
	}
	if found == nil {
		return fmt.Errorf("iam revoke: unknown tenant %q", tenantID)
	}
	if sid == "" && sub == "" {
		return fmt.Errorf("iam revoke: sid or sub is required")
	}
	if ttl <= 0 {
		// The refresh token is the longest replayable credential:
		// default to its TTL (never shorter than the session).
		ttl = found.revocationTTL()
	}
	st, err := newRedisStore(ctx, *cfg.Redis)
	if err != nil {
		return err
	}
	defer st.Close()
	issuer := cfg.PublicURL + "/t/" + found.ID
	return st.Revoke(ctx, issuer, sid, sub, time.Now().Add(ttl))
}

// Close releases the Redis client (no-op for memory).
func (b *IAM) Close() error {
	if b.accounts != nil {
		_ = b.accounts.Close()
	}
	if b.store != nil {
		return b.store.Close()
	}
	return nil
}

// Handler returns the IAM HTTP handler.
func (b *IAM) Handler() http.Handler { return http.HandlerFunc(b.serveHTTP) }

// SetPublicURL updates the external origin. It is used by tests after
// httptest starts (the port is only known then) and by deployments
// behind a dynamic ingress. Issuers and Google redirect URIs follow.
func (b *IAM) SetPublicURL(raw string) {
	b.cfg.PublicURL = strings.TrimRight(strings.TrimSpace(raw), "/")
	for _, rt := range b.tenants {
		if len(rt.adapters) == 0 && rt.adapter != nil {
			if u, ok := rt.adapter.(interface{ SetRedirectURL(string) }); ok {
				u.SetRedirectURL(b.cfg.PublicURL)
			}
			continue
		}
		for _, a := range rt.adapters {
			if u, ok := a.(interface{ SetRedirectURL(string) }); ok {
				u.SetRedirectURL(b.cfg.PublicURL)
			}
		}
	}
}

// browserSession reads the IAM SSO cookie and returns the browser
// session id plus the shared OIDC sid. The cookie is host-only on the
// IAM and scoped to /t/{tenant}: apps never receive it.
func (b *IAM) browserSession(
	ctx context.Context, rt *tenantRuntime, r *http.Request,
) (browserID, sid, sub string, issuedAt time.Time, err error) {
	c, cerr := r.Cookie(b.cfg.SessionCookieName)
	if cerr != nil || c.Value == "" {
		return "", "", "", time.Time{}, nil
	}
	sid, sub, issuedAt, err = b.store.GetSession(ctx, rt.cfg.ID, c.Value)
	if err != nil {
		return "", "", "", time.Time{}, err
	}
	if sid != "" {
		revoked, rerr := b.store.IsRevoked(ctx, b.issuer(rt), sid, "")
		if rerr != nil {
			return "", "", "", time.Time{}, rerr
		}
		if !revoked && sub != "" {
			revoked, rerr = b.store.IsSubjectRevoked(
				ctx, b.issuer(rt), sub, issuedAt)
			if rerr != nil {
				return "", "", "", time.Time{}, rerr
			}
		}
		if revoked {
			// Gate One revoked this sid/sub (e.g. logout from another app).
			// Start a fresh login/sid on the next callback.
			_ = b.store.DeleteSession(ctx, rt.cfg.ID, c.Value)
			return c.Value, "", "", time.Time{}, nil
		}
	}
	return c.Value, sid, sub, issuedAt, nil
}

func (b *IAM) setBrowserSession(
	w http.ResponseWriter, rt *tenantRuntime, id string,
) {
	http.SetCookie(w, &http.Cookie{
		Name:     b.cfg.SessionCookieName,
		Value:    id,
		Path:     "/t/" + rt.cfg.ID,
		MaxAge:   int(rt.cfg.sessionTTL().Seconds()),
		HttpOnly: true,
		Secure:   strings.HasPrefix(b.cfg.PublicURL, "https://"),
		SameSite: http.SameSiteLaxMode,
	})
}

func (b *IAM) clearBrowserSession(w http.ResponseWriter, rt *tenantRuntime) {
	http.SetCookie(w, &http.Cookie{
		Name:     b.cfg.SessionCookieName,
		Value:    "",
		Path:     "/t/" + rt.cfg.ID,
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   strings.HasPrefix(b.cfg.PublicURL, "https://"),
		SameSite: http.SameSiteLaxMode,
	})
}

// idTokenHintSID verifies an IAM-issued ID token and extracts sid/sub.
// The hint is only a hint: it is verified against the tenant keys.
func (b *IAM) idTokenHintSID(
	rt *tenantRuntime, raw string,
) (sid, sub string) {
	if raw == "" {
		return "", ""
	}
	jws, err := jose.ParseSigned(raw, []jose.SignatureAlgorithm{jose.EdDSA})
	if err != nil {
		return "", ""
	}
	for _, k := range rt.keys {
		if k == nil {
			continue
		}
		payload, err := jws.Verify(k.pub)
		if err != nil {
			continue
		}
		var claims map[string]any
		if json.Unmarshal(payload, &claims) != nil {
			return "", ""
		}
		if iss, _ := claims["iss"].(string); iss != b.issuer(rt) {
			return "", ""
		}
		sid, _ = claims["sid"].(string)
		sub, _ = claims["sub"].(string)
		return sid, sub
	}
	return "", ""
}

// revokeLogoutSession revokes the browser's shared sid (or sub when no
// sid is available), deletes the IAM session and clears the cookie.
func (b *IAM) revokeLogoutSession(
	ctx context.Context, w http.ResponseWriter, rt *tenantRuntime, r *http.Request,
) error {
	browserID, sid, sub, _, err := b.browserSession(ctx, rt, r)
	if err != nil {
		return err
	}
	if sid == "" {
		sid, sub = b.idTokenHintSID(rt, r.URL.Query().Get("id_token_hint"))
	}
	if sid == "" && sub == "" {
		b.clearBrowserSession(w, rt)
		return nil
	}
	expires := b.now().Add(rt.cfg.logoutRevocationTTL())
	if err := b.store.Revoke(ctx, b.issuer(rt), sid, sub, expires); err != nil {
		return err
	}
	if browserID != "" {
		_ = b.store.DeleteSession(ctx, rt.cfg.ID, browserID)
	}
	b.clearBrowserSession(w, rt)
	return nil
}

func (b *IAM) sessionRevoked(
	ctx context.Context, rt *tenantRuntime,
	sid, sub string, issuedAt time.Time,
) (bool, error) {
	if sid != "" {
		revoked, err := b.store.IsRevoked(ctx, b.issuer(rt), sid, "")
		if err != nil || revoked {
			return revoked, err
		}
	}
	if sub != "" {
		return b.store.IsSubjectRevoked(
			ctx, b.issuer(rt), sub, issuedAt)
	}
	return false, nil
}

func (b *IAM) serveHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")

	if r.URL.Path == "/health" {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"status":"ok"}`)
		return
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/")
	if len(parts) < 3 || parts[0] != "t" {
		http.NotFound(w, r)
		return
	}
	tenantID := parts[1]
	action := strings.Join(parts[2:], "/")
	rt := b.tenants[tenantID]
	if rt == nil {
		http.NotFound(w, r)
		return
	}
	switch action {
	case ".well-known/openid-configuration":
		b.discovery(w, r, rt)
	case "jwks.json":
		b.jwks(w, r, rt)
	case "authorize":
		b.authorize(w, r, rt)
	case "callback":
		b.callback(w, r, rt)
	case "token":
		b.token(w, r, rt)
	case "logout":
		b.logout(w, r, rt)
	case "logout/done":
		b.logoutDone(w, r, rt)
	case "login":
		b.login(w, r, rt)
	case "register":
		b.register(w, r, rt)
	case "verify-email":
		b.verifyEmail(w, r, rt)
	default:
		http.NotFound(w, r)
	}
}

func (b *IAM) issuer(rt *tenantRuntime) string {
	return b.cfg.PublicURL + "/t/" + rt.cfg.ID
}

func (b *IAM) discovery(w http.ResponseWriter, r *http.Request, rt *tenantRuntime) {
	iss := b.issuer(rt)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"issuer":                                iss,
		"authorization_endpoint":                iss + "/authorize",
		"token_endpoint":                        iss + "/token",
		"jwks_uri":                              iss + "/jwks.json",
		"end_session_endpoint":                  iss + "/logout",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "client_credentials", "refresh_token"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"EdDSA"},
		"scopes_supported":                      []string{"openid", "profile", "email", "mcp-tools"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_post", "none"},
		"code_challenge_methods_supported":      []string{"S256"},
		// Custom metadata: Gate One uses this as the default
		// revocation retention so a logout blocks refresh tokens
		// without a fixed 24h guess.
		"cladone_refresh_token_ttl_seconds": rt.cfg.RefreshTokenTTL,
	})
}

func (b *IAM) jwks(w http.ResponseWriter, r *http.Request, rt *tenantRuntime) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(mergeJWKS(rt.keys))
}

func (b *IAM) authorize(w http.ResponseWriter, r *http.Request, rt *tenantRuntime) {
	q := r.URL.Query()
	clientID := q.Get("client_id")
	redirectURI := q.Get("redirect_uri")
	state := q.Get("state")
	scope := q.Get("scope")
	if clientID != rt.cfg.ClientID {
		oauthError(w, http.StatusBadRequest, "invalid_client", "unknown client_id")
		return
	}
	if !containsString(rt.cfg.RedirectURIs, redirectURI) {
		oauthError(w, http.StatusBadRequest, "invalid_request", "redirect_uri is not registered")
		return
	}
	if q.Get("response_type") != "code" {
		oauthError(w, http.StatusBadRequest, "unsupported_response_type", "only code is supported")
		return
	}
	if state == "" {
		oauthError(w, http.StatusBadRequest, "invalid_request", "state is required")
		return
	}
	if !scopeHas(scope, "openid") {
		oauthError(w, http.StatusBadRequest, "invalid_scope", "openid scope is required")
		return
	}
	challenge := q.Get("code_challenge")
	method := q.Get("code_challenge_method")
	if challenge != "" && method != "S256" {
		oauthError(w, http.StatusBadRequest, "invalid_request", "only S256 PKCE is supported")
		return
	}
	if challenge == "" && rt.cfg.ClientSecret == "" {
		oauthError(w, http.StatusBadRequest, "invalid_request", "PKCE is required for a public client")
		return
	}

	browserID, sharedSID, sharedSub, sharedIssuedAt, err := b.browserSession(r.Context(), rt, r)
	if err != nil {
		oauthError(w, http.StatusBadGateway, "server_error", "session store unavailable")
		return
	}
	nonce := q.Get("nonce")
	if nonce == "" {
		nonce = b.randomHex(16)
	}
	flowID := b.randomHex(24)
	idp := strings.TrimSpace(q.Get("idp"))
	methods := rt.loginMethods()
	if idp == "" {
		if len(methods) == 1 {
			idp = methods[0]
		} else {
			b.writeChooser(w, r, rt, methods)
			return
		}
	}

	log.Printf("iam: authorize tenant=%s idp=%s client=%s",
		rt.cfg.ID, idp, clientID)

	if idp == "local" {
		if !rt.cfg.LocalAccounts {
			oauthError(w, http.StatusBadRequest, "invalid_request",
				"local login is not enabled for this tenant")
			return
		}
		csrf := b.randomHex(16)
		if err := b.store.PutFlow(r.Context(), rt.cfg.ID, flowID, &flow{
			Tenant:            rt.cfg.ID,
			ClientID:          clientID,
			RedirectURI:       redirectURI,
			State:             state,
			Nonce:             nonce,
			BrowserID:         browserID,
			SID:               sharedSID,
			Sub:               sharedSub,
			SessionIssuedAt:   sharedIssuedAt,
			Scope:             scope,
			CodeChallenge:     challenge,
			CodeChallengeMeth: method,
			AuthorizeQuery:    r.URL.RawQuery,
			CSRF:              csrf,
			Expires:           b.now().Add(flowTTL),
		}, flowTTL); err != nil {
			oauthError(w, http.StatusBadGateway, "server_error", "flow store unavailable")
			return
		}
		http.Redirect(w, r, b.issuer(rt)+"/login?flow="+flowID,
			http.StatusFound)
		return
	}

	adapter := rt.adapterFor(idp)
	if adapter == nil {
		oauthError(w, http.StatusBadRequest, "invalid_request",
			"unknown or disabled idp")
		return
	}
	step, err := adapter.Start(r.Context(), identityadapter.Request{
		Tenant:     rt.cfg.ID,
		Method:     r.Method,
		URL:        r.URL.String(),
		RemoteAddr: r.RemoteAddr,
		Header:     r.Header.Clone(),
		Params: map[string]string{
			"iam_state": flowID,
			"nonce":     nonce,
		},
	})
	if err != nil {
		oauthError(w, http.StatusBadGateway, "server_error", "upstream login unavailable")
		return
	}
	if step.Kind != identityadapter.StepRedirect || step.RedirectURL == "" {
		oauthError(w, http.StatusBadGateway, "server_error", "upstream login did not redirect")
		return
	}
	if err := b.store.PutFlow(r.Context(), rt.cfg.ID, flowID, &flow{
		Tenant:            rt.cfg.ID,
		ClientID:          clientID,
		RedirectURI:       redirectURI,
		State:             state,
		Nonce:             nonce,
		BrowserID:         browserID,
		SID:               sharedSID,
		Sub:               sharedSub,
		SessionIssuedAt:   sharedIssuedAt,
		AdapterState:      step.State,
		AdapterID:         idp,
		Scope:             scope,
		CodeChallenge:     challenge,
		CodeChallengeMeth: method,
		Expires:           b.now().Add(flowTTL),
	}, flowTTL); err != nil {
		oauthError(w, http.StatusBadGateway, "server_error", "flow store unavailable")
		return
	}

	http.Redirect(w, r, step.RedirectURL, http.StatusFound)
}

func (b *IAM) callback(w http.ResponseWriter, r *http.Request, rt *tenantRuntime) {
	q := r.URL.Query()
	state := q.Get("state")
	f, err := b.store.TakeFlow(r.Context(), rt.cfg.ID, state)
	if err != nil {
		oauthError(w, http.StatusBadGateway, "server_error", "flow store unavailable")
		return
	}
	if f == nil || b.now().After(f.Expires) {
		log.Printf("iam: callback expired/unknown state tenant=%s state=%q",
			rt.cfg.ID, state)
		writeRestartPage(w, rt,
			"The login session has expired or was already used.")
		return
	}
	if e := q.Get("error"); e != "" {
		oauthError(w, http.StatusBadRequest, e, q.Get("error_description"))
		return
	}
	code := q.Get("code")
	if code == "" {
		oauthError(w, http.StatusBadRequest, "invalid_request", "missing code")
		return
	}
	adapter := rt.adapterFor(f.AdapterID)
	if adapter == nil {
		oauthError(w, http.StatusBadRequest, "invalid_request",
			"unknown upstream")
		return
	}
	step, err := adapter.Continue(
		r.Context(),
		identityadapter.Request{
			Tenant:     rt.cfg.ID,
			Method:     r.Method,
			URL:        r.URL.String(),
			RemoteAddr: r.RemoteAddr,
			Header:     r.Header.Clone(),
			Params:     map[string]string{"code": code},
		},
		f.AdapterState,
	)
	if err != nil {
		switch {
		case errors.Is(err, identityadapter.ErrInvalidRequest):
			oauthError(w, http.StatusBadRequest, "invalid_request", "upstream callback rejected")
		case errors.Is(err, identityadapter.ErrUnauthenticated):
			oauthError(w, http.StatusForbidden, "access_denied", "upstream identity rejected")
		default:
			oauthError(w, http.StatusBadGateway, "upstream_error", "upstream unavailable")
		}
		return
	}
	if step.Kind != identityadapter.StepResult || step.Assertion == nil {
		oauthError(w, http.StatusBadGateway, "upstream_error", "upstream returned no assertion")
		return
	}
	a := step.Assertion
	claims := a.Claims
	if claims == nil {
		claims = map[string]any{}
	}
	if len(a.Groups) > 0 {
		if _, ok := claims["groups"]; !ok {
			claims["groups"] = a.Groups
		}
	}
	if verified, ok := claims["email_verified"].(bool); ok && !verified {
		oauthError(w, http.StatusForbidden, "access_denied", "email is not verified")
		return
	}
	email := a.Email
	if !rt.domainAllowed(email, claims) {
		oauthError(w, http.StatusForbidden, "access_denied", "domain is not allowed")
		return
	}
	sub := a.Subject
	if sub == "" {
		oauthError(w, http.StatusBadGateway, "upstream_error", "upstream subject is empty")
		return
	}
	issuer := claimString(claims, "iss")
	if issuer == "" {
		issuer = rt.upstreamIssuer(f.AdapterID)
	}
	user, err := b.upsertFederatedUser(
		r.Context(), rt, issuer, sub, email, a.Username, claims)
	if err != nil {
		oauthError(w, http.StatusBadGateway, "server_error", "user store unavailable")
		return
	}
	if user.Disabled {
		oauthError(w, http.StatusForbidden, "access_denied", "user is disabled")
		return
	}
	rights := rt.effectiveRights(user, claims)
	username := a.Username
	if username == "" {
		username = email
	}
	log.Printf("iam: login tenant=%s adapter=%s email=%s",
		rt.cfg.ID, f.AdapterID, email)

	var upstream *upstreamSession
	if a.IDToken != "" {
		upstream = &upstreamSession{
			AdapterID: f.AdapterID,
			IDToken:   a.IDToken,
		}
		if es, ok := adapter.(interface{ EndSessionURL() string }); ok {
			upstream.EndSession = es.EndSessionURL()
		}
		if cid, ok := adapter.(interface{ ClientID() string }); ok {
			upstream.ClientID = cid.ClientID()
		}
	}
	b.finishLogin(w, r, rt, f, loginIdentity{
		Sub:      sub,
		Username: username,
		Email:    email,
		Roles:    rights.Roles,
		Scopes:   rights.Scopes,
		Claims:   rights.Claims,
	}, upstream)
}

// loginIdentity is the authenticated principal a completed login
// (upstream or local) hands to the code/session issuance.
type loginIdentity struct {
	Sub      string
	Username string
	Email    string
	Roles    []string
	Scopes   []string
	Claims   map[string]any
}

// finishLogin stores the IAM SSO session, sets the cookie, issues a
// single-use authorization code and redirects to the RP callback.
// Shared by the upstream callback and the local password login.
func (b *IAM) finishLogin(
	w http.ResponseWriter, r *http.Request, rt *tenantRuntime,
	f *flow, id loginIdentity, upstream *upstreamSession,
) {
	iamCode := b.randomHex(24)
	sid := f.SID
	if sid == "" {
		sid = b.randomHex(16)
	}
	browserID := f.BrowserID
	if browserID == "" {
		browserID = b.randomHex(24)
	}
	issuedAt := f.SessionIssuedAt
	if issuedAt.IsZero() {
		issuedAt = b.now()
	}
	if err := b.store.PutSession(
		r.Context(), rt.cfg.ID, browserID, sid, id.Sub, issuedAt,
		rt.cfg.sessionTTL(),
	); err != nil {
		oauthError(w, http.StatusBadGateway, "server_error", "session store unavailable")
		return
	}
	if upstream != nil {
		if err := b.store.PutUpstream(
			r.Context(), rt.cfg.ID, browserID, upstream,
			rt.cfg.sessionTTL(),
		); err != nil {
			oauthError(w, http.StatusBadGateway, "server_error",
				"upstream session store unavailable")
			return
		}
	}
	b.setBrowserSession(w, rt, browserID)
	if err := b.store.PutCode(r.Context(), rt.cfg.ID, iamCode, &authCode{
		Tenant:            rt.cfg.ID,
		ClientID:          f.ClientID,
		RedirectURI:       f.RedirectURI,
		Scope:             f.Scope,
		Nonce:             f.Nonce,
		CodeChallenge:     f.CodeChallenge,
		CodeChallengeMeth: f.CodeChallengeMeth,
		Subject:           id.Sub,
		Username:          id.Username,
		Email:             id.Email,
		Roles:             id.Roles,
		Scopes:            id.Scopes,
		Claims:            id.Claims,
		SID:               sid,
		IssuedAt:          b.now(),
		Expires:           b.now().Add(5 * time.Minute),
	}, 5*time.Minute); err != nil {
		oauthError(w, http.StatusBadGateway, "server_error", "code store unavailable")
		return
	}

	redirect, err := url.Parse(f.RedirectURI)
	if err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", "bad redirect_uri")
		return
	}
	rq := redirect.Query()
	rq.Set("code", iamCode)
	rq.Set("state", f.State)
	redirect.RawQuery = rq.Encode()
	http.Redirect(w, r, redirect.String(), http.StatusFound)
}

func (b *IAM) token(w http.ResponseWriter, r *http.Request, rt *tenantRuntime) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		oauthError(w, http.StatusMethodNotAllowed, "invalid_request", "POST required")
		return
	}
	if err := r.ParseForm(); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", "bad form")
		return
	}
	switch r.Form.Get("grant_type") {
	case "authorization_code":
		b.tokenCode(w, r, rt)
	case "client_credentials":
		b.tokenClientCredentials(w, r, rt)
	case "refresh_token":
		b.tokenRefresh(w, r, rt)
	default:
		oauthError(w, http.StatusBadRequest, "unsupported_grant_type", "unsupported grant_type")
	}
}

func (b *IAM) tokenCode(w http.ResponseWriter, r *http.Request, rt *tenantRuntime) {
	clientID, ok := rt.clientAuthOK(r)
	if !ok {
		w.Header().Set("WWW-Authenticate", `Basic realm="token"`)
		oauthError(w, http.StatusUnauthorized, "invalid_client", "client authentication failed")
		return
	}
	code := r.Form.Get("code")
	redirectURI := r.Form.Get("redirect_uri")
	verifier := r.Form.Get("code_verifier")

	c, err := b.store.TakeCode(r.Context(), rt.cfg.ID, code)
	if err != nil {
		oauthError(w, http.StatusBadGateway, "server_error", "code store unavailable")
		return
	}
	if c == nil || b.now().After(c.Expires) {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "unknown or expired code")
		return
	}
	if clientID != c.ClientID {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "client mismatch")
		return
	}
	if redirectURI != c.RedirectURI {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "redirect_uri mismatch")
		return
	}
	if c.CodeChallenge != "" {
		sum := sha256.Sum256([]byte(verifier))
		got := base64.RawURLEncoding.EncodeToString(sum[:])
		if got != c.CodeChallenge {
			oauthError(w, http.StatusBadRequest, "invalid_grant", "PKCE verification failed")
			return
		}
	}
	revoked, err := b.sessionRevoked(r.Context(), rt, c.SID, c.Subject, c.IssuedAt)
	if err != nil {
		oauthError(w, http.StatusBadGateway, "server_error", "revocation store unavailable")
		return
	}
	if revoked {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "session revoked")
		return
	}
	b.writeTokens(r.Context(), w, rt, c.Subject, c.Username, c.Email, c.Roles,
		c.Scopes, c.Claims, c.SID, c.Scope, rt.defaultAudience(), c.Nonce,
		c.ClientID, true, true)
}

func (b *IAM) tokenClientCredentials(w http.ResponseWriter, r *http.Request, rt *tenantRuntime) {
	clientID, ok := rt.clientAuthOK(r)
	if !ok || rt.cfg.ClientSecret == "" {
		w.Header().Set("WWW-Authenticate", `Basic realm="token"`)
		oauthError(w, http.StatusUnauthorized, "invalid_client", "client authentication failed")
		return
	}
	aud := r.Form.Get("audience")
	if aud == "" {
		aud = rt.defaultAudience()
	}
	if !rt.audienceAllowed(aud) {
		oauthError(w, http.StatusBadRequest, "invalid_target", "unknown audience")
		return
	}
	scope := r.Form.Get("scope")
	if scope == "" {
		scope = "mcp-tools"
	}
	b.writeTokens(r.Context(), w, rt, clientID, clientID, "", rt.cfg.DefaultRoles,
		nil, nil, "", scope, aud, "", clientID, false, false)
}

func (b *IAM) tokenRefresh(w http.ResponseWriter, r *http.Request, rt *tenantRuntime) {
	raw := r.Form.Get("refresh_token")
	g, err := b.store.TakeRefresh(r.Context(), rt.cfg.ID, raw)
	if err != nil {
		oauthError(w, http.StatusBadGateway, "server_error", "refresh store unavailable")
		return
	}
	if g == nil || b.now().After(g.Expires) {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "unknown or expired refresh token")
		return
	}
	revoked, err := b.sessionRevoked(r.Context(), rt, g.SID, g.Subject, g.IssuedAt)
	if err != nil {
		oauthError(w, http.StatusBadGateway, "server_error", "revocation store unavailable")
		return
	}
	if revoked {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "session revoked")
		return
	}
	b.writeTokens(r.Context(), w, rt, g.Subject, g.Username, g.Email, g.Roles,
		g.Scopes, g.Claims, g.SID, g.Scope, g.Audience, "", g.ClientID, false, true)
}

func (b *IAM) writeTokens(
	ctx context.Context, w http.ResponseWriter, rt *tenantRuntime,
	sub, username, email string, roles, scopes []string,
	extraClaims map[string]any, sid, scope, aud, nonce, clientID string,
	withID, withRefresh bool,
) {
	now := b.now()
	scope = mergeScopes(scope, scopes)
	access := map[string]any{
		"iss": b.issuer(rt), "sub": sub, "aud": aud,
		"exp": now.Add(rt.cfg.accessTTL()).Unix(),
		"iat": now.Unix(), "jti": b.randomHex(16),
		"tenant": rt.cfg.ID, "roles": roles, "scope": scope,
		"sid": sid, "email": email, "preferred_username": username,
	}
	mergeExtraClaims(access, extraClaims)
	accessToken, err := rt.activeKey().sign(access)
	if err != nil {
		oauthError(w, http.StatusInternalServerError, "server_error", "signing failed")
		return
	}
	resp := map[string]any{
		"access_token": accessToken,
		"token_type":   "Bearer",
		"expires_in":   int(rt.cfg.accessTTL().Seconds()),
	}
	if withID {
		id := map[string]any{
			"iss": b.issuer(rt), "sub": sub, "aud": clientID,
			"exp": now.Add(rt.cfg.idTTL()).Unix(),
			"iat": now.Unix(), "nonce": nonce,
			"tenant": rt.cfg.ID, "roles": roles, "scope": scope, "sid": sid,
			"email": email, "preferred_username": username,
		}
		mergeExtraClaims(id, extraClaims)
		raw, err := rt.activeKey().sign(id)
		if err != nil {
			oauthError(w, http.StatusInternalServerError, "server_error", "signing failed")
			return
		}
		resp["id_token"] = raw
	}
	if withRefresh {
		refreshToken := b.randomHex(32)
		if err := b.store.PutRefresh(ctx, rt.cfg.ID, refreshToken, &refreshGrant{
			Tenant: rt.cfg.ID, ClientID: clientID,
			Subject: sub, Username: username, Email: email,
			Roles: roles, Scopes: scopes, Claims: extraClaims,
			SID: sid, Scope: scope, Audience: aud,
			IssuedAt: now,
			Expires:  now.Add(time.Duration(rt.cfg.RefreshTokenTTL) * time.Second),
		}, time.Duration(rt.cfg.RefreshTokenTTL)*time.Second); err != nil {
			oauthError(w, http.StatusBadGateway, "server_error", "refresh store unavailable")
			return
		}
		resp["refresh_token"] = refreshToken
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (b *IAM) logout(w http.ResponseWriter, r *http.Request, rt *tenantRuntime) {
	// Read the upstream session BEFORE revokeLogoutSession deletes the
	// IAM session: it carries the upstream id_token_hint and
	// end_session_endpoint.
	browserID := ""
	if c, err := r.Cookie(b.cfg.SessionCookieName); err == nil {
		browserID = c.Value
	}
	var upstream *upstreamSession
	if browserID != "" {
		upstream, _ = b.store.GetUpstream(r.Context(), rt.cfg.ID, browserID)
		_ = b.store.DeleteUpstream(r.Context(), rt.cfg.ID, browserID)
	}

	log.Printf("iam: logout tenant=%s browser=%t upstream=%t end_session=%t",
		rt.cfg.ID, browserID != "", upstream != nil,
		upstream != nil && upstream.EndSession != "")

	if err := b.revokeLogoutSession(
		r.Context(), w, rt, r,
	); err != nil {
		oauthError(w, http.StatusBadGateway, "server_error", "logout revocation failed")
		return
	}

	redirect := r.URL.Query().Get("post_logout_redirect_uri")
	if redirect != "" {
		// Only registered post-logout targets are allowed. Entries
		// ending in "/*" accept any path under that origin (the Gate
		// One guard sends its current URL, including the bare origin).
		if !redirectAllowed(rt.cfg.PostLogoutRedirectURIs, redirect) &&
			!containsString(rt.cfg.RedirectURIs, redirect) {
			oauthError(w, http.StatusBadRequest, "invalid_request", "post_logout_redirect_uri is not registered")
			return
		}
	}

	// RP-initiated logout: close the upstream IdP session too (Auth0,
	// Keycloak, Microsoft…). Google does not advertise an
	// end_session_endpoint; it falls back to the IAM redirect.
	if upstream != nil && upstream.EndSession != "" {
		if u, err := url.Parse(upstream.EndSession); err == nil {
			q := u.Query()
			if upstream.IDToken != "" {
				q.Set("id_token_hint", upstream.IDToken)
			}
			if upstream.ClientID != "" {
				q.Set("client_id", upstream.ClientID)
			}
			if redirect != "" {
				// ONE IAM-owned landing is registered at the
				// upstream (not every app URL): the app target rides
				// in a short-lived, host-only cookie and is validated
				// again by /logout/done.
				http.SetCookie(w, &http.Cookie{
					Name: "iam_logout_to",
					Value: base64.RawURLEncoding.EncodeToString(
						[]byte(redirect)),
					Path:     "/t/" + rt.cfg.ID + "/logout/done",
					MaxAge:   300,
					HttpOnly: true,
					Secure:   strings.HasPrefix(b.cfg.PublicURL, "https://"),
					SameSite: http.SameSiteLaxMode,
				})
				q.Set("post_logout_redirect_uri",
					b.issuer(rt)+"/logout/done")
			}
			u.RawQuery = q.Encode()
			http.Redirect(w, r, u.String(), http.StatusFound)
			return
		}
	}

	if redirect == "" {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	http.Redirect(w, r, redirect, http.StatusFound)
}

// logoutDone is the single post-logout landing registered at every
// upstream IdP. It returns to the application carried by the
// short-lived cookie, after validating it against the client's
// registered post-logout targets (no open redirect).
func (b *IAM) logoutDone(
	w http.ResponseWriter, r *http.Request, rt *tenantRuntime,
) {
	target := ""
	if c, err := r.Cookie("iam_logout_to"); err == nil {
		if raw, err := base64.RawURLEncoding.DecodeString(c.Value); err == nil {
			target = string(raw)
		}
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "iam_logout_to",
		Value:    "",
		Path:     "/t/" + rt.cfg.ID + "/logout/done",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   strings.HasPrefix(b.cfg.PublicURL, "https://"),
		SameSite: http.SameSiteLaxMode,
	})

	ok := target != "" &&
		(redirectAllowed(rt.cfg.PostLogoutRedirectURIs, target) ||
			containsString(rt.cfg.RedirectURIs, target))
	log.Printf("iam: logout/done tenant=%s target_ok=%t", rt.cfg.ID, ok)
	if ok {
		http.Redirect(w, r, target, http.StatusFound)
		return
	}
	if len(rt.cfg.AppOrigins) > 0 {
		http.Redirect(w, r, rt.cfg.AppOrigins[0], http.StatusFound)
		return
	}
	writeAccountPage(w, http.StatusOK, "Signed out",
		"You are signed out. You can close this page.")
}

func (rt *tenantRuntime) defaultAudience() string {
	if len(rt.cfg.Audiences) > 0 {
		return rt.cfg.Audiences[0]
	}
	return rt.cfg.ID
}

func (rt *tenantRuntime) audienceAllowed(aud string) bool {
	if len(rt.cfg.Audiences) == 0 {
		return aud == rt.cfg.ID
	}
	return containsString(rt.cfg.Audiences, aud)
}

func (rt *tenantRuntime) domainAllowed(email string, claims map[string]any) bool {
	if len(rt.cfg.AllowedDomains) == 0 {
		return true
	}
	hd, _ := claims["hd"].(string)
	for _, d := range rt.cfg.AllowedDomains {
		if strings.EqualFold(hd, d) {
			return true
		}
		if strings.HasSuffix(strings.ToLower(email), "@"+strings.ToLower(d)) {
			return true
		}
	}
	return false
}

func (b *IAM) randomHex(n int) string {
	buf := make([]byte, n)
	if _, err := io.ReadFull(b.rand, buf); err != nil {
		// crypto/rand should never fail; fall back to time-based
		// entropy rather than returning a predictable empty string.
		now := b.now().UnixNano()
		for i := range buf {
			buf[i] = byte(now >> (i % 8 * 8))
		}
	}
	return hex.EncodeToString(buf)
}

func oauthError(w http.ResponseWriter, status int, code, desc string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error": code, "error_description": desc,
	})
}

func (rt *tenantRuntime) clientAuthOK(r *http.Request) (string, bool) {
	id, secret, basic := r.BasicAuth()
	if !basic {
		id = r.Form.Get("client_id")
		secret = r.Form.Get("client_secret")
	}
	if id != rt.cfg.ClientID {
		return id, false
	}
	if rt.cfg.ClientSecret == "" {
		return id, true
	}
	if subtle.ConstantTimeCompare(
		[]byte(secret), []byte(rt.cfg.ClientSecret)) != 1 {
		return id, false
	}
	return id, true
}

// redirectAllowed matches exact entries and "/*" suffix patterns.
func redirectAllowed(list []string, raw string) bool {
	for _, allowed := range list {
		if allowed == raw {
			return true
		}
		if strings.HasSuffix(allowed, "/*") &&
			strings.HasPrefix(raw, strings.TrimSuffix(allowed, "*")) {
			return true
		}
	}
	return false
}

func containsString(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

func scopeHas(scope, want string) bool {
	for _, s := range strings.Fields(scope) {
		if s == want {
			return true
		}
	}
	return false
}

func claimStrings(v any) []string {
	switch t := v.(type) {
	case []any:
		out := make([]string, 0, len(t))
		for _, x := range t {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case []string:
		return t
	case string:
		if t == "" {
			return nil
		}
		return strings.Fields(t)
	default:
		return nil
	}
}

// upsertFederatedUser resolves the single external identity link
// (issuer, subject). The user record is an IAM-side authorization
// profile; it never contains an upstream credential. The IdP remains
// the only source of authentication for this user.
func (b *IAM) upsertFederatedUser(
	ctx context.Context, rt *tenantRuntime,
	issuer, subject, email, name string, claims map[string]any,
) (*User, error) {
	verified := true
	if v, ok := claims["email_verified"].(bool); ok {
		verified = v
	}
	u, err := b.accounts.GetUserByIdentity(ctx, rt.cfg.ID, issuer, subject)
	switch {
	case err == nil:
		if u.Kind != "" && u.Kind != "federated" {
			return nil, fmt.Errorf("iam: identity collision with a non-federated user")
		}
		u.Kind = "federated"
		u.Email = email
		u.Name = name
		u.EmailVerified = verified
		if err := b.accounts.PutUser(ctx, u); err != nil {
			return nil, err
		}
		return u, nil
	case errors.Is(err, errAccountNotFound):
		u = &User{
			ID:            b.randomHex(16),
			Tenant:        rt.cfg.ID,
			Kind:          "federated",
			Email:         email,
			Name:          name,
			EmailVerified: verified,
			Issuer:        issuer,
			Subject:       subject,
			CreatedAt:     b.now(),
		}
		if err := b.accounts.PutUser(ctx, u); err != nil {
			return nil, err
		}
		log.Printf("iam: provisioned federated user tenant=%s issuer=%s sub=%s",
			rt.cfg.ID, issuer, subject)
		return u, nil
	default:
		return nil, err
	}
}
