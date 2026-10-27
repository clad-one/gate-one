package authn

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const (
	oidcSessionCookie = "gate_one_session"
	oidcTxCookie      = "gate_one_oidc_tx"
	oidcTxTTL         = 5 * time.Minute
	oidcSessionTTL    = time.Hour
)

// OIDCConfig configures the native OpenID Connect Relying Party.
// auth-bridge is NOT required: Gate One talks to the IdP directly
// (Keycloak, Entra, Google, Authentik, Okta, Auth0, Zitadel…).
type OIDCConfig struct {
	Issuer       string
	ClientID     string
	ClientSecret string // empty = public client (PKCE only)
	LoginBaseURL string // public origin of the login host
	CookieDomain string
	AllowedHosts []string
	Scopes       []string
	RedirectURL  string // default LoginBaseURL + /auth/callback
	// RoleClaims are dot paths into the ID token claims whose values
	// become roles. Default: realm_access.roles,
	// resource_access.<clientID>.roles, groups.
	RoleClaims []string
	// ScopesClaim defaults to "scope"; "scp" is always also read.
	ScopesClaim string
	// MCPAudience, when set, must appear in the access token's aud.
	// "auto" uses the endpoint's protected-resource identifier.
	MCPAudience string
	SessionTTL  time.Duration

	// LegacyTokenCookies mirrors auth-bridge's access_token /
	// refresh_token / id_token cookies on cookieDomain. Migration
	// bridge: auth-bridge's token-broker routes (/connections,
	// /connect, /oauth) can resolve the same session while both
	// services share the login host. No effect on the native session.
	LegacyTokenCookies bool

	// BackchannelForwardURL (migration): after a valid logout_token is
	// applied locally, POST the same token to this auth-bridge
	// /backchannel-logout endpoint, so its persistent sid list stays in
	// sync for /auth (forwardAuth) and /connections. Best effort: a
	// forwarding failure never fails the IdP's backchannel request.
	BackchannelForwardURL string

	// Store persists back-channel logout revocations. Default: an
	// in-memory store (tests/dev). Production passes bbolt.
	Store RevocationStore
	// SessionKey is the cookie signing key. Empty = use the store's
	// persisted key when available, else generate one.
	SessionKey []byte
	// StoreID is the store generation (invalidates cookies when the
	// backing file is lost/recreated).
	StoreID string
	// BackchannelLogout: nil = auto (enable when the IdP advertises
	// backchannel_logout_supported), true/false = explicit override.
	BackchannelLogout *bool
	// RevocationTTL: how long a revocation entry is kept. Default
	// 24h, never shorter than the session TTL.
	RevocationTTL time.Duration

	// test seams
	Now        func() time.Time
	Rand       io.Reader
	HTTPClient *http.Client
}

// OIDC is the native Relying Party. It implements Provider and
// LoginHandler.
type OIDC struct {
	provider       *oidc.Provider
	verifier       *oidc.IDTokenVerifier
	logoutVerifier *oidc.IDTokenVerifier
	mcpVerifier    *oidc.IDTokenVerifier
	oauth2         *oauth2.Config
	issuer         string

	loginBase    *url.URL
	cookieDomain string
	secure       bool
	origins      *originPolicy

	roleClaims         []string
	scopesClaim        string
	mcpAudience        string
	endSession         string
	backchannel        bool
	revocationTTL      time.Duration
	store              RevocationStore
	legacyCookies      bool
	backchannelForward string

	session *sessionCodec
	tx      *txCodec
	now     func() time.Time

	doneTmpl *template.Template
}

// NewOIDC discovers the issuer and builds the provider. Discovery is
// fail-fast: a typo in the issuer refuses startup instead of failing
// on the first login.
func NewOIDC(ctx context.Context, cfg OIDCConfig) (*OIDC, error) {
	issuer := strings.TrimSpace(cfg.Issuer)
	if issuer == "" {
		return nil, fmt.Errorf("authProvider.type oidc: issuer is required")
	}
	clientID := strings.TrimSpace(cfg.ClientID)
	if clientID == "" {
		return nil, fmt.Errorf(
			"authProvider.type oidc: clientId is required")
	}

	raw := strings.TrimRight(strings.TrimSpace(cfg.LoginBaseURL), "/")
	if raw == "" {
		return nil, fmt.Errorf(
			"authProvider.type oidc: loginBaseUrl is required " +
				"(e.g. https://login.example.com)")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf(
			"authProvider.loginBaseUrl %q: invalid URL", cfg.LoginBaseURL)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf(
			"authProvider.loginBaseUrl %q: scheme must be http or https",
			cfg.LoginBaseURL)
	}
	if u.RawQuery != "" || u.Fragment != "" ||
		(u.Path != "" && u.Path != "/") {
		return nil, fmt.Errorf(
			"authProvider.loginBaseUrl %q: origin only (no path/query)",
			cfg.LoginBaseURL)
	}
	domain := strings.Trim(
		strings.ToLower(strings.TrimSpace(cfg.CookieDomain)), ".")
	if domain == "" {
		return nil, fmt.Errorf(
			"authProvider.type oidc: cookieDomain is required")
	}

	if cfg.HTTPClient != nil {
		ctx = oidc.ClientContext(ctx, cfg.HTTPClient)
	}
	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf(
			"authProvider.type oidc: cannot discover issuer %s: %w\n"+
				"hint: check that the IdP is reachable and the issuer URL "+
				"is exact (no trailing slash mismatch)", issuer, err)
	}

	redirect := strings.TrimSpace(cfg.RedirectURL)
	if redirect == "" {
		redirect = raw + "/auth/callback"
	}
	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{"openid", "profile", "email"}
	}
	hasOpenID := false
	for _, s := range scopes {
		if s == "openid" {
			hasOpenID = true
			break
		}
	}
	if !hasOpenID {
		scopes = append([]string{"openid"}, scopes...)
	}
	oauth2Cfg := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: cfg.ClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  redirect,
		Scopes:       scopes,
	}

	var discovery struct {
		EndSessionEndpoint                string `json:"end_session_endpoint"`
		BackchannelLogoutSupported        bool   `json:"backchannel_logout_supported"`
		BackchannelLogoutSessionSupported bool   `json:"backchannel_logout_session_supported"`
	}
	_ = provider.Claims(&discovery)

	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	rnd := cfg.Rand
	if rnd == nil {
		rnd = rand.Reader
	}
	ttl := cfg.SessionTTL
	if ttl <= 0 {
		ttl = oidcSessionTTL
	}

	store := cfg.Store
	if store == nil {
		store = NewMemoryStore()
		log.Printf(
			"OIDC: no revocation store configured — using memory " +
				"(single instance, revocations lost on restart)")
	}
	sessionKey := append([]byte(nil), cfg.SessionKey...)
	if len(sessionKey) == 0 {
		if ks, ok := store.(SessionKeyStore); ok {
			sessionKey = ks.SessionKey()
		}
	}
	if len(sessionKey) == 0 {
		sessionKey = make([]byte, 32)
		if _, err := io.ReadFull(rnd, sessionKey); err != nil {
			return nil, fmt.Errorf(
				"authProvider.type oidc: session key: %w", err)
		}
	}
	storeID := cfg.StoreID
	if storeID == "" {
		if ks, ok := store.(SessionKeyStore); ok {
			storeID = ks.StoreID()
		}
	}

	backchannel := discovery.BackchannelLogoutSupported
	if cfg.BackchannelLogout != nil {
		backchannel = *cfg.BackchannelLogout
	}
	if backchannel && !discovery.BackchannelLogoutSupported &&
		cfg.BackchannelLogout != nil && *cfg.BackchannelLogout {
		log.Printf(
			"OIDC: backchannelLogout forced, but the IdP discovery does " +
				"not advertise backchannel_logout_supported")
	}
	if backchannel && !discovery.BackchannelLogoutSessionSupported {
		log.Printf(
			"OIDC: backchannel logout enabled without session-id support: " +
				"revocation falls back to sub (all user sessions)")
	}
	revocationTTL := cfg.RevocationTTL
	if revocationTTL <= 0 {
		revocationTTL = 24 * time.Hour
	}
	if revocationTTL < ttl {
		revocationTTL = ttl
	}

	txSecret := make([]byte, 32)
	if _, err := io.ReadFull(rnd, txSecret); err != nil {
		return nil, fmt.Errorf("authProvider.type oidc: state key: %w", err)
	}

	roleClaims := cfg.RoleClaims
	if len(roleClaims) == 0 {
		roleClaims = []string{
			"realm_access.roles",
			"resource_access." + clientID + ".roles",
			"groups",
		}
	}
	scopesClaim := cfg.ScopesClaim
	if scopesClaim == "" {
		scopesClaim = "scope"
	}

	o := &OIDC{
		provider: provider,
		issuer:   issuer,
		verifier: provider.Verifier(&oidc.Config{
			ClientID: clientID,
		}),
		// MCP access tokens are not ID tokens: verify signature,
		// issuer and expiry, but not the client-ID audience (the
		// scope is the gate; MCPAudience can add a strict check).
		mcpVerifier: provider.Verifier(&oidc.Config{
			ClientID:          clientID,
			SkipClientIDCheck: true,
		}),
		oauth2:       oauth2Cfg,
		loginBase:    u,
		cookieDomain: domain,
		secure:       u.Scheme == "https",
		origins: newOriginPolicy(
			domain, append([]string{u.Host}, cfg.AllowedHosts...)),
		roleClaims:    roleClaims,
		scopesClaim:   scopesClaim,
		mcpAudience:   strings.TrimSpace(cfg.MCPAudience),
		endSession:    discovery.EndSessionEndpoint,
		backchannel:   backchannel,
		revocationTTL: revocationTTL,
		store:         store,
		legacyCookies: cfg.LegacyTokenCookies,
		backchannelForward: strings.TrimSpace(
			cfg.BackchannelForwardURL),
		session: newSessionCodec(
			oidcSessionCookie, domain, u.Scheme == "https",
			sessionKey, ttl, now, storeID),
		tx: &txCodec{
			secret: txSecret,
			secure: u.Scheme == "https",
			now:    now,
		},
		now:      now,
		doneTmpl: template.Must(template.New("done").Parse(devPopupDoneHTML)),
	}
	return o, nil
}

func (o *OIDC) Name() string      { return "oidc" }
func (o *OIDC) Issuer() string    { return o.issuer }
func (o *OIDC) LoginHost() string { return o.loginBase.Hostname() }
func (o *OIDC) LoginURL() string {
	return strings.TrimRight(o.loginBase.String(), "/") + "/login"
}

// Health re-runs discovery: a down IdP is an outage, not an auth
// failure.
func (o *OIDC) Health(ctx context.Context) error {
	_, err := oidc.NewProvider(ctx, o.issuer)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrProviderUnavailable, err)
	}
	return nil
}

// Verify reads the signed session cookie and enforces RP-side
// revocation (back-channel logout, RP logout) BEFORE the identity is
// returned. The proxy also calls CheckRevoked on cache hits.
func (o *OIDC) Verify(
	ctx context.Context,
	r *http.Request,
) (*Result, error) {
	id, _, ok := o.session.read(r)
	if !ok {
		return nil, ErrUnauthenticated
	}
	revoked, err := o.CheckRevoked(ctx, id)
	if err != nil {
		return nil, err
	}
	if revoked {
		return nil, ErrUnauthenticated
	}
	return &Result{Identity: id}, nil
}

// CheckRevoked implements Provider.
func (o *OIDC) CheckRevoked(
	ctx context.Context,
	id Identity,
) (bool, error) {
	if o.store == nil {
		return false, nil
	}
	revoked, err := o.store.IsRevoked(
		ctx, o.issuer, id.SessionID, id.UserID)
	if err != nil {
		return false, fmt.Errorf("%w: %v", ErrProviderUnavailable, err)
	}
	return revoked, nil
}

// VerifyMCP validates the Bearer access token locally (JWKS) and
// enforces the scope. No auth-bridge hop.
func (o *OIDC) VerifyMCP(
	ctx context.Context,
	r *http.Request,
	scope, resource string,
) (*Result, error) {
	raw := bearerToken(r)
	if raw == "" {
		return nil, ErrUnauthenticated
	}
	// Bound the JWKS fetch: a wedged IdP must not freeze MCP auth.
	vctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	tok, err := o.mcpVerifier.Verify(vctx, raw)
	if err != nil {
		return nil, ErrUnauthenticated
	}
	var claims map[string]any
	if err := tok.Claims(&claims); err != nil {
		return nil, ErrUnauthenticated
	}
	if o.mcpAudience != "" {
		// "auto" = the endpoint's own protected-resource identifier.
		want := o.mcpAudience
		if want == "auto" {
			want = resource
		}
		if want == "" || !audienceContains(tok.Audience, want) {
			return nil, ErrUnauthenticated
		}
	}
	scopes := scopesFromClaims(claims, o.scopesClaim)
	if scope != "" && !contains(scopes, scope) {
		return nil, ErrInsufficientScope
	}
	id := o.identityFromClaims(claims, scopes)
	revoked, err := o.CheckRevoked(ctx, id)
	if err != nil {
		return nil, err
	}
	if revoked {
		return nil, ErrUnauthenticated
	}
	return &Result{Identity: id}, nil
}

// ServeLogin implements LoginHandler: /login, /auth/callback,
// /logout, /auth/popup-done, /health.
func (o *OIDC) ServeLogin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	switch r.URL.Path {
	case "/health":
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"status":"ok","provider":"oidc"}`)
	case "/login":
		o.handleLogin(w, r)
	case "/auth/callback":
		o.handleCallback(w, r)
	case "/logout":
		o.handleLogout(w, r)
	case "/backchannel-logout":
		o.handleBackchannelLogout(w, r)
	case "/auth/popup-done":
		o.renderPopupDone(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (o *OIDC) handleLogin(w http.ResponseWriter, r *http.Request) {
	returnTo := o.origins.safeReturnTo(r.URL.Query().Get("returnTo"))
	state := randomHex(32)
	nonce := randomHex(32)
	verifier := oauth2.GenerateVerifier()

	o.tx.set(w, oidcTx{
		State:    state,
		Nonce:    nonce,
		Verifier: verifier,
		ReturnTo: returnTo,
		Expires:  o.now().Add(oidcTxTTL).Unix(),
	})

	authURL := o.oauth2.AuthCodeURL(
		state,
		oidc.Nonce(nonce),
		oauth2.S256ChallengeOption(verifier),
	)
	http.Redirect(w, r, authURL, http.StatusFound)
}

func (o *OIDC) handleCallback(w http.ResponseWriter, r *http.Request) {
	tx, ok := o.tx.read(r)
	if !ok {
		http.Error(w, "login state expired — restart the login", http.StatusBadRequest)
		return
	}
	o.tx.clear(w)

	if e := r.URL.Query().Get("error"); e != "" {
		desc := r.URL.Query().Get("error_description")
		log.Printf("OIDC callback error: %s (%s)", e, desc)
		http.Error(w, "authentication refused: "+e, http.StatusUnauthorized)
		return
	}
	state := r.URL.Query().Get("state")
	if subtle.ConstantTimeCompare(
		[]byte(tx.State), []byte(state)) != 1 {
		http.Error(w, "invalid login state", http.StatusBadRequest)
		return
	}
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "missing authorization code", http.StatusBadRequest)
		return
	}

	exctx, exCancel := context.WithTimeout(
		r.Context(), 15*time.Second)
	defer exCancel()
	token, err := o.oauth2.Exchange(
		exctx, code, oauth2.VerifierOption(tx.Verifier))
	if err != nil {
		log.Printf("OIDC token exchange failed: %v", err)
		http.Error(w, "authentication failed", http.StatusBadGateway)
		return
	}
	rawID, ok := token.Extra("id_token").(string)
	if !ok || rawID == "" {
		log.Printf("OIDC token exchange returned no id_token")
		http.Error(w, "authentication failed", http.StatusBadGateway)
		return
	}
	vctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	idToken, err := o.verifier.Verify(vctx, rawID)
	if err != nil {
		log.Printf("OIDC id_token verification failed: %v", err)
		http.Error(w, "authentication failed", http.StatusUnauthorized)
		return
	}
	if subtle.ConstantTimeCompare(
		[]byte(idToken.Nonce), []byte(tx.Nonce)) != 1 {
		log.Printf("OIDC nonce mismatch")
		http.Error(w, "authentication failed", http.StatusUnauthorized)
		return
	}

	var claims map[string]any
	if err := idToken.Claims(&claims); err != nil {
		log.Printf("OIDC claims: %v", err)
		http.Error(w, "authentication failed", http.StatusUnauthorized)
		return
	}
	id := o.identityFromClaims(
		claims, scopesFromClaims(claims, o.scopesClaim))
	// The RP session lifetime is our own (SessionTTL, default 12h),
	// independent of the ID token's short exp: otherwise a 5-minute
	// Keycloak ID token would force a full re-login every 5 minutes.
	// Silent refresh/backchannel revocation is a later lot; a shorter
	// sessionTtlSeconds is the conservative option today.
	o.session.set(w, id, rawID, time.Time{})
	o.setLegacyCookies(w, token)

	log.Printf(
		"OIDC login user=%q issuer=%s",
		id.Username, o.issuer)
	http.Redirect(w, r, tx.ReturnTo, http.StatusFound)
}

func (o *OIDC) handleLogout(w http.ResponseWriter, r *http.Request) {
	id, idToken, ok := o.session.read(r)
	o.session.clear(w)
	o.clearLegacyCookies(w)
	// A copied cookie must not survive an RP-initiated logout: revoke
	// the session id locally (never all sessions of the user).
	if ok && o.store != nil && id.SessionID != "" {
		_ = o.store.Revoke(
			r.Context(), o.issuer, id.SessionID, "",
			o.now().Add(o.revocationTTL))
	}

	returnTo := o.origins.safeReturnTo(
		r.URL.Query().Get("returnTo"))
	if returnTo == "/" {
		returnTo = strings.TrimRight(o.loginBase.String(), "/") + "/"
	}
	if o.endSession != "" && idToken != "" {
		u, err := url.Parse(o.endSession)
		if err == nil {
			q := u.Query()
			q.Set("client_id", o.oauth2.ClientID)
			q.Set("post_logout_redirect_uri", returnTo)
			q.Set("id_token_hint", idToken)
			u.RawQuery = q.Encode()
			http.Redirect(w, r, u.String(), http.StatusFound)
			return
		}
	}
	http.Redirect(w, r, returnTo, http.StatusFound)
}

// setLegacyCookies mirrors the auth-bridge token cookies on the shared
// domain. Migration bridge only (LegacyTokenCookies): auth-bridge's
// token-broker proxy routes (/connections, /connect, /oauth) keep
// resolving the same session while both services share the login host.
// The native session cookie remains the source of truth for Gate One.
func (o *OIDC) setLegacyCookies(w http.ResponseWriter, token *oauth2.Token) {
	if !o.legacyCookies {
		return
	}
	maxAge := 3600
	if !token.Expiry.IsZero() {
		if d := token.Expiry.Sub(o.now()); d > 0 {
			maxAge = int(d.Seconds())
		}
	}
	o.legacyCookie(w, "access_token", token.AccessToken, maxAge)
	if token.RefreshToken != "" {
		o.legacyCookie(w, "refresh_token", token.RefreshToken, 30*24*3600)
	}
	if raw, ok := token.Extra("id_token").(string); ok && raw != "" {
		o.legacyCookie(w, "id_token", raw, 3600)
	}
}

func (o *OIDC) legacyCookie(
	w http.ResponseWriter,
	name, value string,
	maxAge int,
) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		Domain:   o.cookieDomain,
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   o.secure,
		SameSite: http.SameSiteLaxMode,
	})
}

func (o *OIDC) clearLegacyCookies(w http.ResponseWriter) {
	if !o.legacyCookies {
		return
	}
	for _, name := range []string{
		"access_token", "refresh_token", "id_token",
	} {
		http.SetCookie(w, &http.Cookie{
			Name:     name,
			Value:    "",
			Path:     "/",
			Domain:   o.cookieDomain,
			MaxAge:   -1,
			HttpOnly: true,
			Secure:   o.secure,
			SameSite: http.SameSiteLaxMode,
		})
	}
}

// handleBackchannelLogout receives the OIDC Back-Channel Logout 1.0
// token from the IdP. The IdP owns the SSO session; this handler
// makes the RP enforce the revocation on its own cookie.
func (o *OIDC) handleBackchannelLogout(
	w http.ResponseWriter,
	r *http.Request,
) {
	if !o.backchannel {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	raw := r.PostFormValue("logout_token")
	if raw == "" {
		http.Error(w, "missing logout_token", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	lt, err := o.verifier.VerifyLogout(ctx, raw)
	if err != nil {
		log.Printf("BACKCHANNEL LOGOUT rejected: %v", err)
		http.Error(w, "invalid logout_token", http.StatusBadRequest)
		return
	}
	now := o.now()
	if lt.IssuedAt.IsZero() ||
		now.Sub(lt.IssuedAt) > 5*time.Minute ||
		lt.IssuedAt.After(now.Add(time.Minute)) {
		log.Printf("BACKCHANNEL LOGOUT rejected: stale iat")
		http.Error(w, "invalid logout_token", http.StatusBadRequest)
		return
	}

	jtiExpiry := now.Add(10 * time.Minute)
	if !lt.Expiry.IsZero() && lt.Expiry.After(jtiExpiry) {
		jtiExpiry = lt.Expiry
	}
	fresh, err := o.store.UseJTI(
		ctx, o.issuer, lt.TokenID, jtiExpiry)
	if err != nil {
		log.Printf("BACKCHANNEL LOGOUT store error: %v", err)
		http.Error(w, "state store unavailable",
			http.StatusServiceUnavailable)
		return
	}
	if !fresh {
		http.Error(w, "replayed logout_token", http.StatusBadRequest)
		return
	}

	expires := now.Add(o.revocationTTL)
	if !lt.Expiry.IsZero() && lt.Expiry.After(expires) {
		expires = lt.Expiry
	}
	sid, sub := lt.SessionID, ""
	if sid == "" {
		// No session id: revoke every session of this user.
		sub = lt.Subject
	}
	if err := o.store.Revoke(
		ctx, o.issuer, sid, sub, expires); err != nil {
		log.Printf("BACKCHANNEL LOGOUT store error: %v", err)
		http.Error(w, "state store unavailable",
			http.StatusServiceUnavailable)
		return
	}
	// Migration: keep auth-bridge's persistent sid list in sync for
	// its /auth (forwardAuth) and /connections pages. Best effort.
	o.forwardBackchannelLogout(ctx, raw)
	log.Printf(
		"BACKCHANNEL LOGOUT issuer=%s sid=%q sub=%q",
		o.issuer, sid, sub)
	w.WriteHeader(http.StatusOK)
}

func (o *OIDC) forwardBackchannelLogout(
	ctx context.Context,
	raw string,
) {
	if o.backchannelForward == "" {
		return
	}
	fctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	form := url.Values{"logout_token": {raw}}.Encode()
	req, err := http.NewRequestWithContext(
		fctx, http.MethodPost, o.backchannelForward,
		strings.NewReader(form))
	if err != nil {
		log.Printf("BACKCHANNEL FORWARD: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Printf("BACKCHANNEL FORWARD %s: %v",
			o.backchannelForward, err)
		return
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		log.Printf("BACKCHANNEL FORWARD %s: status %d",
			o.backchannelForward, resp.StatusCode)
	}
}

func (o *OIDC) renderPopupDone(w http.ResponseWriter, r *http.Request) {
	origin := r.URL.Query().Get("origin")
	if !o.origins.allowedOrigin(origin) {
		origin = ""
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = o.doneTmpl.Execute(w, map[string]any{"Origin": origin})
}

func (o *OIDC) identityFromClaims(
	claims map[string]any,
	scopes []string,
) Identity {
	userID := stringClaim(claims, "sub")
	username := stringClaim(claims, "preferred_username")
	if username == "" {
		username = stringClaim(claims, "email")
	}
	if username == "" {
		username = userID
	}
	return Identity{
		UserID:    userID,
		SessionID: stringClaim(claims, "sid"),
		Username:  username,
		Email:     stringClaim(claims, "email"),
		Roles:     rolesFromClaims(claims, o.roleClaims),
		Scopes:    scopes,
		Claims:    claims,
	}
}

// --- tx cookie -----------------------------------------------------

type oidcTx struct {
	State    string `json:"state"`
	Nonce    string `json:"nonce"`
	Verifier string `json:"verifier"`
	ReturnTo string `json:"returnTo"`
	Expires  int64  `json:"exp"`
}

type txCodec struct {
	secret []byte
	secure bool
	now    func() time.Time
}

func (c *txCodec) set(w http.ResponseWriter, tx oidcTx) {
	raw, _ := json.Marshal(tx)
	body := base64.RawURLEncoding.EncodeToString(raw)
	http.SetCookie(w, &http.Cookie{
		Name:     oidcTxCookie,
		Value:    body + "." + c.sign(body),
		Path:     "/auth/callback",
		MaxAge:   int(oidcTxTTL.Seconds()),
		HttpOnly: true,
		Secure:   c.secure,
		SameSite: http.SameSiteLaxMode,
	})
}

func (c *txCodec) read(r *http.Request) (oidcTx, bool) {
	cookie, err := r.Cookie(oidcTxCookie)
	if err != nil {
		return oidcTx{}, false
	}
	body, sig, ok := strings.Cut(cookie.Value, ".")
	if !ok || body == "" || sig == "" {
		return oidcTx{}, false
	}
	if !hmac.Equal([]byte(sig), []byte(c.sign(body))) {
		return oidcTx{}, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		return oidcTx{}, false
	}
	var tx oidcTx
	if err := json.Unmarshal(raw, &tx); err != nil {
		return oidcTx{}, false
	}
	if tx.Expires == 0 || c.now().Unix() >= tx.Expires {
		return oidcTx{}, false
	}
	return tx, true
}

func (c *txCodec) clear(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     oidcTxCookie,
		Value:    "",
		Path:     "/auth/callback",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   c.secure,
		SameSite: http.SameSiteLaxMode,
	})
}

func (c *txCodec) sign(body string) string {
	mac := hmac.New(sha256.New, c.secret)
	mac.Write([]byte(body))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// --- helpers -------------------------------------------------------

func randomHex(n int) string {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		// crypto/rand failure is fatal for a login flow; the
		// caller will see an invalid state and refuse.
		return ""
	}
	return hex.EncodeToString(buf)
}

func bearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
}

func audienceContains(auds []string, want string) bool {
	for _, a := range auds {
		if a == want {
			return true
		}
	}
	return false
}

// scopesFromClaims reads the granted scopes from "scope" (Keycloak,
// space-separated) or "scp" (Entra; string or array).
func scopesFromClaims(claims map[string]any, key string) []string {
	if v, ok := claims[key]; ok {
		switch t := v.(type) {
		case string:
			return strings.Fields(t)
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
		}
	}
	if v, ok := claims["scp"]; ok {
		switch t := v.(type) {
		case string:
			return strings.Fields(t)
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
		}
	}
	return nil
}

// rolesFromClaims reads roles from dot paths. A path resolving to an
// array yields its strings; a string yields one role (comma-split is
// accepted for providers exposing "role1,role2").
func rolesFromClaims(claims map[string]any, paths []string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			return
		}
		seen[s] = true
		out = append(out, s)
	}
	for _, path := range paths {
		switch v := lookupPath(claims, path).(type) {
		case []any:
			for _, x := range v {
				if s, ok := x.(string); ok {
					add(s)
				}
			}
		case []string:
			for _, s := range v {
				add(s)
			}
		case string:
			for _, s := range strings.Split(v, ",") {
				add(s)
			}
		}
	}
	return out
}

func lookupPath(m map[string]any, path string) any {
	var cur any = m
	for _, part := range strings.Split(path, ".") {
		mm, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = mm[part]
	}
	return cur
}
