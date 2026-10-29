// Package fakegoogle implements a minimal Google-compatible OIDC
// provider for tests and the local Compose stack. It is not a
// production identity provider: it auto-consents, keeps codes in
// memory, and exposes control hooks for failure/rotation scenarios.
package fakegoogle

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// User is one fake Google account.
type User struct {
	Sub               string   `json:"sub"`
	Email             string   `json:"email"`
	EmailVerified     bool     `json:"emailVerified"`
	HostedDomain      string   `json:"hostedDomain,omitempty"`
	PreferredUsername string   `json:"preferredUsername,omitempty"`
	Name              string   `json:"name,omitempty"`
	Groups            []string `json:"groups,omitempty"`
}

// Config configures the fake provider. Durations are in seconds so
// the same struct can be loaded from JSON by cmd/fake-google.
type Config struct {
	ClientID         string `json:"clientId,omitempty"`
	Issuer           string `json:"issuer,omitempty"`
	Users            []User `json:"users,omitempty"`
	CodeTTLSeconds   int    `json:"codeTtlSeconds,omitempty"`
	AccessTTLSeconds int    `json:"accessTtlSeconds,omitempty"`
}

type signingKey struct {
	kid  string
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

type authCode struct {
	nonce       string
	redirectURI string
	user        int
	expires     time.Time
}

type accessToken struct {
	user    int
	expires time.Time
}

// Server is an http.Handler serving discovery, JWKS, authorize, token
// and userinfo.
type Server struct {
	mu sync.Mutex

	clientID    string
	users       []User
	defaultUser int
	codeTTL     time.Duration
	accessTTL   time.Duration
	now         func() time.Time
	issuer      string

	keys   []*signingKey
	nextID int
	codes  map[string]authCode
	access map[string]accessToken

	failDiscovery bool
	failJWKS      bool
	failToken     bool
	invalidJWKS   bool
	slow          time.Duration
}

// New builds a fake provider. The issuer can be fixed here (Compose)
// or set later with SetIssuer (httptest).
func New(cfg Config) (*Server, error) {
	if cfg.ClientID == "" {
		cfg.ClientID = "google-client"
	}
	if len(cfg.Users) == 0 {
		cfg.Users = []User{{
			Sub:               "google-sub-1",
			Email:             "alice@acme.test",
			EmailVerified:     true,
			HostedDomain:      "acme.test",
			PreferredUsername: "alice",
			Name:              "Alice",
		}}
	}
	codeTTL := time.Duration(cfg.CodeTTLSeconds) * time.Second
	if codeTTL <= 0 {
		codeTTL = 5 * time.Minute
	}
	accessTTL := time.Duration(cfg.AccessTTLSeconds) * time.Second
	if accessTTL <= 0 {
		accessTTL = time.Hour
	}
	s := &Server{
		clientID:  cfg.ClientID,
		users:     append([]User(nil), cfg.Users...),
		codeTTL:   codeTTL,
		accessTTL: accessTTL,
		now:       time.Now,
		issuer:    strings.TrimRight(strings.TrimSpace(cfg.Issuer), "/"),
		codes:     map[string]authCode{},
		access:    map[string]accessToken{},
		nextID:    1,
	}
	if err := s.addKeyLocked(); err != nil {
		return nil, err
	}
	return s, nil
}

// SetIssuer fixes the issuer advertised by discovery and used in ID
// tokens. Used by httptest after the server URL is known.
func (s *Server) SetIssuer(raw string) {
	s.mu.Lock()
	s.issuer = strings.TrimRight(strings.TrimSpace(raw), "/")
	s.mu.Unlock()
}

// SetNow injects a clock (tests).
func (s *Server) SetNow(now func() time.Time) {
	s.mu.Lock()
	if now != nil {
		s.now = now
	}
	s.mu.Unlock()
}

// SetDefaultUser selects the user returned when no login_hint matches.
func (s *Server) SetDefaultUser(email string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, u := range s.users {
		if strings.EqualFold(u.Email, email) ||
			strings.EqualFold(u.PreferredUsername, email) {
			s.defaultUser = i
			return nil
		}
	}
	return fmt.Errorf("fakegoogle: unknown user %q", email)
}

// SetFailDiscovery makes discovery return 503.
func (s *Server) SetFailDiscovery(v bool) {
	s.mu.Lock()
	s.failDiscovery = v
	s.mu.Unlock()
}

// SetFailJWKS makes the JWKS endpoint return 503.
func (s *Server) SetFailJWKS(v bool) {
	s.mu.Lock()
	s.failJWKS = v
	s.mu.Unlock()
}

// SetFailToken makes the token endpoint return 500.
func (s *Server) SetFailToken(v bool) {
	s.mu.Lock()
	s.failToken = v
	s.mu.Unlock()
}

// SetInvalidJWKS serves a malformed key set (200 with bad key data).
func (s *Server) SetInvalidJWKS(v bool) {
	s.mu.Lock()
	s.invalidJWKS = v
	s.mu.Unlock()
}

// SetSlow delays every request by d.
func (s *Server) SetSlow(d time.Duration) {
	s.mu.Lock()
	s.slow = d
	s.mu.Unlock()
}

// RotateKey generates a new active key and keeps the previous ones in
// JWKS for the overlap window.
func (s *Server) RotateKey() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.addKeyLocked()
}

// RetireOldKeys keeps only the active key in JWKS.
func (s *Server) RetireOldKeys() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.keys) > 1 {
		s.keys = s.keys[len(s.keys)-1:]
	}
}

// Status is the control-plane view of the fake.
type Status struct {
	Issuer        string   `json:"issuer"`
	ClientID      string   `json:"clientId"`
	DefaultUser   string   `json:"defaultUser"`
	Users         []string `json:"users"`
	Kids          []string `json:"kids"`
	FailDiscovery bool     `json:"failDiscovery"`
	FailJWKS      bool     `json:"failJWKS"`
	FailToken     bool     `json:"failToken"`
	InvalidJWKS   bool     `json:"invalidJWKS"`
	SlowMillis    int64    `json:"slowMillis"`
}

// Status returns the current control-plane state.
func (s *Server) Status() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := Status{
		Issuer:        s.issuer,
		ClientID:      s.clientID,
		FailDiscovery: s.failDiscovery,
		FailJWKS:      s.failJWKS,
		FailToken:     s.failToken,
		InvalidJWKS:   s.invalidJWKS,
		SlowMillis:    s.slow.Milliseconds(),
	}
	if s.defaultUser >= 0 && s.defaultUser < len(s.users) {
		st.DefaultUser = s.users[s.defaultUser].Email
	}
	for _, u := range s.users {
		st.Users = append(st.Users, u.Email)
	}
	for _, k := range s.keys {
		st.Kids = append(st.Kids, k.kid)
	}
	return st
}

func (s *Server) addKeyLocked() error {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	s.keys = append(s.keys, &signingKey{
		kid:  fmt.Sprintf("google-%d", s.nextID),
		priv: priv,
		pub:  pub,
	})
	s.nextID++
	return nil
}

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	slow := s.slow
	s.mu.Unlock()
	if slow > 0 {
		time.Sleep(slow)
	}

	switch r.URL.Path {
	case "/.well-known/openid-configuration":
		s.handleDiscovery(w, r)
	case "/jwks", "/jwks.json":
		s.handleJWKS(w, r)
	case "/authorize":
		s.handleAuthorize(w, r)
	case "/token":
		s.handleToken(w, r)
	case "/userinfo":
		s.handleUserinfo(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) baseURL(r *http.Request) string {
	s.mu.Lock()
	iss := s.issuer
	s.mu.Unlock()
	if iss != "" {
		return iss
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}

func (s *Server) handleDiscovery(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	fail := s.failDiscovery
	s.mu.Unlock()
	if fail {
		writeJSON(w, http.StatusServiceUnavailable,
			map[string]any{"error": "temporarily_unavailable"})
		return
	}
	base := s.baseURL(r)
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                base,
		"authorization_endpoint":                base + "/authorize",
		"token_endpoint":                        base + "/token",
		"userinfo_endpoint":                     base + "/userinfo",
		"jwks_uri":                              base + "/jwks",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"EdDSA"},
		"scopes_supported":                      []string{"openid", "profile", "email"},
		"claims_supported": []string{
			"sub", "email", "email_verified", "hd", "name",
			"preferred_username", "groups",
		},
		"token_endpoint_auth_methods_supported": []string{
			"client_secret_post", "client_secret_basic", "none",
		},
		"code_challenge_methods_supported": []string{"S256"},
	})
}

func (s *Server) handleJWKS(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	fail, invalid := s.failJWKS, s.invalidJWKS
	keys := append([]*signingKey(nil), s.keys...)
	s.mu.Unlock()
	if fail {
		writeJSON(w, http.StatusServiceUnavailable,
			map[string]any{"error": "temporarily_unavailable"})
		return
	}
	if invalid {
		writeJSON(w, http.StatusOK, map[string]any{
			"keys": []any{map[string]any{
				"kty": "OKP", "crv": "Ed25519", "x": "not-a-valid-key",
			}},
		})
		return
	}
	set := jose.JSONWebKeySet{}
	for _, k := range keys {
		set.Keys = append(set.Keys, jose.JSONWebKey{
			Key: k.pub, KeyID: k.kid, Algorithm: "EdDSA", Use: "sig",
		})
	}
	writeJSON(w, http.StatusOK, set)
}

func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	redirect := strings.TrimSpace(q.Get("redirect_uri"))
	if redirect == "" {
		http.Error(w, "missing redirect_uri", http.StatusBadRequest)
		return
	}
	u, err := url.Parse(redirect)
	if err != nil || !u.IsAbs() {
		http.Error(w, "invalid redirect_uri", http.StatusBadRequest)
		return
	}

	code := randomHex(16)
	s.mu.Lock()
	idx := s.userIndexLocked(q.Get("login_hint"))
	s.codes[code] = authCode{
		nonce:       q.Get("nonce"),
		redirectURI: redirect,
		user:        idx,
		expires:     s.now().Add(s.codeTTL),
	}
	s.mu.Unlock()

	rq := u.Query()
	rq.Set("code", code)
	if state := q.Get("state"); state != "" {
		rq.Set("state", state)
	}
	u.RawQuery = rq.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	fail := s.failToken
	s.mu.Unlock()
	if fail {
		writeJSON(w, http.StatusInternalServerError,
			map[string]any{"error": "temporarily_unavailable"})
		return
	}
	if err := r.ParseForm(); err != nil {
		writeJSON(w, http.StatusBadRequest,
			map[string]any{"error": "invalid_request"})
		return
	}
	code := r.Form.Get("code")
	s.mu.Lock()
	st, ok := s.codes[code]
	delete(s.codes, code)
	now := s.now()
	s.mu.Unlock()
	if !ok || now.After(st.expires) {
		writeJSON(w, http.StatusBadRequest,
			map[string]any{"error": "invalid_grant"})
		return
	}
	if redirect := r.Form.Get("redirect_uri"); redirect != "" &&
		redirect != st.redirectURI {
		writeJSON(w, http.StatusBadRequest,
			map[string]any{"error": "invalid_grant"})
		return
	}

	s.mu.Lock()
	if st.user < 0 || st.user >= len(s.users) {
		s.mu.Unlock()
		writeJSON(w, http.StatusBadRequest,
			map[string]any{"error": "invalid_grant"})
		return
	}
	user := s.users[st.user]
	issuer := s.issuer
	s.mu.Unlock()
	if issuer == "" {
		issuer = s.baseURL(r)
	}

	idToken, err := s.signIDToken(user, st.nonce, issuer, now)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError,
			map[string]any{"error": "server_error"})
		return
	}
	access := randomHex(24)
	s.mu.Lock()
	s.access[access] = accessToken{
		user:    st.user,
		expires: now.Add(s.accessTTL),
	}
	ttl := int(s.accessTTL.Seconds())
	s.mu.Unlock()

	writeJSON(w, http.StatusOK, map[string]any{
		"access_token":  access,
		"token_type":    "Bearer",
		"expires_in":    ttl,
		"id_token":      idToken,
		"refresh_token": randomHex(24),
		"scope":         "openid profile email",
	})
}

func (s *Server) handleUserinfo(w http.ResponseWriter, r *http.Request) {
	raw := strings.TrimSpace(r.Header.Get("Authorization"))
	if !strings.HasPrefix(strings.ToLower(raw), "bearer ") {
		writeJSON(w, http.StatusUnauthorized,
			map[string]any{"error": "invalid_token"})
		return
	}
	token := strings.TrimSpace(raw[len("bearer "):])
	s.mu.Lock()
	at, ok := s.access[token]
	now := s.now()
	var user User
	if ok && now.Before(at.expires) && at.user >= 0 && at.user < len(s.users) {
		user = s.users[at.user]
	} else {
		ok = false
	}
	s.mu.Unlock()
	if !ok {
		writeJSON(w, http.StatusUnauthorized,
			map[string]any{"error": "invalid_token"})
		return
	}
	claims := map[string]any{
		"sub":            user.Sub,
		"email":          user.Email,
		"email_verified": user.EmailVerified,
	}
	if user.HostedDomain != "" {
		claims["hd"] = user.HostedDomain
	}
	if user.PreferredUsername != "" {
		claims["preferred_username"] = user.PreferredUsername
	}
	if user.Name != "" {
		claims["name"] = user.Name
	}
	if len(user.Groups) > 0 {
		claims["groups"] = user.Groups
	}
	writeJSON(w, http.StatusOK, claims)
}

func (s *Server) signIDToken(
	user User, nonce, issuer string, now time.Time,
) (string, error) {
	s.mu.Lock()
	if len(s.keys) == 0 {
		s.mu.Unlock()
		return "", fmt.Errorf("fakegoogle: no signing key")
	}
	key := s.keys[len(s.keys)-1]
	clientID := s.clientID
	ttl := s.accessTTL
	s.mu.Unlock()

	claims := map[string]any{
		"iss":            issuer,
		"aud":            clientID,
		"sub":            user.Sub,
		"exp":            now.Add(ttl).Unix(),
		"iat":            now.Unix(),
		"nonce":          nonce,
		"email":          user.Email,
		"email_verified": user.EmailVerified,
	}
	if user.HostedDomain != "" {
		claims["hd"] = user.HostedDomain
	}
	if user.PreferredUsername != "" {
		claims["preferred_username"] = user.PreferredUsername
	}
	if user.Name != "" {
		claims["name"] = user.Name
	}
	if len(user.Groups) > 0 {
		claims["groups"] = user.Groups
	}
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.EdDSA, Key: key.priv},
		(&jose.SignerOptions{}).WithHeader("kid", key.kid))
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	obj, err := signer.Sign(payload)
	if err != nil {
		return "", err
	}
	return obj.CompactSerialize()
}

func (s *Server) userIndexLocked(loginHint string) int {
	hint := strings.TrimSpace(loginHint)
	if hint != "" {
		for i, u := range s.users {
			if strings.EqualFold(u.Email, hint) ||
				strings.EqualFold(u.PreferredUsername, hint) {
				return i
			}
		}
	}
	if s.defaultUser >= 0 && s.defaultUser < len(s.users) {
		return s.defaultUser
	}
	return 0
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}
