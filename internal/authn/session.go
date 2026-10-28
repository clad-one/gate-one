package authn

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

// sessionCodec is the signed session cookie shared by the native
// providers (dev, OIDC). The payload is authenticated (HMAC-SHA256),
// not encrypted: it carries identity claims, never refresh tokens.
// The ID token is kept only for RP-initiated logout (id_token_hint);
// it is the user's own token and is already visible to them.
type sessionCodec struct {
	cookieName string
	domain     string
	secure     bool
	secret     []byte
	ttl        time.Duration
	now        func() time.Time
	// storeID invalidates cookies when the state file is lost and
	// recreated (no epoch on every restart).
	storeID string
}

func newSessionCodec(
	cookieName, domain string,
	secure bool,
	secret []byte,
	ttl time.Duration,
	now func() time.Time,
	storeID string,
) *sessionCodec {
	if now == nil {
		now = time.Now
	}
	if ttl <= 0 {
		ttl = 12 * time.Hour
	}
	return &sessionCodec{
		cookieName: cookieName,
		domain:     domain,
		secure:     secure,
		secret:     secret,
		ttl:        ttl,
		now:        now,
		storeID:    storeID,
	}
}

type sessionPayload struct {
	UserID    string         `json:"uid,omitempty"`
	User      string         `json:"u"`
	SessionID string         `json:"sid,omitempty"`
	Email     string         `json:"e,omitempty"`
	Roles     []string       `json:"r,omitempty"`
	Scopes    []string       `json:"s,omitempty"`
	Claims    map[string]any `json:"c,omitempty"`
	IDToken   string         `json:"idt,omitempty"`
	StoreID   string         `json:"st,omitempty"`
	Expires   int64          `json:"exp"`
	IssuedAt  int64          `json:"iat,omitempty"`
}

func (c *sessionCodec) encode(
	id Identity,
	idToken string,
	expires time.Time,
) string {
	now := c.now()
	exp := now.Add(c.ttl)
	if !expires.IsZero() && expires.Before(exp) {
		exp = expires
	}
	p := sessionPayload{
		UserID:    id.UserID,
		User:      id.Username,
		SessionID: id.SessionID,
		Email:     id.Email,
		Roles:     id.Roles,
		Scopes:    id.Scopes,
		Claims:    id.Claims,
		IDToken:   idToken,
		StoreID:   c.storeID,
		Expires:   exp.Unix(),
		IssuedAt:  now.Unix(),
	}
	raw, _ := json.Marshal(p)
	body := base64.RawURLEncoding.EncodeToString(raw)
	return body + "." + c.sign(body)
}

func (c *sessionCodec) decode(
	v string,
) (Identity, string, bool) {
	body, sig, ok := strings.Cut(v, ".")
	if !ok || body == "" || sig == "" {
		return Identity{}, "", false
	}
	if !hmac.Equal([]byte(sig), []byte(c.sign(body))) {
		return Identity{}, "", false
	}
	raw, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		return Identity{}, "", false
	}
	var p sessionPayload
	if err := json.Unmarshal(raw, &p); err != nil {
		return Identity{}, "", false
	}
	if p.Expires == 0 || c.now().Unix() >= p.Expires {
		return Identity{}, "", false
	}
	if c.storeID != "" && p.StoreID != c.storeID {
		// The state file was recreated: reject cookies signed with a
		// previous store identity (prevents revoked sessions from
		// being reactivated after a lost file).
		return Identity{}, "", false
	}
	userID := p.UserID
	if userID == "" {
		userID = p.User
	}
	return Identity{
		UserID:    userID,
		SessionID: p.SessionID,
		IssuedAt:  time.Unix(p.IssuedAt, 0),
		Username:  p.User,
		Email:     p.Email,
		Roles:     p.Roles,
		Scopes:    p.Scopes,
		Claims:    p.Claims,
	}, p.IDToken, true
}

func (c *sessionCodec) sign(body string) string {
	mac := hmac.New(sha256.New, c.secret)
	mac.Write([]byte(body))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (c *sessionCodec) set(
	w http.ResponseWriter,
	id Identity,
	idToken string,
	expires time.Time,
) {
	http.SetCookie(w, &http.Cookie{
		Name:     c.cookieName,
		Value:    c.encode(id, idToken, expires),
		Path:     "/",
		Domain:   c.domain,
		MaxAge:   int(c.ttl.Seconds()),
		HttpOnly: true,
		Secure:   c.secure,
		SameSite: http.SameSiteLaxMode,
	})
}

func (c *sessionCodec) clear(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     c.cookieName,
		Value:    "",
		Path:     "/",
		Domain:   c.domain,
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   c.secure,
		SameSite: http.SameSiteLaxMode,
	})
}

func (c *sessionCodec) read(
	r *http.Request,
) (Identity, string, bool) {
	cookie, err := r.Cookie(c.cookieName)
	if err != nil {
		return Identity{}, "", false
	}
	return c.decode(cookie.Value)
}
