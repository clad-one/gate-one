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
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// DevUser is one account of the embedded development IdP. Passwords
// are plaintext ON PURPOSE: this provider only runs on loopback and
// must never be used in production.
type DevUser struct {
	Username string
	Password string
	Roles    []string
	Scopes   []string
	Claims   map[string]any
	MCPToken string
}

// DevConfig configures the embedded development IdP.
type DevConfig struct {
	// LoginBaseURL is the public origin of the login host, e.g.
	// http://login.demo.localhost:3000 (no path/query).
	LoginBaseURL string
	// CookieDomain is the shared parent domain, e.g.
	// demo.localhost. The session cookie is set on it so every app
	// subdomain is signed in at once.
	CookieDomain string
	// AllowedHosts are the application hosts accepted as returnTo
	// targets (in addition to CookieDomain and its subdomains).
	AllowedHosts []string
	// Users: empty = alice/alice + bob/bob.
	Users []DevUser
	// SessionTTL defaults to 12h.
	SessionTTL time.Duration

	// test seams
	Now   func() time.Time
	Rand  io.Reader
	Clock func() time.Time
}

const (
	devSessionCookie = "gate_one_dev_session"
	devCSRFCookie    = "gate_one_dev_csrf"
	devSessionTTL    = 12 * time.Hour
	devMaxFailures   = 10
	devFailureWindow = 5 * time.Minute
)

// Dev is the embedded development identity provider. It implements
// Provider and LoginHandler.
type Dev struct {
	loginBase    *url.URL
	cookieDomain string
	secure       bool
	users        map[string]DevUser
	byToken      map[string]string // MCP token -> username
	allowed      map[string]bool
	secret       []byte
	ttl          time.Duration
	now          func() time.Time

	loginTmpl *template.Template
	doneTmpl  *template.Template

	mu       sync.Mutex
	failures map[string][]time.Time
}

// NewDev validates and builds the development provider.
func NewDev(cfg DevConfig) (*Dev, error) {
	raw := strings.TrimRight(strings.TrimSpace(cfg.LoginBaseURL), "/")
	if raw == "" {
		return nil, fmt.Errorf("authProvider.dev: loginBaseUrl is required")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf(
			"authProvider.dev.loginBaseUrl %q: invalid URL", cfg.LoginBaseURL)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf(
			"authProvider.dev.loginBaseUrl %q: scheme must be http or https",
			cfg.LoginBaseURL)
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf(
			"authProvider.dev.loginBaseUrl %q: query and fragment forbidden",
			cfg.LoginBaseURL)
	}
	if u.Path != "" && u.Path != "/" {
		return nil, fmt.Errorf(
			"authProvider.dev.loginBaseUrl %q: a path is not supported",
			cfg.LoginBaseURL)
	}
	domain := strings.TrimSpace(cfg.CookieDomain)
	if domain == "" {
		return nil, fmt.Errorf(
			"authProvider.dev.cookieDomain is required (e.g. demo.localhost)")
	}

	users := cfg.Users
	if len(users) == 0 {
		users = []DevUser{
			{
				Username: "alice", Password: "alice",
				Roles:  []string{"user"},
				Scopes: []string{"profile", "offline_access", "mcp-tools"},
			},
			{
				Username: "bob", Password: "bob",
				Roles:  []string{"user", "admin"},
				Scopes: []string{"profile", "offline_access", "mcp-tools", "mcp-admin"},
			},
		}
	}

	d := &Dev{
		loginBase:    u,
		cookieDomain: domain,
		secure:       u.Scheme == "https",
		users:        make(map[string]DevUser, len(users)),
		byToken:      make(map[string]string, len(users)),
		allowed:      map[string]bool{},
		ttl:          cfg.SessionTTL,
		now:          cfg.Now,
		failures:     map[string][]time.Time{},
		loginTmpl:    template.Must(template.New("login").Parse(devLoginHTML)),
		doneTmpl:     template.Must(template.New("done").Parse(devPopupDoneHTML)),
	}
	if d.ttl <= 0 {
		d.ttl = devSessionTTL
	}
	if d.now == nil {
		d.now = time.Now
	}

	rnd := cfg.Rand
	if rnd == nil {
		rnd = rand.Reader
	}
	d.secret = make([]byte, 32)
	if _, err := io.ReadFull(rnd, d.secret); err != nil {
		return nil, fmt.Errorf("authProvider.dev: session key: %w", err)
	}

	// Normalize the allowed hosts: the cookie domain (and its
	// subdomains) plus every configured application host.
	d.allowed[normalizeHost(domain)] = true
	d.allowed[normalizeHost(u.Host)] = true
	for _, h := range cfg.AllowedHosts {
		if h = normalizeHost(h); h != "" {
			d.allowed[h] = true
		}
	}

	for _, user := range users {
		user.Username = strings.TrimSpace(user.Username)
		if user.Username == "" {
			return nil, fmt.Errorf("authProvider.dev.users: empty username")
		}
		if _, dup := d.users[user.Username]; dup {
			return nil, fmt.Errorf(
				"authProvider.dev.users: duplicate username %q", user.Username)
		}
		if len(user.Roles) == 0 {
			user.Roles = []string{"user"}
		}
		if len(user.Scopes) == 0 {
			user.Scopes = []string{"profile", "offline_access", "mcp-tools"}
		}
		if user.Claims == nil {
			user.Claims = map[string]any{}
		}
		if _, ok := user.Claims["preferred_username"]; !ok {
			user.Claims["preferred_username"] = user.Username
		}
		if _, ok := user.Claims["email"]; !ok {
			user.Claims["email"] = user.Username + "@example.com"
		}
		if _, ok := user.Claims["email_verified"]; !ok {
			user.Claims["email_verified"] = true
		}
		if user.MCPToken == "" {
			user.MCPToken = "dev-" + user.Username
		}
		if _, dup := d.byToken[user.MCPToken]; dup {
			return nil, fmt.Errorf(
				"authProvider.dev.users: duplicate mcpToken")
		}
		d.users[user.Username] = user
		d.byToken[user.MCPToken] = user.Username
	}
	return d, nil
}

func (d *Dev) Name() string { return "dev" }

func (d *Dev) Issuer() string {
	return strings.TrimRight(d.loginBase.String(), "/") + "/dev"
}

func (d *Dev) LoginURL() string {
	return strings.TrimRight(d.loginBase.String(), "/") + "/login"
}

func (d *Dev) Health(context.Context) error { return nil }

// LoginHost implements LoginHandler.
func (d *Dev) LoginHost() string { return d.loginBase.Hostname() }

// Verify reads the signed session cookie. It also accepts a dev
// bearer ("dev-bob") so API routes are testable with curl.
func (d *Dev) Verify(
	_ context.Context,
	r *http.Request,
) (*Result, error) {
	if c, err := r.Cookie(devSessionCookie); err == nil {
		if id, ok := d.decodeSession(c.Value); ok {
			return &Result{Identity: id}, nil
		}
	}
	if id, ok := d.bearerIdentity(r); ok {
		return &Result{Identity: id}, nil
	}
	return nil, ErrUnauthenticated
}

// VerifyMCP accepts the user's dev token and enforces the scope.
func (d *Dev) VerifyMCP(
	_ context.Context,
	r *http.Request,
	scope, _ string,
) (*Result, error) {
	id, ok := d.bearerIdentity(r)
	if !ok {
		return nil, ErrUnauthenticated
	}
	if scope != "" && !contains(id.Scopes, scope) {
		return nil, ErrInsufficientScope
	}
	return &Result{Identity: id}, nil
}

func (d *Dev) bearerIdentity(r *http.Request) (Identity, bool) {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return Identity{}, false
	}
	token := strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
	if token == "" {
		return Identity{}, false
	}
	username, ok := d.byToken[token]
	if !ok {
		return Identity{}, false
	}
	return d.identity(d.users[username]), true
}

func (d *Dev) identity(u DevUser) Identity {
	return Identity{
		UserID:   u.Username,
		Username: u.Username,
		Email:    stringClaim(u.Claims, "email"),
		Roles:    append([]string(nil), u.Roles...),
		Scopes:   append([]string(nil), u.Scopes...),
		Claims:   cloneClaims(u.Claims),
	}
}

// sessionPayload is the signed cookie content.
type sessionPayload struct {
	User     string         `json:"u"`
	Email    string         `json:"e,omitempty"`
	Roles    []string       `json:"r,omitempty"`
	Scopes   []string       `json:"s,omitempty"`
	Claims   map[string]any `json:"c,omitempty"`
	Expires  int64          `json:"exp"`
	IssuedAt int64          `json:"iat,omitempty"`
}

func (d *Dev) encodeSession(id Identity) string {
	p := sessionPayload{
		User: id.Username, Email: id.Email,
		Roles: id.Roles, Scopes: id.Scopes, Claims: id.Claims,
		Expires: d.now().Add(d.ttl).Unix(), IssuedAt: d.now().Unix(),
	}
	raw, _ := json.Marshal(p)
	body := base64.RawURLEncoding.EncodeToString(raw)
	return body + "." + d.sign(body)
}

func (d *Dev) decodeSession(v string) (Identity, bool) {
	body, sig, ok := strings.Cut(v, ".")
	if !ok || body == "" || sig == "" {
		return Identity{}, false
	}
	if !hmac.Equal([]byte(sig), []byte(d.sign(body))) {
		return Identity{}, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		return Identity{}, false
	}
	var p sessionPayload
	if err := json.Unmarshal(raw, &p); err != nil {
		return Identity{}, false
	}
	if p.Expires == 0 || d.now().Unix() >= p.Expires {
		return Identity{}, false
	}
	return Identity{
		UserID: p.User, Username: p.User, Email: p.Email,
		Roles: p.Roles, Scopes: p.Scopes, Claims: p.Claims,
	}, true
}

func (d *Dev) sign(body string) string {
	mac := hmac.New(sha256.New, d.secret)
	mac.Write([]byte(body))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (d *Dev) setSession(w http.ResponseWriter, id Identity) {
	http.SetCookie(w, &http.Cookie{
		Name:     devSessionCookie,
		Value:    d.encodeSession(id),
		Path:     "/",
		Domain:   d.cookieDomain,
		MaxAge:   int(d.ttl.Seconds()),
		HttpOnly: true,
		Secure:   d.secure,
		SameSite: http.SameSiteLaxMode,
	})
}

func (d *Dev) clearSession(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     devSessionCookie,
		Value:    "",
		Path:     "/",
		Domain:   d.cookieDomain,
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   d.secure,
		SameSite: http.SameSiteLaxMode,
	})
}

// ServeLogin implements LoginHandler.
func (d *Dev) ServeLogin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	switch r.URL.Path {
	case "/health":
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"status":"ok","provider":"dev"}`)
	case "/login":
		if r.Method == http.MethodPost {
			d.handleLoginPost(w, r)
			return
		}
		d.renderLogin(w, r, "", http.StatusOK)
	case "/logout":
		d.clearSession(w)
		target := d.safeReturnTo(r.URL.Query().Get("returnTo"))
		http.Redirect(w, r, target, http.StatusFound)
	case "/auth/popup-done":
		d.renderPopupDone(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (d *Dev) renderLogin(
	w http.ResponseWriter,
	r *http.Request,
	errMsg string,
	status int,
) {
	returnTo := d.safeReturnTo(r.URL.Query().Get("returnTo"))
	csrf := d.newCSRF(w)
	data := map[string]any{
		"Error":    errMsg,
		"ReturnTo": returnTo,
		"CSRF":     csrf,
		"Users":    d.demoAccounts(),
		"Secure":   d.secure,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := d.loginTmpl.Execute(w, data); err != nil {
		log.Printf("dev auth: login template: %v", err)
	}
}

func (d *Dev) handleLoginPost(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if !d.checkCSRF(r) {
		d.renderLogin(w, r, "Session expirée, merci de réessayer.", http.StatusForbidden)
		return
	}
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	returnTo := d.safeReturnTo(r.FormValue("returnTo"))

	if d.tooManyFailures(username, r.RemoteAddr) {
		d.renderLogin(w, r, "Trop de tentatives, patientez quelques minutes.", http.StatusTooManyRequests)
		return
	}

	user, ok := d.users[username]
	if !ok || subtle.ConstantTimeCompare(
		[]byte(user.Password), []byte(password)) != 1 {
		d.recordFailure(username, r.RemoteAddr)
		d.renderLogin(w, r, "Identifiants invalides.", http.StatusUnauthorized)
		return
	}

	d.clearFailures(username, r.RemoteAddr)
	d.setSession(w, d.identity(user))
	http.Redirect(w, r, returnTo, http.StatusFound)
}

func (d *Dev) newCSRF(w http.ResponseWriter) string {
	buf := make([]byte, 32)
	_, _ = rand.Read(buf)
	token := hex.EncodeToString(buf)
	http.SetCookie(w, &http.Cookie{
		Name:     devCSRFCookie,
		Value:    token,
		Path:     "/",
		MaxAge:   300,
		HttpOnly: true,
		Secure:   d.secure,
		SameSite: http.SameSiteLaxMode,
	})
	return token
}

func (d *Dev) checkCSRF(r *http.Request) bool {
	c, err := r.Cookie(devCSRFCookie)
	if err != nil || c.Value == "" {
		return false
	}
	got := r.FormValue("csrf")
	return subtle.ConstantTimeCompare([]byte(c.Value), []byte(got)) == 1
}

func (d *Dev) renderPopupDone(w http.ResponseWriter, r *http.Request) {
	origin := r.URL.Query().Get("origin")
	if !d.allowedOrigin(origin) {
		origin = ""
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = d.doneTmpl.Execute(w, map[string]any{"Origin": origin})
}

func (d *Dev) safeReturnTo(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "/"
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "/"
	}
	if u.IsAbs() {
		if (u.Scheme == "http" || u.Scheme == "https") &&
			d.allowedHost(u.Host) {
			return u.String()
		}
		return "/"
	}
	if strings.HasPrefix(raw, "//") || !strings.HasPrefix(raw, "/") {
		return "/"
	}
	return raw
}

func (d *Dev) allowedOrigin(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() {
		return false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return false
	}
	return d.allowedHost(u.Host)
}

func (d *Dev) allowedHost(host string) bool {
	h := normalizeHost(host)
	if h == "" {
		return false
	}
	if d.allowed[h] {
		return true
	}
	// Any subdomain of the shared cookie domain.
	return strings.HasSuffix(h, "."+normalizeHost(d.cookieDomain))
}

func (d *Dev) demoAccounts() []string {
	out := make([]string, 0, len(d.users))
	for name := range d.users {
		out = append(out, name)
	}
	// deterministic order
	for i := 0; i < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			if out[j] < out[i] {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}

func (d *Dev) failureKey(username, remote string) string {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		host = remote
	}
	return username + "|" + host
}

func (d *Dev) tooManyFailures(username, remote string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	key := d.failureKey(username, remote)
	d.pruneFailures(key)
	return len(d.failures[key]) >= devMaxFailures
}

func (d *Dev) recordFailure(username, remote string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	key := d.failureKey(username, remote)
	d.pruneFailures(key)
	d.failures[key] = append(d.failures[key], d.now())
}

func (d *Dev) clearFailures(username, remote string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.failures, d.failureKey(username, remote))
}

func (d *Dev) pruneFailures(key string) {
	cutoff := d.now().Add(-devFailureWindow)
	kept := d.failures[key][:0]
	for _, ts := range d.failures[key] {
		if ts.After(cutoff) {
			kept = append(kept, ts)
		}
	}
	d.failures[key] = kept
}

func normalizeHost(h string) string {
	h = strings.TrimSpace(strings.ToLower(h))
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	return strings.Trim(h, "[]")
}

func contains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

func stringClaim(claims map[string]any, key string) string {
	if v, ok := claims[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func cloneClaims(in map[string]any) map[string]any {
	if in == nil {
		return nil
	}
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

const devLoginHTML = `<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Gate One — développement</title>
<style>
:root{color-scheme:light dark}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:grid;place-items:center;
font:15px/1.45 system-ui,-apple-system,Segoe UI,sans-serif;
background:#f4f5f7;color:#1c1f23}
.card{width:min(92vw,380px);background:#fff;border:1px solid #dfe3e8;
border-radius:14px;padding:26px;box-shadow:0 10px 30px rgba(0,0,0,.07)}
.badge{display:inline-block;font-size:11px;font-weight:700;letter-spacing:.08em;
text-transform:uppercase;color:#8a5a00;background:#fff1cc;
border-radius:999px;padding:3px 9px}
h1{font-size:20px;margin:14px 0 4px}
p.sub{margin:0 0 18px;color:#5c6470;font-size:13px}
label{display:block;font-size:12px;font-weight:600;margin:12px 0 5px}
input{width:100%;padding:10px 11px;border:1px solid #cfd5dc;border-radius:8px;
font:inherit;background:#fff;color:inherit}
input:focus{outline:2px solid #4a7c59;outline-offset:1px;border-color:#4a7c59}
button{width:100%;margin-top:18px;padding:11px;border:0;border-radius:8px;
background:#2f6b45;color:#fff;font:inherit;font-weight:650;cursor:pointer}
button:hover{background:#275a3a}
.err{margin:12px 0 0;padding:9px 11px;border-radius:8px;background:#fdecec;
color:#a11616;font-size:13px}
.accounts{margin-top:16px;padding-top:14px;border-top:1px solid #eceff2;
color:#6a7280;font-size:12px}
code{background:#f1f3f5;border-radius:4px;padding:1px 5px}
@media(prefers-color-scheme:dark){
body{background:#121417;color:#e8eaed}
.card{background:#1a1d21;border-color:#2c3138}
p.sub,.accounts{color:#9aa2ad}
input{background:#121417;border-color:#39404a}
code{background:#24282e}
}
</style>
</head>
<body>
<main class="card">
<span class="badge">Dev auth</span>
<h1>Connexion de développement</h1>
<p class="sub">IdP embarqué — accessible uniquement en local.</p>
{{if .Error}}<p class="err">{{.Error}}</p>{{end}}
<form method="post" action="/login" autocomplete="on">
<input type="hidden" name="csrf" value="{{.CSRF}}">
<input type="hidden" name="returnTo" value="{{.ReturnTo}}">
<label for="username">Utilisateur</label>
<input id="username" name="username" autocomplete="username" required autofocus>
<label for="password">Mot de passe</label>
<input id="password" name="password" type="password" autocomplete="current-password" required>
<button type="submit">Se connecter</button>
</form>
<p class="accounts">Comptes de démonstration :
{{range $i, $u := .Users}}{{if $i}}, {{end}}<code>{{$u}}</code>{{end}}
(mot de passe = nom d'utilisateur).</p>
</main>
</body>
</html>`

const devPopupDoneHTML = `<!doctype html>
<html lang="fr"><head><meta charset="utf-8"><title>Connecté</title></head>
<body style="font:15px system-ui;padding:24px">
<p>Connexion réussie. Cette fenêtre va se fermer.</p>
<script>
(function(){
  var origin = {{if .Origin}}"{{.Origin}}"{{else}}""{{end}};
  if (origin && window.opener) {
    try { window.opener.postMessage("cladone-auth:ok", origin); } catch (e) {}
    window.close();
  } else if (origin) {
    location.replace(origin);
  }
})();
</script>
</body></html>`
