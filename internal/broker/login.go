package broker

import (
	"crypto/subtle"
	"fmt"
	"html"
	"net/http"
	"strings"
	"time"
)

// login serves the local password login surface of the broker. It is
// only reachable through /authorize?idp=local, which stores a
// short-lived flow (client, redirect_uri, state, PKCE, CSRF).
func (b *Broker) login(
	w http.ResponseWriter, r *http.Request, rt *tenantRuntime,
) {
	switch r.Method {
	case http.MethodGet:
		b.loginPage(w, r, rt)
	case http.MethodPost:
		b.loginSubmit(w, r, rt)
	default:
		w.Header().Set("Allow", "GET, POST")
		oauthError(w, http.StatusMethodNotAllowed, "invalid_request",
			"GET or POST required")
	}
}

func (b *Broker) loginPage(
	w http.ResponseWriter, r *http.Request, rt *tenantRuntime,
) {
	flowID := strings.TrimSpace(r.URL.Query().Get("flow"))
	f, err := b.store.GetFlow(r.Context(), rt.cfg.ID, flowID)
	if err != nil {
		oauthError(w, http.StatusBadGateway, "server_error",
			"flow store unavailable")
		return
	}
	if f == nil || b.now().After(f.Expires) {
		writeAccountPage(w, http.StatusBadRequest, "Session expirée",
			"Recommencez la connexion depuis l'application.")
		return
	}
	writeLoginPage(w, http.StatusOK, b.issuer(rt)+"/login",
		f.CSRF, flowID, "")
}

func (b *Broker) loginSubmit(
	w http.ResponseWriter, r *http.Request, rt *tenantRuntime,
) {
	if err := r.ParseForm(); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", "bad form")
		return
	}
	flowID := strings.TrimSpace(r.Form.Get("flow"))
	f, err := b.store.TakeFlow(r.Context(), rt.cfg.ID, flowID)
	if err != nil {
		oauthError(w, http.StatusBadGateway, "server_error",
			"flow store unavailable")
		return
	}
	if f == nil || b.now().After(f.Expires) {
		writeAccountPage(w, http.StatusBadRequest, "Session expirée",
			"Recommencez la connexion depuis l'application.")
		return
	}

	action := b.issuer(rt) + "/login"
	csrfOK := subtle.ConstantTimeCompare(
		[]byte(r.Form.Get("csrf")), []byte(f.CSRF)) == 1
	if !csrfOK {
		_ = b.store.PutFlow(r.Context(), rt.cfg.ID, flowID, f, 10*time.Minute)
		writeLoginPage(w, http.StatusBadRequest, action,
			f.CSRF, flowID, "Session invalide. Réessayez.")
		return
	}

	email, err := normalizeEmail(r.Form.Get("email"))
	password := r.Form.Get("password")
	var user *localUser
	if err == nil {
		user, err = b.accounts.GetUserByEmail(r.Context(), rt.cfg.ID, email)
	}
	if err != nil || user == nil || !user.EmailVerified ||
		!verifyPassword(user.PasswordHash, password) {
		// Generic message: never reveal whether the account exists or
		// whether only the email is unverified.
		_ = b.store.PutFlow(r.Context(), rt.cfg.ID, flowID, f, 10*time.Minute)
		writeLoginPage(w, http.StatusUnauthorized, action,
			f.CSRF, flowID,
			"Identifiants invalides ou adresse e-mail non vérifiée.")
		return
	}

	username := strings.TrimSpace(user.Name)
	if username == "" {
		username = user.Email
	}
	b.finishLogin(w, r, rt, f, loginIdentity{
		Sub:      user.ID,
		Username: username,
		Email:    user.Email,
		Roles:    user.Roles,
	})
}

func writeLoginPage(
	w http.ResponseWriter, code int, action, csrf, flow, errMsg string,
) {
	var errHTML string
	if errMsg != "" {
		errHTML = fmt.Sprintf(`<p class="err">%s</p>`, html.EscapeString(errMsg))
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_, _ = fmt.Fprintf(w, `<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Connexion</title>
<style>
:root{color-scheme:light dark}
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#f4f5f7;color:#1c1f26;font:16px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
main{width:100%%;max-width:22em;margin:2rem;padding:2rem 2.25rem;background:#fff;border-radius:12px;box-shadow:0 8px 30px rgba(0,0,0,.08)}
h1{margin:0 0 1rem;font-size:1.3rem}
label{display:block;margin:.7rem 0 .25rem;font-size:.9rem;color:#444}
input{width:100%%;box-sizing:border-box;padding:.55rem .7rem;border:1px solid #c9ced8;border-radius:8px;font:inherit}
button{width:100%%;margin-top:1.2rem;padding:.65rem 1rem;border:0;border-radius:8px;background:#2563eb;color:#fff;font:inherit;font-weight:600;cursor:pointer}
button:hover{background:#1d4ed8}
p.err{margin:0 0 .5rem;padding:.5rem .7rem;border-radius:8px;background:#fdecec;color:#a11;font-size:.9rem}
@media (prefers-color-scheme:dark){body{background:#16181d;color:#eef0f3}main{background:#20242e}label{color:#c7ccd6}input{background:#161a21;border-color:#3a4150;color:#eef0f3}p.err{background:#3a1f22;color:#ffb4b4}}
</style>
</head>
<body>
<main>
<h1>Connexion</h1>
%s
<form method="post" action="%s">
<input type="hidden" name="flow" value="%s">
<input type="hidden" name="csrf" value="%s">
<label for="email">Adresse e-mail</label>
<input id="email" name="email" type="email" autocomplete="username" required>
<label for="password">Mot de passe</label>
<input id="password" name="password" type="password" autocomplete="current-password" required>
<button type="submit">Se connecter</button>
</form>
</main>
</body>
</html>`,
		errHTML,
		html.EscapeString(action),
		html.EscapeString(flow),
		html.EscapeString(csrf))
}
