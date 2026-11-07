package broker

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const verifyTokenTTL = 24 * time.Hour

type registerRequest struct {
	Email       string `json:"email"`
	Password    string `json:"password"`
	Name        string `json:"name,omitempty"`
	ContinueURL string `json:"continueUrl,omitempty"`
}

func (b *Broker) registerAuthorized(
	rt *tenantRuntime, r *http.Request,
) bool {
	if rt.cfg.RegistrationSecret == "" {
		return false
	}
	const prefix = "Bearer "
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, prefix) {
		return false
	}
	got := strings.TrimSpace(strings.TrimPrefix(h, prefix))
	return subtle.ConstantTimeCompare(
		[]byte(got), []byte(rt.cfg.RegistrationSecret)) == 1
}

// register creates a local account and sends the verification email.
// It is server-to-server only (Bearer registration secret): the app
// backend calls it after its own signup form.
func (b *Broker) register(
	w http.ResponseWriter, r *http.Request, rt *tenantRuntime,
) {
	if !rt.cfg.LocalAccounts {
		oauthError(w, http.StatusNotFound, "not_found", "local accounts disabled")
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		oauthError(w, http.StatusMethodNotAllowed, "invalid_request", "POST required")
		return
	}
	if !b.registerAuthorized(rt, r) {
		oauthError(w, http.StatusUnauthorized, "unauthorized", "registration secret required")
		return
	}
	if b.mailer == nil {
		oauthError(w, http.StatusServiceUnavailable, "server_error", "email delivery is not configured")
		return
	}

	var req registerRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
	if err := dec.Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		oauthError(w, http.StatusBadRequest, "invalid_request", "invalid JSON body")
		return
	}
	email, err := normalizeEmail(req.Email)
	if err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", "invalid email address")
		return
	}
	if len(req.Password) < 10 {
		oauthError(w, http.StatusBadRequest, "invalid_request", "password must be at least 10 characters")
		return
	}
	if !rt.continueURLAllowed(req.ContinueURL) {
		oauthError(w, http.StatusBadRequest, "invalid_request", "continueUrl is not an allowed app origin")
		return
	}

	existing, err := b.accounts.GetUserByEmail(r.Context(), rt.cfg.ID, email)
	switch {
	case err == nil && existing.EmailVerified:
		oauthError(w, http.StatusConflict, "invalid_request", "email already registered")
		return
	case err != nil && !errors.Is(err, errAccountNotFound):
		oauthError(w, http.StatusBadGateway, "server_error", "account store unavailable")
		return
	}

	user := existing
	if user == nil {
		hash, err := hashPassword(req.Password)
		if err != nil {
			oauthError(w, http.StatusInternalServerError, "server_error", "password hashing failed")
			return
		}
		roles := append([]string(nil), rt.cfg.DefaultRoles...)
		for _, admin := range rt.cfg.AdminEmails {
			if strings.EqualFold(admin, email) {
				roles = append(roles, "admin")
			}
		}
		user = &localUser{
			ID:           b.randomHex(16),
			Tenant:       rt.cfg.ID,
			Kind:         "local",
			Email:        email,
			Name:         strings.TrimSpace(req.Name),
			PasswordHash: hash,
			Roles:        roles,
			CreatedAt:    b.now(),
		}
		if err := b.accounts.PutUser(r.Context(), user); err != nil {
			oauthError(w, http.StatusBadGateway, "server_error", "account store unavailable")
			return
		}
	}

	raw, tokenHash, err := newVerifyToken()
	if err != nil {
		oauthError(w, http.StatusInternalServerError, "server_error", "token generation failed")
		return
	}
	vt := &verifyToken{
		Email:       email,
		ContinueURL: strings.TrimSpace(req.ContinueURL),
		Expires:     b.now().Add(verifyTokenTTL),
	}
	if err := b.accounts.PutVerifyToken(
		r.Context(), rt.cfg.ID, tokenHash, vt, verifyTokenTTL,
	); err != nil {
		oauthError(w, http.StatusBadGateway, "server_error", "account store unavailable")
		return
	}

	link := b.issuer(rt) + "/verify-email?token=" +
		url.QueryEscape(raw) + "&continueUrl=" +
		url.QueryEscape(vt.ContinueURL)
	if err := b.mailer.SendVerification(r.Context(), email, link); err != nil {
		log.Printf("broker: verification email to %s failed: %v", email, err)
		oauthError(w, http.StatusBadGateway, "server_error", "email delivery failed")
		return
	}

	log.Printf("broker: verification email sent tenant=%s user=%s",
		rt.cfg.ID, user.ID)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status": "verification_sent",
	})
}

// verifyEmail consumes the single-use token, marks the account
// verified, then returns to the application carried by the link.
func (b *Broker) verifyEmail(
	w http.ResponseWriter, r *http.Request, rt *tenantRuntime,
) {
	if !rt.cfg.LocalAccounts {
		http.NotFound(w, r)
		return
	}
	raw := strings.TrimSpace(r.URL.Query().Get("token"))
	if raw == "" {
		writeAccountPage(w, http.StatusBadRequest, "Invalid link",
			"This verification link is incomplete.")
		return
	}

	vt, err := b.accounts.TakeVerifyToken(
		r.Context(), rt.cfg.ID, verifyTokenHash(raw))
	if err != nil {
		writeAccountPage(w, http.StatusBadRequest, "Expired link",
			"This verification link is invalid, expired or already used.")
		return
	}

	user, err := b.accounts.GetUserByEmail(r.Context(), rt.cfg.ID, vt.Email)
	if err != nil {
		writeAccountPage(w, http.StatusBadRequest, "Account not found",
			"The account linked to this verification no longer exists.")
		return
	}
	if err := b.accounts.SetUserVerified(
		r.Context(), rt.cfg.ID, user.ID,
	); err != nil {
		writeAccountPage(w, http.StatusBadGateway, "Error",
			"Unable to complete the verification. Please try again later.")
		return
	}

	log.Printf("broker: email verified tenant=%s user=%s", rt.cfg.ID, user.ID)

	if vt.ContinueURL != "" && rt.continueURLAllowed(vt.ContinueURL) {
		target := vt.ContinueURL
		if u, err := url.Parse(target); err == nil {
			q := u.Query()
			q.Set("verified", "1")
			u.RawQuery = q.Encode()
			target = u.String()
		}
		http.Redirect(w, r, target, http.StatusFound)
		return
	}

	writeAccountPage(w, http.StatusOK, "Email verified",
		"Your email address is confirmed. You can close this page.")
}

// writeAccountPage is a minimal self-contained page for the account
// lifecycle (no external asset, values escaped).
func writeRestartPage(
	w http.ResponseWriter, rt *tenantRuntime, message string,
) {
	link := ""
	if rt != nil && len(rt.cfg.AppOrigins) > 0 {
		link = rt.cfg.AppOrigins[0]
	}
	writeAccountPageLink(w, http.StatusBadRequest,
		"Login session expired", message, link)
}

func writeAccountPage(
	w http.ResponseWriter, code int, title, message string,
) {
	writeAccountPageLink(w, code, title, message, "")
}

func writeAccountPageLink(
	w http.ResponseWriter, code int, title, message, link string,
) {
	var action string
	if link != "" {
		action = fmt.Sprintf(
			"<p><a class=\"btn\" href=\"%s\">Restart from the application</a></p>",
			html.EscapeString(link))
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_, _ = fmt.Fprintf(w, `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>%s</title>
<style>
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#f4f5f7;color:#1c1f26;font:16px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
main{max-width:34em;margin:2rem;padding:2rem 2.25rem;background:#fff;border-radius:12px;box-shadow:0 8px 30px rgba(0,0,0,.08)}
h1{margin:0 0 .6rem;font-size:1.4rem}p{margin:0;color:#444}
@media (prefers-color-scheme:dark){body{background:#16181d;color:#eef0f3}main{background:#20242e}p{color:#c7ccd6}}
</style>
</head>
<body><main><h1>%s</h1><p>%s</p>%s</main></body>
</html>`,
		html.EscapeString(title),
		html.EscapeString(title),
		html.EscapeString(message),
		action)
}
