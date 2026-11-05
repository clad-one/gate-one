package proxy

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"html"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync/atomic"
)

// landingActionKeys are the query parameters that identify an
// out-of-band action link (email verification, password reset,
// OIDC action token). When one is present on the login host root but
// no application return target is, the link is incomplete: a silent
// redirect to the default app would hide an adapter misconfiguration.
var landingActionKeys = []string{
	"mode", "oobCode", "key", "token", "ticket", "code", "state",
	"error", "error_description", "session_code", "execution",
}

// serveLoginLanding handles a bare visit to the login host root.
//
// It is the generic, IdP-blind landing point for links that were
// emitted by an upstream identity/email provider:
//
//   - returnTo / continueUrl present and allowed -> 302 to the app,
//     the rest of the query preserved (oobCode, mode, lang…);
//   - action payload present but no return target -> readable 400
//     page naming the missing configuration (never a silent fallback);
//   - bare root -> 302 to defaultAppUrl (operational fallback);
//   - no defaultAppUrl -> the same readable page.
//
// Gate One never guesses the application: the target must be carried
// by the link (Firebase continueUrl, OIDC redirect_uri/state, custom
// returnTo) and is validated against the configured app hosts.
func (g *Gateway) serveLoginLanding(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	target := strings.TrimSpace(q.Get("returnTo"))
	if target == "" {
		target = strings.TrimSpace(q.Get("continueUrl"))
	}
	if target != "" {
		if g.landingTargetAllowed(r, target) {
			g.redirectLanding(w, r, target)
			return
		}
		g.writeLandingFallback(
			w, r, q, "returnTo/continueUrl refusé (hôte non autorisé)")
		return
	}

	if names := landingActionParamsPresent(q); len(names) > 0 {
		g.writeLandingFallback(
			w, r, q, "application de retour absente du lien")
		return
	}

	if target := g.providerDefaultAppURL(r.Host); target != "" {
		g.redirectLanding(w, r, target)
		return
	}
	if g.config.DefaultAppURL != "" {
		g.redirectLanding(w, r, g.config.DefaultAppURL)
		return
	}

	g.writeLandingFallback(
		w, r, q, "aucune application par défaut n'est configurée")
}

// landingTargetAllowed validates an application return target: an
// absolute http(s) URL on a configured app host (route host), the
// login host itself (popup-done), or a subdomain of a configured
// cookie domain. This is the anti-open-redirect gate.
func (g *Gateway) landingTargetAllowed(
	r *http.Request, raw string,
) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil {
		return false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return false
	}
	host := normalizeHost(u.Host)
	if host == "" {
		return false
	}

	if host == normalizeHost(r.Host) {
		return true
	}
	for i := range g.config.Routes {
		if host == normalizeHost(g.config.Routes[i].Host) {
			return true
		}
	}
	for _, d := range g.landingCookieDomains() {
		if host == d || strings.HasSuffix(host, "."+d) {
			return true
		}
	}
	if g.config.DefaultAppURL != "" {
		if d, err := url.Parse(g.config.DefaultAppURL); err == nil &&
			normalizeHost(d.Host) == host {
			return true
		}
	}
	return false
}

func (g *Gateway) landingCookieDomains() []string {
	seen := map[string]bool{}
	out := make([]string, 0, 2)
	add := func(domain string) {
		domain = strings.Trim(
			strings.ToLower(strings.TrimSpace(domain)), ".")
		if domain == "" || seen[domain] {
			return
		}
		seen[domain] = true
		out = append(out, domain)
	}
	if g.config.AuthProvider != nil {
		add(g.config.AuthProvider.CookieDomain)
	}
	for _, ap := range g.config.AuthProviders {
		if ap != nil {
			add(ap.CookieDomain)
		}
	}
	return out
}

// redirectLanding sends the browser to the application, merging the
// action payload (mode, oobCode, lang…) into the target query. The
// routing parameters themselves are not forwarded.
func (g *Gateway) redirectLanding(
	w http.ResponseWriter, r *http.Request, target string,
) {
	u, err := url.Parse(target)
	if err != nil {
		http.Error(w, "invalid redirect target", http.StatusInternalServerError)
		return
	}
	q := u.Query()
	for k, vs := range r.URL.Query() {
		if k == "returnTo" || k == "continueUrl" {
			continue
		}
		q.Del(k)
		for _, v := range vs {
			q.Add(k, v)
		}
	}
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func landingActionParamsPresent(q url.Values) []string {
	out := make([]string, 0, 3)
	for _, k := range landingActionKeys {
		if q.Has(k) {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

func (g *Gateway) writeLandingFallback(
	w http.ResponseWriter, r *http.Request, q url.Values, reason string,
) {
	names := landingActionParamsPresent(q)
	ref := landingRef()
	atomic.AddInt64(&statLandingFallback, 1)
	log.Printf(
		"AUTH LANDING incomplete host=%q reason=%q params=%v ref=%s",
		r.Host, reason, names, ref)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusBadRequest)
	_, _ = w.Write([]byte(landingFallbackHTML(
		reason, names, g.config.DefaultAppURL, ref)))
}

func landingRef() string {
	buf := make([]byte, 6)
	if _, err := rand.Read(buf); err != nil {
		return "unknown"
	}
	return hex.EncodeToString(buf)
}

// landingFallbackHTML: self-contained diagnostic page (inline CSS, no
// external asset). Only fixed parameter NAMES are shown — never their
// values (an oobCode/token must not be rendered).
func landingFallbackHTML(
	reason string, params []string, defaultApp, ref string,
) string {
	var received string
	if len(params) > 0 {
		received = fmt.Sprintf(
			"<p class=\"hint\">Paramètres reçus : <code>%s</code> "+
				"(valeurs masquées).</p>",
			html.EscapeString(strings.Join(params, ", ")))
	}

	var action string
	if defaultApp != "" {
		action = fmt.Sprintf(
			"<p><a class=\"btn\" href=\"%s\">"+
				"Continuer vers l'application</a></p>",
			html.EscapeString(defaultApp))
	} else {
		action = "<p class=\"hint\">Aucune application par défaut " +
			"n'est configurée. Contactez l'administrateur.</p>"
	}

	return `<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Lien incomplet</title>
<style>
:root{color-scheme:light dark}
body{margin:0;min-height:100vh;display:flex;align-items:center;` +
		`justify-content:center;background:#f4f5f7;color:#1c1f26;` +
		`font:16px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
main{max-width:38em;margin:2rem;padding:2rem 2.25rem;background:#fff;` +
		`border-radius:12px;box-shadow:0 8px 30px rgba(0,0,0,.08)}
h1{margin:0 0 .6rem;font-size:1.4rem}
p{margin:0 0 .8rem;color:#444}
p:last-child{margin-bottom:0}
p.hint{font-size:.92rem;color:#555}
ul{margin:.2rem 0 .9rem 1.2rem;padding:0;color:#444}
li{margin:.15rem 0}
code{font:13px/1.4 ui-monospace,SFMono-Regular,Menlo,monospace;` +
		`background:#f0f2f5;padding:.1rem .3rem;border-radius:4px}
a.btn{display:inline-block;margin-top:.4rem;padding:.6rem 1rem;` +
		`border-radius:8px;background:#2563eb;color:#fff;` +
		`text-decoration:none;font-weight:600}
a.btn:hover{background:#1d4ed8}
p.ref{margin-top:1.2rem;font-size:.8rem;color:#888}
@media (prefers-color-scheme:dark){body{background:#16181d;color:#eef0f3}` +
		`main{background:#20242e}p{color:#c7ccd6}p.hint{color:#aab2c0}` +
		`ul{color:#c7ccd6}code{background:#2a2f3a}` +
		`a.btn{background:#3b82f6}a.btn:hover{background:#60a5fa}` +
		`p.ref{color:#8b93a3}}
</style>
</head>
<body>
<main>
<h1>Lien incomplet</h1>
<p>Ce lien ne précise pas vers quelle application revenir.</p>
<p><strong>Cause :</strong> ` + html.EscapeString(reason) + `.</p>
<p>L'émetteur du lien doit fournir :</p>
<ul>
<li>Firebase : <code>ActionCodeSettings.url</code> (<code>continueUrl</code>)</li>
<li>OIDC / Keycloak : <code>redirect_uri</code> + <code>state</code></li>
<li>Lien personnalisé : <code>returnTo</code></li>
</ul>
` + received + `
` + action + `
<p class="ref">Référence : ` + html.EscapeString(ref) + `</p>
</main>
</body>
</html>`
}
