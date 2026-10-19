package proxy

import (
	"embed"
	"io"
	"net/http"
	"regexp"

	"cladone/gateway/internal/core"
)

// LoginPageURL is the public auth-bridge login page. Shared by the
// server-side redirect for page routes (proxy.go) and the injected
// 401 guard script (this file).
const LoginPageURL = "https://login.cladone.com/login"

// AuthStatePath is the gateway-served session probe: 200 + JSON
// {roles, scopes, claims} when the caller holds a valid session
// (Bearer header or cookies), 401 otherwise. Never proxied. Consumed
// by the injected guard script for the declarative [data-gtw-auth] /
// [data-gtw-auth-hidden] / [data-gtw-roles] / [data-gtw-scopes] /
// [data-gtw-claims] gating. MUST match the path hardcoded in
// guardScript below.
const AuthStatePath = "/__gateway/auth"

// guardScript is injected into HTML responses of frontend routes. It
// wraps window.fetch so that a 401 answer (session expired or
// identity conditions not met, the gateway answers JSON 401 on API
// routes) triggers a login flow that does NOT reload the application:
//
//   - every fetch is cloned before being sent (a Request body can
//     only be read once), keeping a replayable copy ;
//   - on 401 the failed request is queued and a DISMISSABLE
//     banner ("Se connecter" / ×) is shown: mid-flow 401s never open
//     a tab automatically (a background 401 must not steal focus).
//     The tab opens only on an explicit click: a
//     data-gtw-auth="before" element or the banner button. Dismissing resolves the pending requests with
//     their original 401 response (the app continues anonymously,
//     retryable later) and login() promises resolve false ;
//   - when the tab opens from the banner button, the click is a
//     genuine user gesture, so no popup-blocker issue ; if the tab
//     were opened programmatically on a stale activation, the
//     banner is the reliable path. No code in the app ;
//   - auth-bridge /auth/popup-done (same origin as the login page)
//     postMessages "cladone-auth:ok" to this page and closes the
//     tab. Queued requests are replayed and the ORIGINAL fetch
//     promises resolve with the replayed responses: the application
//     code never sees the authentication happen ;
//   - if the tab is closed without completing (user, blocker):
//     explicit login() promises resolve false silently (« not now ») ;
//     the banner reappears only when real requests are frozen — it is
//     their exit surface (Se connecter or ×) ;
//   - the banner is closable without any login action: ×, click
//     anywhere outside it, or Escape. Closing it closes the linked
//     login tab (if open) at the same time, resolves pending
//     requests with their original 401 and login() with false ;
//   - fallback to the historical full-page redirect when the request
//     cannot be cloned (streaming bodies) or window.open is
//     unavailable.
//
// Declarative gating (opt-in, zero app code) — two orthogonal
// dimensions:
//
//	data-gtw-auth — when auth happens:
//	  "after"  : native click preserved, auth enforced at the request
//	    level (401 → queued → replayed after login) ; the login tab
//	    opens on click as an invitation ;
//	  "before" : the click is neutralized (no native request) and the
//	    login tab opens directly — authenticate first, act after ;
//	  absent   : fully transparent — first 401 → dismissable banner
//	    (never an auto-opened tab).
//
//	data-gtw-auth-hidden — visibility:
//	  "before" : hidden while anonymous, shown once authed (silent
//	    gate — never a trigger; activating clicks are neutralized and
//	    show the banner) ;
//	  "after"  : visible while anonymous, hidden once authed (pure
//	    affordance, composable with gtw-auth="before" for padlocks) ;
//	  absent   : always visible.
//
// Pages using no attribute make no probe request and stay fully
// transparent (auth handled mid-flow by the wrapper, with the
// banner as login affordance).
//
// Notes:
//   - only fetch() calls are wrapped; document navigations are already
//     redirected server-side for page routes
//   - answers from the login page itself are ignored (no redirect loop)
//   - window.__cladoneAuth.login() exposes the same flow to apps that
//     want to trigger authentication from their own UI (opt-in; the
//     zero-code-change contract holds for everyone else)
//
// guardScript : le script de garde, VÉRROUILLÉ par les tests
// (guardInjectedLen, parité node). Le JS vit hors du Go :
// guard/guard.js.tmpl (go:embed) ; les %[n]s sont substitués au
// Sprintf du buildInjectors (login, sonde, uiGate, badge, rewrite).
//
//go:embed guard/guard.js.tmpl
var guardScriptFS embed.FS

var guardScript = func() string {
	b, err := guardScriptFS.ReadFile("guard/guard.js.tmpl")
	if err != nil {
		panic("guard template: " + err.Error())
	}
	return string(b)
}()

var headOpen = regexp.MustCompile(`(?i)<head[^>]*>`)

// charsetMeta : déclaration d'encodage du site servie dans le <head>.
// Le navigateur ne scanne que les 1024 PREMIERS octets pour la
// détecter — le script de garde (~28 Ko) inséré AVANT elle la
// poussait hors fenêtre : le navigateur retombait sur windows-1252
// et affichait "DÃ©connexion" (incident 2026-10-17). L'injection se
// fait donc APRÈS ce meta quand il est dans la fenêtre.
var charsetMeta = regexp.MustCompile(`(?i)<meta[^>]*charset[^>]*>`)

// encodingSniffWindow : la fenêtre de détection d'encodage des
// navigateurs (méta charset cherchée dans les 1024 premiers octets).
const encodingSniffWindow = 1024

// maxGuardBody (32 Mio de budget de buffering) a DISPARU avec
// l'injection en flux (2026-10-18) : le corps n'est plus lu, il
// traverse. Voir guardStream.

// guardEnabledFor resolves the route's authGuard policy: active by
// default on frontend routes, opt-out via {"enabled": false}, no-op on
// non-frontend routes.
func guardEnabledFor(route *core.Route) bool {
	if route.Frontend != true {
		return false
	}
	if route.AuthGuard == nil {
		return true
	}
	if route.AuthGuard.Enabled != nil {
		return *route.AuthGuard.Enabled
	}
	return true
}

// guardLoginURL returns the login URL configured for the guard, if any.
func guardLoginURL(route *core.Route) string {
	if route.AuthGuard != nil && route.AuthGuard.LoginURL != "" {
		return route.AuthGuard.LoginURL
	}
	return LoginPageURL
}

// injectGuardScript installe l'injection de la garde en FLUX : le
// corps n'est plus bufferisé (l'algorithme d'avant 2026-10-18 lisait
// jusqu'à 32 Mio en mémoire) — l'octet qui arrive de l'origine ressort
// vers le client, la mémoire reste O(1) et le navigateur entame son
// rendu dès le premier chunk (TTFB == celui de l'origine, le livre
// proxifié de 6 Mo se rend page par page pendant le téléchargement).
//
// Échanges de taille changeant (script inséré), Content-Length est
// retiré : la réponse part en chunked, et ReverseProxy flusse après
// chaque écriture dès que ContentLength vaut -1 (il lit la décision
// sur resp.ContentLength). Pages PLUS GRANDES que toute limite :
// servies intégralement ET injectées — la troncature de l'incident
// 2026-10-17 est structurellement impossible (plus aucun ReadAll).
func injectGuardScript(resp *http.Response, script string) {

	// Le corps change de taille (script ~28 Ko inséré) : la réponse
	// est servie chunked. En clair dans le pipeline : la décompression
	// gzip est aussi en flux, Content-Encoding a déjà disparu (cette
	// suppression reste un filet, jamais un déclencheur).
	resp.Header.Del("Content-Length")
	resp.Header.Del("Content-Encoding")
	resp.ContentLength = -1
	resp.Body = newGuardStream(resp.Body, script)
}

// injectScanWindow : maximum d'octets retenus pour décider du point
// d'insertion. Concrètement la décision tombe vers l'octet 1024 (fin
// de la fenêtre de détection d'encodage) — <head> est dans les
// premiers octets de tout vrai document ; au-delà de la fenêtre sans
// <head> (fragment HTML d'app framework), fallback historique : le
// script est inséré en tout début de document, puis le reste du corps
// passe en flux.
const injectScanWindow = 64 << 10

// decideInjection : PARITÉ EXACTE avec l'algorithme bufferisé
// historique (avant le streaming, 2026-10-18) :
//   - <head> trouvé : insertion APRÈS lui, mais APRÈS le meta charset
//     quand celui-ci est DANS LA FENÊTRE DE DÉTECTION (< 1024 octets
//     du document original) — sinon le navigateur décode en
//     windows-1252 et affiche "DÃ©connexion" (incident 2026-10-17) ;
//   - pas de <head> dans la fenêtre : script en tout début (fallback
//     historique des pages sans head).
//
// Retourne l'indice d'insertion dans buf, ou -1 pour « pas encore
// décidé — lire davantage » ; eof=true force la décision finale
// (fin de corps, erreur transport incluse).
func decideInjection(buf []byte, eof bool) int {

	if idx := headOpen.FindIndex(buf); idx != nil {
		if len(buf) < encodingSniffWindow && !eof {
			return -1 // la meta charset peut encore apparaître jusqu'à 1024
		}
		injectAt := idx[1]
		sniff := buf
		if len(sniff) > encodingSniffWindow {
			sniff = sniff[:encodingSniffWindow]
		}
		if m := charsetMeta.FindIndex(sniff); m != nil && m[1] > injectAt {
			injectAt = m[1]
		}
		return injectAt
	}

	// pas de <head> : chercher jusqu'à la fenêtre, puis fallback (0).
	if len(buf) < injectScanWindow && !eof {
		return -1
	}
	return 0
}

// guardStream traverse le corps en flux et insère le script une fois,
// au point choisi parmi les premiers octets. Tout ce qui suit
// l'injection passe SANS copie de re-lecture : les 6 Mo du livre
// proxifié ne résident jamais en mémoire gateway.
type guardStream struct {
	src    io.ReadCloser
	script string

	scratch  []byte // buffer de lecture recyclé
	buf      []byte // octets retenus en attente de décision (≤ fenêtre)
	pend     []byte // octets à émettre (préfixe + script + reste du buf)
	pendOff  int
	decided  bool
	streamed bool  // pend épuisé : passthrough direct
	err      error // erreur transport (servie après le pend, jamais avalée)
}

func newGuardStream(src io.ReadCloser, script string) *guardStream {
	return &guardStream{
		src:     src,
		script:  script,
		scratch: make([]byte, 4096),
	}
}

func (g *guardStream) Read(p []byte) (int, error) {

	for g.pendOff >= len(g.pend) {

		if g.streamed {
			if g.err != nil {
				return 0, g.err // propagée, jamais silencieuse
			}
			return g.src.Read(p)
		}

		n, rerr := g.src.Read(g.scratch)
		if n > 0 {
			g.buf = append(g.buf, g.scratch[:n]...)
		}
		eof := rerr == io.EOF
		if rerr != nil && !eof {
			if g.err == nil {
				g.err = rerr
			}
			// décision immédiate sur les octets déjà arrivés
			// (l'erreur du dessous fera tiquer le copyResponse)
			eof = true
		}
		injectAt := decideInjection(g.buf, eof)
		if injectAt < 0 {
			continue // tampon borné par injectScanWindow
		}
		out := make([]byte, 0, len(g.buf)+len(g.script))
		out = append(out, g.buf[:injectAt]...)
		out = append(out, g.script...)
		out = append(out, g.buf[injectAt:]...)
		g.pend = out
		g.pendOff = 0
		g.buf = nil
		g.streamed = true
	}

	n := copy(p, g.pend[g.pendOff:])
	g.pendOff += n
	return n, nil
}

func (g *guardStream) Close() error {
	return g.src.Close()
}
