package proxy

import (
	"net/http"
	"net/url"

	"cladone/gateway/internal/core"
)

// applyUpstreamDirector finalise la requête sortante selon la policy
// upstream d'une route. L'en-tête Host suit la policy : défaut
// historique = host public préservé (backends du réseau interne,
// ligne req.Host = u.Host longtemps laissée commentée dans le
// Director) ; upstream.host/hostOverride = origine backend — requis
// pour un site externe qui route par Host (ex. Cloudflare). La
// négociation TLS/SNI, elle, vise toujours l'origine du backend
// (transport standard de Go, dérivé de req.URL).
//
// Les en-têtes statiques sont posés en Set (écrasent la valeur
// éventuellement envoyée par le client) ; valeur "" = en-tête
// supprimé de la requête (jamais transmis vide). Jamais de
// journalisation de ces valeurs (secrets : basic auth, service
// tokens).
func applyUpstreamDirector(
	up *core.UpstreamPolicy,
	backend *url.URL,
	req *http.Request,
) {

	switch {
	case up.HostOverride != "":
		req.Host = up.HostOverride
	case up.Host != nil && *up.Host:
		req.Host = backend.Host
	}

	for k, v := range up.Headers {
		if v == "" {
			req.Header.Del(k)
			continue
		}
		req.Header.Set(k, v)
	}
}

// upstreamResponseModifier retourne le modificateur de réponse de la
// policy upstream : réécriture des Location absolues visant l'origine
// backend vers le host public (sinon le navigateur quitterait le
// proxy dès la première redirection absolue du site cible), puis
// ajustement des en-têtes de réponse (set/remove — ex. retirer un
// Content-Security-Policy d'origine qui bloquerait les balises
// injectées). Installé EN AMONT des injections garde/PWA dans la
// chaîne ModifyResponse (celles-ci ne touchent que le corps des 200
// HTML — l'ordre reste sans effet sur elles).
func upstreamResponseModifier(
	route *core.Route,
	backend *url.URL,
) func(*http.Response) error {

	up := route.Upstream
	publicHost := normalizeHost(route.Host)

	return func(resp *http.Response) error {

		if up.RewriteRedirects != nil && *up.RewriteRedirects {
			rewriteUpstreamLocation(backend, publicHost, resp)
		}

		if rh := up.ResponseHeaders; rh != nil {
			for _, name := range rh.Remove {
				resp.Header.Del(name)
			}
			for k, v := range rh.Set {
				if v == "" {
					resp.Header.Del(k)
					continue
				}
				resp.Header.Set(k, v)
			}
		}

		return nil
	}
}

// rewriteUpstreamLocation réécrit sur place l'en-tête Location de la
// réponse quand il vise l'origine du backend en absolu
// (schéma://backend.host/...) : schéma public https, host public,
// chemin/query/fragment préservés. Les Location relatives et celles
// visant une autre origine (ex. domaine d'équipe Cloudflare Access)
// passent intactes.
func rewriteUpstreamLocation(
	backend *url.URL,
	publicHost string,
	resp *http.Response,
) {

	loc := resp.Header.Get("Location")
	if loc == "" {
		return
	}

	ru, err := url.Parse(loc)
	if err != nil || ru.Host == "" {
		return // relative (ou imparsable) : rien à réécrire
	}

	// Seules les redirections vers la propre origine du backend sont
	// ramenées au host public — une autre origine ne nous appartient
	// pas (ex. login Cloudflare Access sur le domaine d'équipe).
	if ru.Host != backend.Host ||
		(ru.Scheme != "" && ru.Scheme != backend.Scheme) {
		return
	}

	ru.Scheme = "https"
	ru.Host = publicHost

	resp.Header.Set("Location", ru.String())
}
