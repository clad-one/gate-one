package proxy

import (
	"log"
	"net/http"
	"net/url"
	"strings"

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

		if rc := up.RewriteCookies; rc != nil {
			rewriteUpstreamCookies(route, backend, publicHost, rc, resp)
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

// noms de cookies réservés à la session gateway (posés par auth-bridge
// sur le même host public que tout site proxifié) : un Set-Cookie de
// l'origine portant l'un d'eux écraserait l'auth du navigateur.
var reservedCookieNames = map[string]bool{
	"access_token":  true,
	"refresh_token": true,
	"id_token":      true,
	"session":       true,
}

// rewriteUpstreamCookies traduit les Set-Cookie posés par l'origine
// vers le host public (policy upstream.rewriteCookies). Un attribut
// Domain visant l'hôte d'origine (ou un parent) est rejeté par le
// navigateur depuis le host public : mode "rewrite" = transposé vers
// le host public (le périmètre de partage — hôte + sous-domaines —
// est fidèlement traduit), mode "strip" = attribut retiré (host-only
// sur le host public). Les autres cookies passent intacts — chirurgie
// textuelle sur la ligne d'origine : les autres attributs (Path,
// Secure, HttpOnly, SameSite, Expires…) sortent à l'octet près.
// En-têtes uniquement : aucun impact corps/flux.
func rewriteUpstreamCookies(
	route *core.Route,
	backend *url.URL,
	publicHost string,
	rc *core.RewriteCookiesPolicy,
	resp *http.Response,
) {

	lines := resp.Header["Set-Cookie"]
	if len(lines) == 0 {
		return
	}

	out := make([]string, 0, len(lines))
	for _, line := range lines {
		name, _, _ := strings.Cut(line, "=")
		name = strings.TrimSpace(name)
		if reservedCookieNames[name] {
			// le nom jamais la valeur
			log.Printf(
				"COOKIE dropped host=%s: nom réservé %q — un Set-Cookie de l'origine écraserait la session gateway",
				route.Host, name)
			continue
		}
		out = append(out, rewriteCookieDomain(
			line, backend.Hostname(), publicHost, rc.Domain))
	}
	resp.Header["Set-Cookie"] = out
}

// rewriteCookieDomain applique la règle Domain d'un Set-Cookie :
// Domain visant l'hôte d'origine (égal ou parent) → réécrit vers le
// host public ("rewrite") ou retiré ("strip") ; tout le reste sort à
// l'octet près.
func rewriteCookieDomain(line, originHost, publicHost, mode string) string {

	// attributs : à partir du premier ';' hors guillemets (une valeur
	// citée peut en contenir)
	domainStart, domainEnd := -1, -1
	off := nextUnquotedSemicolon(line)
	for off >= 0 {
		rest := line[off+1:]
		attrEnd := len(line)
		var attr string
		if n := nextUnquotedSemicolon(rest); n < 0 {
			attr = rest // dernier attribut
		} else {
			attr = rest[:n]
			attrEnd = off + 1 + n
		}

		key, val, _ := strings.Cut(attr, "=")
		if strings.EqualFold(strings.TrimSpace(key), "domain") {
			dv := strings.Trim(strings.TrimSpace(val), `"`)
			dv = strings.TrimPrefix(dv, ".") // forme RFC historique .host
			dv = strings.ToLower(dv)
			if dv == originHost || strings.HasSuffix(originHost, "."+dv) {
				domainStart, domainEnd = off, attrEnd
			}
			break // premier attribut Domain : les suivants sont illégaux
		}
		if attrEnd >= len(line) {
			break // dernier attribut traité
		}
		// attrEnd = index du ';' ouvrant l'attribut suivant — l'itération
		// suivante examine celui qui le suit (off+1)
		off = attrEnd
	}
	if domainStart < 0 {
		return line // pas de Domain visant l'origine : intact
	}

	if mode == "strip" {
		// l'attribut ET son séparateur partent ensemble
		return line[:domainStart] + line[domainEnd:]
	}
	// la VALEUR seule est remplacée : la clé "Domain=" d'origine
	// (casse, espacement) sort telle quelle
	eq := domainStart + strings.Index(line[domainStart:domainEnd], "=")
	return line[:eq+1] + publicHost + line[domainEnd:]
}

// nextUnquotedSemicolon : index du premier ';' hors valeur citée, -1
// si aucun.
func nextUnquotedSemicolon(s string) int {
	inQuote := false
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '"':
			inQuote = !inQuote
		case ';':
			if !inQuote {
				return i
			}
		}
	}
	return -1
}
