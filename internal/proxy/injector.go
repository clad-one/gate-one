package proxy

// Registry des injecteurs — le point d'extension unique des
// modifications apportées aux RÉPONSES proxifiées. Chaque feature
// (décompression, garde 401/403, réécriture du corps, ajustements
// upstream, PWA, injections custom) implémente l'interface ; la chaîne
// est construite une fois par route au chargement de la config, dans
// l'ordre d'exécution. Fin du câblage à coups de closures imbriquées
// dans proxy.go : ajouter une feature = ajouter un injector.
//
// Ordre d'exécution (l'ordre du slice) — équivalent strict au
// chaînage historique, prouvé par les tests inchangés :
//
//	gzip → garde → rewriteBody → upstream(headers) → pwa → custom
//
// En-têtes seulement ou enveloppe de resp.Body en flux : les deux
// mécanismes passent par la même interface — aucun buffering, la
// mémoire reste O(1) quelle que soit la taille de la page.

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"

	"cladone/gateway/internal/core"
	"cladone/gateway/internal/pwa"
)

// injector : une modification de réponse appliquée aux routes qui y
// sont éligibles.
type injector interface {
	name() string
	// modify applique sa modification (en-têtes, enveloppe de corps
	// en flux, insertion…). Retourner errStopChain pour arrêter la
	// chaîne SANS erreur (réponse servie telle quelle).
	modify(resp *http.Response) error
}

// errStopChain : la réponse ne doit pas être manipulée davantage
// (ex. encodage indécodable) — elle est servie telle quelle, sans
// erreur (fail-open documenté).
var errStopChain = errors.New("injection: chaîne arrêtée — réponse servie telle quelle")

// isHTMLResponse : les injecteurs de corps ne touchent que les 200
// HTML (assets, JSON, PDF, 30x… jamais modifiés).
func isHTMLResponse(resp *http.Response) bool {
	return resp.StatusCode == http.StatusOK &&
		strings.Contains(resp.Header.Get("Content-Type"), "text/html")
}

// buildInjectors : la chaîne d'injection d'une route, dans l'ordre
// d'exécution. u = URL du backend ; rwPlan = politique rewriteBody
// compilée (nil si absente) ; injectsBody = une injection de corps est
// attendue (forçage gzip amont déjà décidé).
func buildInjectors(
	route *core.Route,
	u *url.URL,
	rwPlan *rewritePlan,
	injectsBody bool,
) []injector {

	injectors := make([]injector, 0, 5)

	if injectsBody {
		injectors = append(injectors, &gzipDecodeInjector{host: route.Host})
	}

	if guardEnabledFor(route) {
		log.Printf(
			"GUARD enabled host=%s path=%s loginUrl=%s",
			route.Host,
			route.Path,
			guardLoginURL(route),
		)
		script := fmt.Sprintf(
			guardScript,
			guardLoginURL(route),
			AuthStatePath,
			uiGateJSON(route),
			userBadgeJSON(route),
			rewriteGuardJSON(route, u),
			patchJSONFor(route),
		)
		injectors = append(injectors, &guardInjector{
			host:   route.Host,
			script: script,
		})
	}

	if rwPlan != nil {
		log.Printf(
			"UPSTREAM rewriteBody enabled host=%s origins=%v target=%s except=%d",
			route.Host,
			rwPlan.origins,
			rwPlan.pub,
			len(rwPlan.except),
		)
		injectors = append(injectors, &rewriteBodyInjector{plan: rwPlan})
	}

	if route.Upstream != nil {
		log.Printf(
			"UPSTREAM enabled host=%s path=%s backend=%s",
			route.Host,
			route.Path,
			route.Backend,
		)
		injectors = append(injectors, &upstreamAdjustInjector{
			modifyResponse: upstreamResponseModifier(route, u),
		})
	}

	if route.PWA != nil && route.PWA.Enabled {
		injectors = append(injectors, &pwaInjector{})
	}

	if bundle := route.InjectionBundle(); bundle != nil {
		log.Printf(
			"CUSTOM inject enabled host=%s path=%s entries=%d patch=%d",
			route.Host,
			route.Path,
			len(bundle.Contents),
			len(bundle.Patch),
		)
		injectors = append(injectors, &customInjector{
			host:   route.Host,
			bundle: bundle,
		})
	}

	return injectors
}

// chainInjectors : la ModifyResponse générique — chaque injecteur
// passe la main dans l'ordre ; errStopChain = le reste de la chaîne
// est sauté, la réponse part telle quelle.
func chainInjectors(items []injector) func(*http.Response) error {
	return func(resp *http.Response) error {
		for _, in := range items {
			if err := in.modify(resp); err != nil {
				if errors.Is(err, errStopChain) {
					return nil
				}
				return err
			}
		}
		return nil
	}
}

// gzipDecodeInjector : décompression EN FLUX du HTML gzip avant toute
// manipulation (le stdlib Go ne décode ni brotli ni zstd — incident
// 2026-10-17). Un encodage indécodable qui aurait franchi le forçage
// amont = réponse servie telle quelle, sans injection.
type gzipDecodeInjector struct {
	host string
}

func (i *gzipDecodeInjector) name() string { return "gzip" }

func (i *gzipDecodeInjector) modify(resp *http.Response) error {
	if !isHTMLResponse(resp) {
		return nil
	}

	switch enc := resp.Header.Get("Content-Encoding"); enc {
	case "", "identity":
		// déjà en clair
	case "gzip":
		if err := decodeGzipBody(resp); err != nil {
			log.Printf("GUNZIP failed host=%s: %v", i.host, err)
			return err
		}
	default:
		log.Printf(
			"INJECTION skipped host=%s: Content-Encoding %q indécodable — réponse servie telle quelle",
			i.host,
			enc,
		)
		return errStopChain
	}
	return nil
}

// guardInjector : le script de garde 401/403 (auth sans rechargement,
// gating déclaratif, badge, réécriture runtime) inséré en flux après
// <head>/meta charset. Le script est construit UNE fois à la compile
// de la route.
type guardInjector struct {
	host   string
	script string
}

func (i *guardInjector) name() string { return "guard" }

func (i *guardInjector) modify(resp *http.Response) error {
	if !isHTMLResponse(resp) {
		return nil
	}
	// Injection EN FLUX : elle ne lit pas le corps ici (aucun
	// buffering) — les erreurs transport surfent pendant la copie.
	injectGuardScript(resp, i.script)
	return nil
}

// rewriteBodyInjector : réécriture des URLs d'origine dans le corps
// HTML (upstream.rewriteBody), en flux.
type rewriteBodyInjector struct {
	plan *rewritePlan
}

func (i *rewriteBodyInjector) name() string { return "rewriteBody" }

func (i *rewriteBodyInjector) modify(resp *http.Response) error {
	if !isHTMLResponse(resp) {
		return nil
	}
	// Réécriture EN FLUX idem guardStream : aucun buffering,
	// Content-Length retiré (chunked, flush par écriture car
	// ContentLength vaut -1).
	resp.Header.Del("Content-Length")
	resp.Header.Del("Content-Encoding")
	resp.ContentLength = -1
	resp.Body = newRewriteStream(resp.Body, i.plan)
	return nil
}

// upstreamAdjustInjector : ajustements de la RÉPONSE du backend —
// réécriture des Location absolues, en-têtes set/remove, traduction
// des Set-Cookie (upstream.rewriteCookies).
type upstreamAdjustInjector struct {
	modifyResponse func(*http.Response) error
}

func (i *upstreamAdjustInjector) name() string { return "upstream" }

func (i *upstreamAdjustInjector) modify(resp *http.Response) error {
	return i.modifyResponse(resp)
}

// pwaInjector : link manifest + enregistrement du service worker
// injectés dans le <head> des 200 HTML.
type pwaInjector struct{}

func (i *pwaInjector) name() string { return "pwa" }

func (i *pwaInjector) modify(resp *http.Response) error {
	return pwa.InjectResponse(resp)
}

// customInjector : les injections déclarées par le bundle de la route
// (upstream "inject" — HTML/JS/CSS par cible nommée), en flux.
type customInjector struct {
	host   string
	bundle *core.InjectBundle
}

func (i *customInjector) name() string { return "custom" }

func (i *customInjector) modify(resp *http.Response) error {
	if !isHTMLResponse(resp) {
		return nil
	}
	// Les entrées sont chaînées en ordre DÉCROISSANT : chaque passe
	// insère APRÈS le marqueur de la précédente — l'ordre du document
	// final suit l'ordre croissant des Order.
	items := i.bundle.Contents
	for j := len(items) - 1; j >= 0; j-- {
		item := &items[j]
		// le ciblage par page (when.path) se décide par requête :
		// le chemin de la requête a traversé le director sans être
		// réécrit (seul Host change)
		if !itemMatchesPath(item, resp.Request) {
			continue
		}
		resp.Body = newInjectStream(resp.Body, item.Content, item.Target)
		resp.Header.Del("Content-Length")
		resp.Header.Del("Content-Encoding")
		resp.ContentLength = -1
	}
	return nil
}
