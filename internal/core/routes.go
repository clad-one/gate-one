package core

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

type Match struct {
	Method string `json:"method,omitempty"`

	Query map[string]string `json:"query,omitempty"`

	Header map[string]string `json:"header,omitempty"`

	Body map[string]any `json:"body,omitempty"`

	// Conditions d'identité : évaluées APRÈS authentification
	// (le token n'existe pas avant) — un échec produit un 403.
	Roles []string `json:"roles,omitempty"`

	Scopes []string `json:"scopes,omitempty"`

	// Claims du token : valeur "*" = simple présence, sinon
	// comparaison de la valeur stringifiée (booléen JSON →
	// "true"/"false", nombres → format Go).
	Claims map[string]string `json:"claims,omitempty"`

	User string `json:"user,omitempty"`
}

type RateLimitPolicy struct {
	Requests int    `json:"requests"`
	Period   string `json:"period"`

	When *Match `json:"when,omitempty"`
}

type QuotaPolicy struct {
	Limit  int    `json:"limit"`
	Period string `json:"period"`

	When *Match `json:"when,omitempty"`
}

// UIGateRule : règle de gating UI pilotée par la config — pour les
// fronts dont on ne peut pas modifier le markup (filet de sécurité ;
// si vous contrôlez le HTML, préférez les attributs data-gtw-*).
// L'élément sélectionné n'est visible que si la session satisfait les
// conditions (OU sur roles, OU sur scopes, ET sur claims, "* " =
// présence). auth/hidden optionnels : mêmes sémantiques que les
// attributs data-gtw-auth / data-gtw-auth-hidden. PRÉCÉDENCE : un
// élément portant au moins un attribut data-gtw-* ignore les règles
// uiGate — la déclaration la plus proche de l'élément gagne.
type UIGateRule struct {
	// Selector : sélecteur CSS (querySelectorAll) des éléments visés.
	Selector string `json:"selector"`
	// Roles : visible si AU MOINS UN de ces rôles est possédé.
	Roles []string `json:"roles,omitempty"`
	// Scopes : visible si AU MOINS UN de ces scopes est accordé.
	Scopes []string `json:"scopes,omitempty"`
	// Claims : tous doivent matcher ("*" = présence).
	Claims map[string]string `json:"claims,omitempty"`
	// Auth : "after" (action native préservée + onglet d'invitation)
	// ou "before" (clic neutralisé + onglet direct).
	Auth string `json:"auth,omitempty"`
	// Hidden : "before" (masqué avant authentification) ou "after"
	// (masqué une fois authentifié).
	Hidden string `json:"hidden,omitempty"`
}

// UserBadgePolicy : onglet utilisateur injecté par le script de garde
// une fois authentifié — replié au bord supérieur (position
// left|right), déplié au survol/focus : les claims choisis + un
// bouton de déconnexion (end_session OIDC). Absent = pas de badge.
type UserBadgePolicy struct {
	// Position : bord supérieur gauche ou droit (défaut "right").
	Position string `json:"position,omitempty"`
	// Claims affichés dans l'onglet déplié (les claims absents sont
	// omis — ex. preferred_username, email).
	Claims []string `json:"claims,omitempty"`
	// LogoutLabel : libellé du bouton (défaut "Déconnexion").
	LogoutLabel string `json:"logoutLabel,omitempty"`
	// LoginBadge : le badge apparaît AUSSI en anonyme, dès la
	// première visite, en mode invitation (« 👤 Se connecter ») —
	// cliqué, il ouvre l'onglet de connexion. Pour proposer la
	// connexion sans toucher au markup du site. Défaut : false
	// (badge seulement une fois authentifié ; en anonyme il
	// n'apparaît qu'après une mort de session détectée).
	LoginBadge bool `json:"loginBadge,omitempty"`
}

type AuthPolicy struct {
	When *Match `json:"when,omitempty"`

	//Roles []string `json:"roles,omitempty"`
}

type OpenAPIPolicy struct {
	URL    string `json:"url"`
	Public bool   `json:"public,omitempty"`
}

// AuthGuardPolicy controls the injection of the gateway's 401/403 guard
// script into HTML responses of frontend routes. Unlike the AuthPolicy
// (which enforces authentication on a route), the guard only reacts to
// 401/403 answers already produced: when the injected script sees a
// fetch() answer 401/403 it redirects the browser to the login page.
// Absent policy = guard active on frontend routes, no-op elsewhere.
type AuthGuardPolicy struct {
	Enabled  *bool  `json:"enabled,omitempty"`  // false = opt-out
	LoginURL string `json:"loginUrl,omitempty"` // default: shared constant
}

// RewriteExcept : exception de rewriteBody. Deux formes déclarables :
//
//   - une chaîne : "path" — les URLs de l'origine DONT LE CHEMIN
//     commence par ce préfixe restent pointées vers l'origine (aucune
//     réécriture) ;
//   - un objet {"path", "to"} : les mêmes URLs sont réécrites vers le
//     host public alternatif `to` (schéma https) — le reste du chemin,
//     query et fragment est préservé.
//
// Le préfixe le plus long gagne. Les entrées sont triées par longueur
// décroissante à la compilation, côté gateway comme côté SW client.
type RewriteExcept struct {
	// Path : préfixe de chemin ("/..." — sans '?' ni '#').
	Path string `json:"path"`
	// To : base de remplacement "https://host.alternatif" ; vide =
	// les URLs de ce préfixe restent à l'origine (forme chaîne).
	To string `json:"to,omitempty"`
}

// UnmarshalJSON accepte la forme chaîne ("path") et la forme objet
// {"path","to"} du tableau except.
func (e *RewriteExcept) UnmarshalJSON(b []byte) error {

	if len(b) > 0 && b[0] == '"' {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		e.Path, e.To = s, ""
		return nil
	}

	var raw struct {
		Path string `json:"path"`
		To   string `json:"to"`
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&raw); err != nil {
		return err
	}
	*e = RewriteExcept{Path: raw.Path, To: raw.To}
	return nil
}

// RewriteBodyPolicy : réécriture en flux des URLs absolues de
// l'origine (upstream.rewriteBody). Pour un site externe proxifié, le
// HTML d'origine cite ses propres URLs ("https://origine/...",
// "//origine/...") : sans réécriture le navigateur quitterait le
// proxy dès le premier lien/asset absolu. La gateway réécrit ces
// occurrences vers le host PUBLIC de la route (même chemin), en flux,
// sur les corps HTML 200 — à l'exception des préfixes déclarés dans
// except : une exception chaîne laisse le lien à l'origine (lien de
// lecture resté hors proxy, p.ex.), une exception {path,to} pointe
// vers un autre host public (ex. variante de lecture hébergée avec
// ses propres fonctionnalités).
//
// Le runtime JS/WASM (fetch/XHR, import(), img dynamique…) est couvert
// par le service worker configuré de la route (même politique) +
// réécriture au niveau des appels dans le script de garde. Le corps
// des fichiers JS/CSS n'est pas réécrit (redondant avec le SW).
type RewriteBodyPolicy struct {
	Enabled bool `json:"enabled"`
	// Except : exceptions de préfixe de chemin — forme chaîne (reste
	// à l'origine) ou objet {path, to} (host public alternatif).
	Except []RewriteExcept `json:"except,omitempty"`
}

// UpstreamResponseHeaders : ajustement des en-têtes de RÉPONSE du
// backend avant envoi au navigateur — typiquement retirer un
// Content-Security-Policy d'origine qui bloquerait le script de garde
// injecté, ou poser un en-tête de déploiement.
type UpstreamResponseHeaders struct {
	// Set : en-têtes ajoutés/écrasés sur la réponse ; valeurs avec
	// interpolation ${VAR} (environnement du conteneur) ; valeur ""
	// = en-tête supprimé (jamais transmis vide).
	Set map[string]string `json:"set,omitempty"`
	// Remove : noms d'en-têtes supprimés de la réponse.
	Remove []string `json:"remove,omitempty"`
}

// UpstreamPolicy : comment la gateway joint le backend quand il
// n'est pas un service du réseau interne — typiquement un site
// hébergé derrière Cloudflare (Pages, Access…). Absente =
// comportement historique inchangé (Host public préservé, en-têtes
// du client transmis tels quels).
type UpstreamPolicy struct {
	// Host : true = l'en-tête Host envoyé au backend est celui de
	// l'origine backend (requis pour un site externe qui route par
	// Host, ex. Cloudflare : sinon la requête arrive avec le host
	// public et l'origine ne la reconnaît pas). Absent/false = Host
	// public transmis tel quel (backends internes).
	Host *bool `json:"host,omitempty"`
	// HostOverride : valeur explicite de l'en-tête Host envoyée au
	// backend, quand elle doit différer à la fois du host public et
	// de l'origine backend (rare). Précédence sur Host.
	HostOverride string `json:"hostOverride,omitempty"`
	// Headers : en-têtes de requête statiques posés vers le backend
	// (Set : écrasent la valeur éventuellement envoyée par le
	// client). Usage : franchir un basic auth d'origine
	// ("Authorization": "Basic ${MONSITE_BASIC_AUTH}") ou les service
	// tokens Cloudflare Access ("CF-Access-Client-Id" /
	// "CF-Access-Client-Secret"). Valeurs avec interpolation ${VAR}
	// depuis l'environnement du conteneur (variable absente = erreur
	// fatale au load — jamais d'identifiant vide silencieux) ;
	// valeur "" = en-tête supprimé de la requête. Les valeurs ne
	// sont jamais journalisées.
	Headers map[string]string `json:"headers,omitempty"`
	// RewriteRedirects : true = les Location ABSOLUES visant
	// l'origine du backend sont réécrites vers le host public
	// (sinon le navigateur quitterait le proxy dès la première
	// redirection absolue du site cible). Les Location relatives et
	// celles visant d'autres origines (ex. domaine d'équipe Cloudflare
	// Access) passent intactes. Défaut : false.
	RewriteRedirects *bool `json:"rewriteRedirects,omitempty"`
	// ResponseHeaders : ajustement des en-têtes de réponse (cf.
	// UpstreamResponseHeaders).
	ResponseHeaders *UpstreamResponseHeaders `json:"responseHeaders,omitempty"`
	// RewriteBody : réécriture des URLs absolues de l'origine dans les
	// corps HTML 200 (déclaratif, en flux, avec exceptions de préfixe ;
	// le SW client configuré couvre les appels runtime). Défaut :
	// aucune réécriture du corps.
	RewriteBody *RewriteBodyPolicy `json:"rewriteBody,omitempty"`
	// RewriteCookies : traduction des Set-Cookie posés par l'origine
	// (leur attribut Domain vise son propre namespace, que le
	// navigateur rejetterait depuis le host public). Défaut : aucune
	// réécriture des cookies.
	RewriteCookies *RewriteCookiesPolicy `json:"rewriteCookies,omitempty"`
}

// RewriteCookiesPolicy : traduction des Set-Cookie de l'origine vers
// le host public (cf. UpstreamPolicy.RewriteCookies).
type RewriteCookiesPolicy struct {
	// Domain : "rewrite" = Domain visant l'hôte d'origine (ou un de
	// ses parents) réécrit vers Domain=<host public> — le périmètre de
	// partage (hôte + sous-domaines) est transposé tel quel ;
	// "strip" = attribut Domain retiré (cookie host-only sur le host
	// public). Dans les deux modes, un Set-Cookie portant un nom
	// réservé à la session gateway (access_token, refresh_token,
	// id_token, session) est retiré avec un warning : posé sur le même
	// host public, il écraserait les cookies d'auth.
	Domain string `json:"domain"`
}

type MCPOperation struct {
	Name        string `json:"name"`
	OperationID string `json:"operationId"`
}

type MCPPolicy struct {
	Enabled bool   `json:"enabled"`
	Path    string `json:"path,omitempty"`
	// Scope: le client scope Keycloak exigé des clients MCP (porté par
	// le claim `scope` du bearer). Annoncé dans
	// /.well-known/oauth-protected-resource et vérifié par auth-bridge
	// (transmis via le header interne X-MCP-Scope). Défaut :
	// defaultMCPScope. Le realm doit accorder le même scope (client
	// scope optionnel du même nom dans cladone-realm.json).
	Scope      string         `json:"scope,omitempty"`
	Operations []MCPOperation `json:"operations"`
}

// PWAApiCache declares a size-bounded offline cache for API responses
// (typically POST+SSE streams like /api/process_stream): responses are
// stored keyed by request (URL + body) while streaming normally to the
// app, and replayed from cache when the network fails. Only complete,
// successful responses are cached. Multiple blocks may be declared
// (one per endpoint policy).
type PWAApiCache struct {
	Path string `json:"path"`
	// Method selects the cached method: "POST" (default) for the
	// network-first offline replay of POST/SSE calls, "GET" for a
	// stale-while-revalidate cache of that exact path (offline is
	// covered by SWR itself, so OfflineFastPath does not apply), or
	// "none" to opt this path OUT of caching entirely: no route is
	// generated and the apiGETCache catch-all also ignores it — the
	// endpoint always goes to the network. Useful to exempt an
	// endpoint from the universal GET cache.
	Method string `json:"method,omitempty"`
	// MaxEntries bounds the number of cached responses (default 50).
	MaxEntries int `json:"maxEntries,omitempty"`
	// MaxAgeSeconds bounds entry age (default 86400 = 24h).
	MaxAgeSeconds int `json:"maxAgeSeconds,omitempty"`
	// MaxEntrySizeBytes refuses to cache individual responses larger
	// than this (default 2 MiB) so one huge payload cannot evict
	// everything else.
	MaxEntrySizeBytes int64 `json:"maxEntrySizeBytes,omitempty"`
	// Version bumps this endpoint's cache when the backend's results
	// change (new lexicon, bug fix in the computation): the string is
	// part of the cache name, so changing it invalidates the old
	// entries at the next SW activation.
	Version string `json:"version,omitempty"`
	// IdleFinalizeMs: the cached response is finalized after this many
	// milliseconds without a new chunk from the SSE stream (default
	// 1500). Handles backends that keep the connection open (keep-alive
	// SSE) instead of closing it after the last event.
	IdleFinalizeMs int `json:"idleFinalizeMs,omitempty"`
	// NetworkTimeoutSeconds bounds how long the offline replay waits
	// for the network BEFORE falling back to the cache (default 3).
	// Applies to the headers only: once a response arrives, its
	// streaming duration is unbounded. The OS offline flag
	// (navigator.onLine === false) skips the network entirely.
	NetworkTimeoutSeconds int `json:"networkTimeoutSeconds,omitempty"`
	// OfflineFastPath (default true): when navigator.onLine === false,
	// serve the cached response directly instead of attempting the
	// network first. Disable for endpoints where replaying a cached
	// write would be wrong (the app would see success while nothing
	// was sent); with false, the offline detection is by fetch
	// failure (bounded by NetworkTimeoutSeconds). Pointer: absent
	// (nil) means the default, an explicit false disables.
	OfflineFastPath *bool `json:"offlineFastPath,omitempty"`
}

// PWAApiGETCache configures the universal no-config GET cache
// (pwa.apiGETCache). Its presence enables it.
type PWAApiGETCache struct {
	// Excludes: path prefixes never cached by the catch-all (on top
	// of the declared apiCaches[] paths and the virtual /__gateway_pwa/
	// prefix, which are always excluded).
	Excludes []string `json:"excludes,omitempty"`
	// ExcludePatterns: regular expressions (JS RegExp syntax, tested
	// against the FULL URL) of requests the catch-all must never cache.
	// Use when a prefix is not selective enough — e.g. exclude a
	// parameterized endpoint while keeping the rest of its path cached:
	// "^https://vers\\.cladone\\.com/api/poems\\?.*user=" . A pattern
	// with invalid syntax is rejected at config load (the gateway fails
	// fast rather than silently caching what should be excluded).
	ExcludePatterns []string `json:"excludePatterns,omitempty"`
}

// PWANetworkOnlyPolicy declares URLs that must never be cached by any
// strategy of the generated service worker (pwa.networkOnly). Its
// presence enables the catch-all "never cache" route.
type PWANetworkOnlyPolicy struct {
	// ExcludePatterns: JS regular expressions tested against the FULL
	// URL (path + query). Typical use: the auth server's paths
	// ("/protocol/openid-connect", "/auth") and OAuth/OIDC callback
	// parameters ("[?&]code=", "[?&]state=", …) — one-time codes must
	// never land in a cache. Nothing is hard-coded: declare what YOUR
	// auth server needs. Invalid syntax is rejected at config load.
	ExcludePatterns []string `json:"excludePatterns,omitempty"`
}

// PWAPolicy declares, per frontend route, the gateway-managed PWA wrap:
// virtual endpoints under /__gateway_pwa/ (manifest, service worker,
// self-hosted Workbox runtime) and <head> injection on HTML responses.
type PWAPolicy struct {
	Enabled    bool   `json:"enabled"`
	Name       string `json:"name,omitempty"`
	ShortName  string `json:"shortName,omitempty"`
	ThemeColor string `json:"themeColor,omitempty"`
	// Icons are paths on the same host, referenced from the generated
	// manifest, not proxied. Chrome requires 192x192 and 512x512 PNG
	// for a fully installable app. Legacy single "icon" is still read.
	Icon  string   `json:"icon,omitempty"`
	Icons []string `json:"icons,omitempty"`
	// ApiCaches: offline replay of API responses (POST/SSE included),
	// one block per endpoint policy. ApiCache is the legacy singular
	// form, still read. Method selects the cached method ("POST" by
	// default, "GET" for a SWR cache of that exact path, "none" to
	// opt the path out of caching entirely — declared endpoints are
	// excluded from the apiGETCache catch-all for every method).
	ApiCache  *PWAApiCache   `json:"apiCache,omitempty"`
	ApiCaches []*PWAApiCache `json:"apiCaches,omitempty"`
	// ApiGETCache, when present, adds a catch-all GET cache for
	// the requests nothing else covers (fetch() data calls, images,
	// fonts — anything the assets route does not match). Declared
	// apiCaches[] paths are excluded (an endpoint declared is master
	// of its path, every method); Excludes removes further prefixes.
	ApiGETCache *PWAApiGETCache `json:"apiGETCache,omitempty"`
	// NetworkOnly, when present, adds a catch-all "never cache" route:
	// every URL matching one of its patterns goes straight to the
	// network, untouched by any cache (authentication exchanges,
	// OAuth/OIDC callbacks carrying one-time codes, health endpoints…).
	// Nothing is hard-coded: which URLs are excluded is a deployment
	// decision — the gateway works with any auth server. Patterns are
	// JS regular expressions tested against the FULL URL (path + query);
	// invalid syntax is rejected at config load.
	NetworkOnly *PWANetworkOnlyPolicy `json:"networkOnly,omitempty"`
	// Assets tunes the strategy for pages and same-origin assets
	// (documents, scripts, styles). If unset: StaleWhileRevalidate
	// without timeout — the cache answers instantly, network refreshes
	// it in the background.
	Assets *PWAAssetsPolicy `json:"assets,omitempty"`
}

// PWAAssetsPolicy selects the workbox strategy for documents/scripts/
// styles and, for networkFirst, how long to wait for the network
// before falling back to the cache.
type PWAAssetsPolicy struct {
	// Strategy: "staleWhileRevalidate" (default), "networkFirst",
	// "cacheFirst".
	Strategy string `json:"strategy,omitempty"`
	// NetworkTimeoutSeconds: for networkFirst only, seconds to wait for
	// the network before serving the cache (default 3).
	NetworkTimeoutSeconds int `json:"networkTimeoutSeconds,omitempty"`
}

// EffectiveAssets returns the assets policy with defaults applied.
func (p *PWAPolicy) EffectiveAssets() (strategy string, timeout int) {
	strategy, timeout = "staleWhileRevalidate", 0
	if p.Assets != nil {
		if s := strings.ToLower(p.Assets.Strategy); s != "" {
			strategy = s
		}
		if p.Assets.NetworkTimeoutSeconds > 0 {
			timeout = p.Assets.NetworkTimeoutSeconds
		}
	}
	// strings.ToLower aplatit aussi les valeurs CamelCase déclarées
	// (networkFirst -> networkfirst) : les comparaisons sont en
	// minuscules, seule la classe workbox générée par swJS rétablit la
	// casse.
	switch strategy {
	case "networkfirst":
		if timeout <= 0 {
			timeout = 3
		}
		strategy = "NetworkFirst"
	case "cachefirst":
		strategy = "CacheFirst"
	default:
		strategy = "StaleWhileRevalidate"
		if timeout > 0 {
			timeout = 0
		}
	}
	return strategy, timeout
}

// EffectiveApiCaches merges the legacy singular form with the list.
func EffectiveApiCaches(p *PWAPolicy) []*PWAApiCache {
	out := p.ApiCaches
	if p.ApiCache != nil {
		out = append(out, p.ApiCache)
	}
	return out
}

// networkOnlyPatterns returns every exclusion pattern declared on the
// PWA policy (apiGETCache.excludePatterns + networkOnly.excludePatterns),
// for a single validation pass.
func (p *PWAPolicy) networkOnlyPatterns() []string {
	var out []string
	if p.ApiGETCache != nil {
		out = append(out, p.ApiGETCache.ExcludePatterns...)
	}
	if p.NetworkOnly != nil {
		out = append(out, p.NetworkOnly.ExcludePatterns...)
	}
	return out
}

type Route struct {
	Host string `json:"host"`
	Path string `json:"path"`

	Frontend bool   `json:"frontend,omitempty"`
	Backend  string `json:"backend"`

	// Upstream : jointure vers un backend hors réseau interne (site
	// externe proxifié — ex. Cloudflare) : Host, en-têtes statiques
	// (basic auth, service tokens), réécriture des redirections et
	// des en-têtes de réponse. Absente = comportement historique.
	Upstream *UpstreamPolicy `json:"upstream,omitempty"`

	AutoHead bool `json:"autoHead,omitempty"`

	Auth      *AuthPolicy      `json:"auth,omitempty"`
	RateLimit *RateLimitPolicy `json:"rateLimit,omitempty"`
	Quota     *QuotaPolicy     `json:"quota,omitempty"`

	OpenAPI *OpenAPIPolicy `json:"openapi,omitempty"`
	MCP     *MCPPolicy     `json:"mcp,omitempty"`
	PWA     *PWAPolicy     `json:"pwa,omitempty"`

	// UIGate : gating UI par config (sélecteurs CSS + conditions
	// d'identité) — pour les fronts non modifiables ; embarqué dans
	// le script de garde injecté. Précédence : le markup data-gtw-*
	// d'un élément gagne sur les règles uiGate.
	UIGate []*UIGateRule `json:"uiGate,omitempty"`

	// UserBadge : onglet utilisateur injecté (claims + déconnexion).
	UserBadge *UserBadgePolicy `json:"userBadge,omitempty"`

	AuthGuard *AuthGuardPolicy `json:"authGuard,omitempty"`

	// Inject : chemin du bundle d'injections custom de la route
	// (JSON : injects = HTML/JS/CSS par cible nommée, patch = règles
	// data-* appliquées par le garde), relatif au fichier de config —
	// le tableau de routage ne grossit jamais du code des sites.
	Inject string `json:"inject,omitempty"`

	// injection : bundle résolu au load (contenus des file: lus,
	// validation stricte) — jamais sérialisé.
	injection *InjectBundle `json:"-"`
}

// InjectionBundle : le bundle d'injections résolu de la route ; nil
// sans bloc "inject".
func (r *Route) InjectionBundle() *InjectBundle { return r.injection }

// InjectBundle : bundle d'injections custom d'une route, résolu au
// load (fichiers lus, tout validé — un bundle fautif refuse le
// démarrage/reload plutôt qu'être ignoré).
type InjectBundle struct {
	// Contents : les injections à insérer dans les pages (triées par
	// Order croissant = ordre dans le document).
	Contents []InjectContent `json:"injects,omitempty"`
	// Patch : règles d'attribution data-* par sélecteur, appliquées
	// côté client par le garde (extension de l'évaluation uiGate —
	// même sonde, même cycle). Route frontend requise.
	Patch []InjectPatch `json:"patch,omitempty"`
}

// InjectContent : une insertion — contenu assemblé au load (html/
// style/script inline + contenu des file:), cible nommée dans le
// document, filtrage par page (préfixe de chemin, même grammaire que
// route.path).
type InjectContent struct {
	// Name : identifiant du bundle (unique, logs).
	Name string `json:"name"`
	// Target : "head" (défaut — après <head>/meta charset) ou
	// "body-end" (avant </body>).
	Target string `json:"target,omitempty"`
	// Order : position dans le document au sein d'une même cible
	// (30+ pour les customs ; la garde vaut 10, la pwa 20).
	Order int `json:"order,omitempty"`
	// WhenPath : préfixe de chemin des pages visées ("/*" = tout le
	// site) ; vide = toutes.
	WhenPath string `json:"when,omitempty"`
	// Content : le snippet ASSEMBLÉ (html + style + script + file),
	// prêt à insérer tel quel.
	Content string `json:"-"`
}

// InjectPatch : une règle de patch — les attributs (typiquement des
// data-gtw-*) sont posés sur les éléments matchés par le sélecteur.
// S'applique à chaque cycle d'évaluation du garde (éléments dynamiques
// couverts) ; un attribut markup préexistant est ÉCRASÉ (le patch
// déclare la cible, le sélecteur la trouve).
type InjectPatch struct {
	Selector string            `json:"selector"`
	Attrs    map[string]string `json:"attrs,omitempty"`
}

type Config struct {
	// $schema : référence optionnelle vers api-routes.schema.json
	// (autocomplétion/validation éditeur) — ignorée au runtime.
	Schema string `json:"$schema,omitempty"`

	// OIDC : l'IdP de la plateforme — la gateway est multi-tenant,
	// aucune URL d'IdP n'est codée en dur (les routes y accèdent via
	// LoginURLFor / OIDC.Issuer).
	OIDC *OIDCConfig `json:"oidc,omitempty"`

	Routes []Route `json:"routes"`
}

// OIDCConfig : l'IdP de la plateforme (bloc top-level). loginUrl =
// page de login par défaut des routes frontend à garde active
// (overridable par route via authGuard.loginUrl) ; issuer = émetteur
// OIDC annoncé dans la metadata OAuth des routes MCP.
type OIDCConfig struct {
	LoginURL string `json:"loginUrl,omitempty"`
	Issuer   string `json:"issuer,omitempty"`
}

// GuardActive : la garde est-elle active sur cette route ? (frontend +
// authGuard non désactivé) — la même règle que le proxy.
func (r *Route) GuardActive() bool {
	if r.Frontend != true {
		return false
	}
	if r.AuthGuard == nil {
		return true
	}
	if r.AuthGuard.Enabled != nil {
		return *r.AuthGuard.Enabled
	}
	return true
}

// MCPActive : la route expose-t-elle un serveur MCP ?
func (r *Route) MCPActive() bool {
	return r.MCP != nil && r.MCP.Enabled
}

// LoginURLFor : l'URL de login d'une route — authGuard.loginUrl
// (route) gagne sur oidc.loginUrl (plateforme). Garantie non vide par
// la validation au load pour toute route à garde active.
func (c *Config) LoginURLFor(route *Route) string {
	if route.AuthGuard != nil && route.AuthGuard.LoginURL != "" {
		return route.AuthGuard.LoginURL
	}
	if c.OIDC != nil {
		return c.OIDC.LoginURL
	}
	return ""
}

func Load(path string) (*Config, error) {

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg Config

	// Stricte : tout champ inconnu (typiquement une faute de frappe
	// dans un nom de policy) est rejeté au load plutôt que
	// silencieusement ignoré.
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()

	if err := dec.Decode(&cfg); err != nil {

		if se, ok := err.(*json.SyntaxError); ok {

			line := 1
			col := 1

			for i := 0; i < int(se.Offset)-1 && i < len(data); i++ {
				if data[i] == '\n' {
					line++
					col = 1
				} else {
					col++
				}
			}

			return nil, fmt.Errorf(
				"%s:%d:%d: %v",
				path,
				line,
				col,
				err,
			)
		}

		return nil, err
	}

	// Secrets upstream (${VAR} dans les en-têtes) résolus AVANT la
	// validation : variable absente = refus de démarrer.
	if err := cfg.expandUpstreamEnv(); err != nil {
		return nil, fmt.Errorf("%s: %v", path, err)
	}

	// Bundles d'injection résolus (fichiers lus au load : un bundle
	// fautif refuse le démarrage, jamais ignoré en silence).
	if err := cfg.loadInjectBundles(filepath.Dir(path)); err != nil {
		return nil, fmt.Errorf("%s: %v", path, err)
	}

	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("%s: %v", path, err)
	}

	return &cfg, nil
}

// envVarPattern : forme d'interpolation supportée dans les valeurs
// d'en-têtes upstream — ${NOM} uniquement (jamais $NU, pour ne pas
// dénaturer une valeur qui contiendrait un $ littéral).
var envVarPattern = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

// cibles d'insertion nommées (le "head" = après <head>/meta charset —
// la mécanique de la garde ; "body-end" = avant </body>).
var validInjectTargets = map[string]bool{
	"":         true, // défaut = head
	"head":     true,
	"body-end": true,
}

// bornes des injections custom : Order >= 30 (la garde vaut 10, la
// pwa 20 — un custom ne peut pas se glisser devant l'infrastructure)
// et contenu borné.
const (
	minInjectOrder    = 30
	maxInjectOrder    = 10000
	maxInjectContents = 64
	maxInjectPatch    = 64
	maxInjectSnippet  = 256 << 10 // 256 Kio par entrée (fichier inclus)
)

// rawInjectBundle : forme sérialisée du bundle (avant résolution des
// file:).
type rawInjectBundle struct {
	Injects []struct {
		Name   string `json:"name"`
		Target string `json:"target,omitempty"`
		Order  *int   `json:"order,omitempty"`
		When   string `json:"when,omitempty"`
		HTML   string `json:"html,omitempty"`
		Style  string `json:"style,omitempty"`
		Script string `json:"script,omitempty"`
		File   string `json:"file,omitempty"`
	} `json:"injects"`
	Patch []InjectPatch `json:"patch"`
}

// loadInjectBundles résout le bloc "inject" de chaque route : lit le
// bundle (JSON strict), assemble les contenus (inline + files) et
// valide. dir = répertoire du fichier de config.
func (c *Config) loadInjectBundles(dir string) error {

	for i := range c.Routes {

		ref := c.Routes[i].Inject
		if ref == "" {
			continue
		}
		host := c.Routes[i].Host

		bundlePath := ref
		if !filepath.IsAbs(bundlePath) {
			bundlePath = filepath.Join(dir, ref)
		}
		data, err := os.ReadFile(bundlePath)
		if err != nil {
			return fmt.Errorf("route %s: inject %q: %v", host, ref, err)
		}

		var raw rawInjectBundle
		dec := json.NewDecoder(bytes.NewReader(data))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&raw); err != nil {
			return fmt.Errorf("route %s: inject %q: %v", host, ref, err)
		}

		if len(raw.Injects) > maxInjectContents {
			return fmt.Errorf("route %s: inject %q: %d entrées (max %d)",
				host, ref, len(raw.Injects), maxInjectContents)
		}
		if len(raw.Patch) > maxInjectPatch {
			return fmt.Errorf("route %s: inject %q: %d patch (max %d)",
				host, ref, len(raw.Patch), maxInjectPatch)
		}

		bundle := &InjectBundle{Patch: raw.Patch}
		bundleDir := filepath.Dir(bundlePath)
		seen := make(map[string]bool, len(raw.Injects))

		for j := range raw.Injects {
			in := &raw.Injects[j]
			if in.Name == "" {
				return fmt.Errorf(
					"route %s: inject %q: injects[%d].name vide", host, ref, j)
			}
			if seen[in.Name] {
				return fmt.Errorf(
					"route %s: inject %q: nom dupliqué %q", host, ref, in.Name)
			}
			seen[in.Name] = true

			if !validInjectTargets[in.Target] {
				return fmt.Errorf(
					"route %s: inject %q: %s.target %q (attendu \"head\" ou \"body-end\")",
					host, ref, in.Name, in.Target)
			}

			order := 30
			if in.Order != nil {
				order = *in.Order
			}
			if order < minInjectOrder || order > maxInjectOrder {
				return fmt.Errorf(
					"route %s: inject %q: %s.order %d (bornes %d-%d)",
					host, ref, in.Name, order, minInjectOrder, maxInjectOrder)
			}

			// assemblage : le style et le script sont ENVELOPPÉS
			// (l'html et le file: sont injectés tels quels)
			var parts []string
			if in.HTML != "" {
				parts = append(parts, in.HTML)
			}
			if in.Style != "" {
				parts = append(parts, "<style>"+in.Style+"</style>")
			}
			if in.Script != "" {
				parts = append(parts, "<script>"+in.Script+"</script>")
			}
			content := strings.Join(parts, "\n")
			if in.File != "" {
				if strings.Contains(in.File, "..") || filepath.IsAbs(in.File) {
					return fmt.Errorf(
						"route %s: inject %q: %s.file %q (chemin relatif au bundle requis)",
						host, ref, in.Name, in.File)
				}
				fileData, err := os.ReadFile(
					filepath.Join(bundleDir, in.File))
				if err != nil {
					return fmt.Errorf(
						"route %s: inject %q: %s.file: %v",
						host, ref, in.Name, err)
				}
				parts = append(parts, string(fileData))
				content = strings.Join(parts, "\n")
			}
			if strings.TrimSpace(content) == "" {
				return fmt.Errorf(
					"route %s: inject %q: %s sans contenu (html/style/script/file)",
					host, ref, in.Name)
			}
			if len(content) > maxInjectSnippet {
				return fmt.Errorf(
					"route %s: inject %q: %s : %d octets (max %d)",
					host, ref, in.Name, len(content), maxInjectSnippet)
			}

			bundle.Contents = append(bundle.Contents, InjectContent{
				Name:     in.Name,
				Target:   in.Target,
				Order:    order,
				WhenPath: in.When,
				Content:  content,
			})
		}

		// ordre du document = Order croissant (tri stable)
		sort.SliceStable(bundle.Contents, func(a, b int) bool {
			return bundle.Contents[a].Order < bundle.Contents[b].Order
		})

		for k := range raw.Patch {
			p := &raw.Patch[k]
			if p.Selector == "" {
				return fmt.Errorf(
					"route %s: inject %q: patch[%d].selector vide",
					host, ref, k)
			}
			if len(p.Attrs) == 0 {
				return fmt.Errorf(
					"route %s: inject %q: patch[%d] (%s) sans attrs",
					host, ref, k, p.Selector)
			}
		}

		c.Routes[i].injection = bundle
	}
	return nil
}

// expandEnvVars remplace chaque ${VAR} par la variable d'environnement
// correspondante. Variable absente = erreur nommée (le gateway refuse
// de démarrer plutôt que d'envoyer un identifiant vide au backend).
// Variable PRÉSENTE MAIS VIDE = valeur entière vidée, noms signalés
// dans emptyNames (l'appelant la traitera comme un en-tête retiré et
// journalisera l'avertissement) — cf. compose « ${VAR:-} » qui
// injecte une chaîne vide quand la variable manque au .env.
func expandEnvVars(s string) (out string, err error, emptyNames []string) {

	var missing []string

	out = envVarPattern.ReplaceAllStringFunc(s, func(m string) string {
		name := m[2 : len(m)-1]
		v, ok := os.LookupEnv(name)
		if !ok {
			missing = append(missing, name)
			return m
		}
		if v == "" {
			emptyNames = append(emptyNames, name)
			return ""
		}
		return v
	})

	if len(missing) > 0 {
		return "", fmt.Errorf(
			"variable(s) d'environnement absente(s): %s",
			strings.Join(missing, ", "),
		), nil
	}

	if len(emptyNames) > 0 {
		return "", nil, emptyNames
	}

	return out, nil, nil
}

// expandUpstreamEnv résout l'interpolation ${VAR} des en-têtes
// upstream. Pass ciblé aux seuls blocs upstream (la config est
// committée dans git : les secrets y entrent par l'environnement du
// conteneur, jamais en clair) — un passe-générale risquerait de
// corrompre des patterns regex PWA contenant un '$'.
func (c *Config) expandUpstreamEnv() error {

	for i := range c.Routes {

		up := c.Routes[i].Upstream
		if up == nil {
			continue
		}

		host := c.Routes[i].Host

		for k, v := range up.Headers {
			out, err, emptyVars := expandEnvVars(v)
			if err != nil {
				return fmt.Errorf(
					"route %s: upstream.headers[%q]: %v",
					host, k, err,
				)
			}
			if emptyVars != nil {
				// Variable présente mais vide (typiquement absente
				// du .env, injectée en "" par compose) : en-tête
				// retiré plutôt qu'un parasite « Basic » tronqué.
				// Non fatal — l'upstream répondra 401 et les autres
				// sites restent en service.
				log.Printf(
					"CONFIG WARNING route %s: upstream.headers[%q]: variable(s) vide(s): %s — en-tête retiré (site cible répondra 401)",
					host, k, strings.Join(emptyVars, ", "),
				)
			}
			up.Headers[k] = out
		}

		if up.ResponseHeaders == nil {
			continue
		}

		for k, v := range up.ResponseHeaders.Set {
			out, err, emptyVars := expandEnvVars(v)
			if err != nil {
				return fmt.Errorf(
					"route %s: upstream.responseHeaders.set[%q]: %v",
					host, k, err,
				)
			}
			if emptyVars != nil {
				log.Printf(
					"CONFIG WARNING route %s: upstream.responseHeaders.set[%q]: variable(s) vide(s): %s — en-tête retiré",
					host, k, strings.Join(emptyVars, ", "),
				)
			}
			up.ResponseHeaders.Set[k] = out
		}
	}

	return nil
}

// validate rejects configs that cannot work at runtime — fail fast at
// load instead of silently caching what should have been excluded.
func (c *Config) validate() error {
	for i := range c.Routes {
		host := c.Routes[i].Host
		route := &c.Routes[i]

		if route.GuardActive() && c.LoginURLFor(route) == "" {
			return fmt.Errorf(
				"route %s: garde active sans URL de login (bloc oidc.loginUrl ou authGuard.loginUrl requis)",
				host)
		}

		if route.MCPActive() && (c.OIDC == nil || c.OIDC.Issuer == "") {
			return fmt.Errorf(
				"route %s: MCP actif sans oidc.issuer (metadata OAuth : authorization_servers)",
				host)
		}

		if p := route.PWA; p != nil {
			for _, pat := range p.networkOnlyPatterns() {
				if _, err := regexp.Compile(pat); err != nil {
					return fmt.Errorf(
						"route %s: expression invalide dans les exclusions PWA %q: %v",
						host, pat, err)
				}
			}
		}

		if rb := c.Routes[i].UpstreamRewriteBody(); rb != nil {
			if err := validateRewriteBody(rb); err != nil {
				return fmt.Errorf("route %s: %v", host, err)
			}
		}

		if up := c.Routes[i].Upstream; up != nil && up.RewriteCookies != nil {
			if up.RewriteCookies.Domain != "rewrite" &&
				up.RewriteCookies.Domain != "strip" {
				return fmt.Errorf(
					"route %s: rewriteCookies.domain %q (attendu \"rewrite\" ou \"strip\")",
					host, up.RewriteCookies.Domain)
			}
		}
	}
	return nil
}

// UpstreamRewriteBody : accesseur de la policy rewriteBody d'une route
// (nil si absente ou désactivée).
func (r *Route) UpstreamRewriteBody() *RewriteBodyPolicy {
	if r.Upstream == nil || r.Upstream.RewriteBody == nil ||
		!r.Upstream.RewriteBody.Enabled {
		return nil
	}
	return r.Upstream.RewriteBody
}

// bornes d'une configuration except : la fenêtre de réécriture du
// moteur en flux (et du SW client) est proportionnelle au préfixe
// d'origine + au préfixe d'exception le plus long — elles restent
// petites et les configurations déraisonnables sont refusées au load.
const (
	maxRewriteExcepts = 64
	maxRewritePathLen = 256
)

func validateRewriteBody(rb *RewriteBodyPolicy) error {
	if len(rb.Except) > maxRewriteExcepts {
		return fmt.Errorf(
			"rewriteBody.except: %d entrées (max %d)",
			len(rb.Except), maxRewriteExcepts,
		)
	}
	seen := make(map[string]bool, len(rb.Except))
	for i := range rb.Except {
		e := &rb.Except[i]
		if e.Path == "" {
			return fmt.Errorf(
				"rewriteBody.except[%d]: path vide", i)
		}
		if !strings.HasPrefix(e.Path, "/") {
			return fmt.Errorf(
				"rewriteBody.except[%d]: path %q ne commence pas par '/'", i, e.Path)
		}
		if strings.ContainsAny(e.Path, "?#") {
			return fmt.Errorf(
				"rewriteBody.except[%d]: path %q contient '?' ou '#' (préfixe de chemin uniquement)", i, e.Path)
		}
		if len(e.Path) > maxRewritePathLen {
			return fmt.Errorf(
				"rewriteBody.except[%d]: path %d octets (max %d)",
				i, len(e.Path), maxRewritePathLen)
		}
		e.Path = strings.TrimRight(e.Path, "/")
		if e.Path == "" {
			return fmt.Errorf(
				"rewriteBody.except[%d]: path \"/\" (préfixe racine interdit : il excepterait tout)", i)
		}
		if seen[e.Path] {
			return fmt.Errorf(
				"rewriteBody.except[%d]: path %q déclaré deux fois", i, e.Path)
		}
		seen[e.Path] = true
		if e.To == "" {
			continue
		}
		// To : base de réécriture alternative "https://host" — les
		// slashs finaux sont retirés (le chemin d'origine suit).
		for strings.HasSuffix(e.To, "/") {
			e.To = strings.TrimSuffix(e.To, "/")
		}
		u, err := url.Parse(e.To)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return fmt.Errorf(
				"rewriteBody.except[%d]: to %q n'est pas une URL absolue (https://host, http://host en démo)", i, e.To)
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return fmt.Errorf(
				"rewriteBody.except[%d]: to %q doit être en http(s)", i, e.To)
		}
	}
	return nil
}

// AsciiJSON marshalise v et échappe TOUT caractère non-ASCII en
// \uXXXX : les payloads injectés (script de garde, service worker)
// restent décodables quel que soit l'encodage déclaré — ou omis — par
// le site qui les reçoit. fallback si Marshal échoue (impossible sur
// ces structs).
func AsciiJSON(v any, fallback string) string {
	b, err := json.Marshal(v)
	if err != nil {
		return fallback
	}

	var sb strings.Builder
	for _, r := range string(b) {
		switch {
		case r < 0x80:
			sb.WriteRune(r)
		case r <= 0xFFFF:
			fmt.Fprintf(&sb, `\u%04x`, r)
		default:
			r -= 0x10000
			fmt.Fprintf(&sb, `\u%04x\u%04x`,
				0xD800+(r>>10),
				0xDC00+(r&0x3FF),
			)
		}
	}
	return sb.String()
}
