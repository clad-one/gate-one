// Package pwa implements the declarative PWA wrap of frontend routes:
// it serves /__gateway_pwa/manifest.json, /__gateway_pwa/sw.js and the
// self-hosted Workbox runtime (embedded in the binary, nothing is
// fetched from storage.googleapis.com at runtime — Workbox is MIT
// licensed, see workbox/LICENSE).
package pwa

import (
	"crypto/sha256"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"strings"

	"cladone/gateway/internal/core"
)

// Virtual prefix served by the gateway itself, before any route proxying.
const PathPrefix = "/__gateway_pwa/"

//go:embed workbox
var workboxFS embed.FS

// workboxVersion must match the vendored build in workbox/.
const workboxVersion = "7.4.1"

// apiCacheLogicVersion versionne le FORMAT des entrées du cache API
// (forme de la clé, en-têtes stockés, logique de storeCompleteResponse).
// L'incrémenter quand la logique de stockage change : les caches
// existants seront purgés à l'activation du nouveau SW. Il est
// volontairement indépendant du hash du SW, pour qu'un déploiement qui
// ne touche pas ce format ne vide pas le replay offline.
const apiCacheLogicVersion = "1"

// apiCachePolicyJSON sérialise la politique déclarative d'un endpoint
// apiCache pour le hash de son cache : toute reconfiguration du bloc
// dans api-routes.json change le hash, donc le nom du cache.
func apiCachePolicyJSON(c any) []byte {
	data, _ := json.Marshal(c)
	return data
}

type Handler struct {
	policy *core.PWAPolicy
}

func New(policy *core.PWAPolicy) *Handler {
	return &Handler{policy: policy}
}

func (h *Handler) manifest() []byte {

	name := h.policy.Name
	if name == "" {
		name = "Cladone"
	}

	short := h.policy.ShortName
	if short == "" {
		short = name
	}

	theme := h.policy.ThemeColor
	if theme == "" {
		theme = "#4285f4"
	}

	manifest := map[string]any{
		"name":             name,
		"short_name":       short,
		"start_url":        "/",
		"scope":            "/",
		"display":          "standalone",
		"background_color": "#ffffff",
		"theme_color":      theme,
	}

	if h.policy.Icon != "" {
		h.policy.Icons = append(h.policy.Icons, h.policy.Icon)
	}

	if len(h.policy.Icons) > 0 {
		icons := make([]map[string]any, 0, len(h.policy.Icons))
		for _, src := range h.policy.Icons {
			icons = append(icons, map[string]any{
				"src":   src,
				"sizes": pwaIconSizes(src),
				"type":  "image/png",
			})
		}
		manifest["icons"] = icons
	}

	data, _ := json.MarshalIndent(manifest, "", "  ")
	return data
}

// swJS is the gateway-generated service worker. Workbox is loaded from
// the self-hosted copy embedded below (modulePathPrefix), never from a
// CDN. Auth traffic is explicitly NetworkOnly so the service worker
// never caches or intercepts Keycloak/auth-bridge exchanges. When the
// route declares an apiCache policy, API responses (POST/SSE included)
// are cached keyed by request and replayed offline.
func (h *Handler) swJS() string {
	// Passe 1 : générer le corps avec le placeholder CACHE_VERSION.
	// Ce hash ne versionne que ASSETS_CACHE (pages/scripts/styles).
	// Les caches API sont versionnés indépendamment, par endpoint :
	// cf. apiCacheRouteJS (hash du bloc de config + apiCacheLogicVersion)
	// pour que le replay offline survive aux déploiements sans rapport.
	body := `importScripts('` + PathPrefix + `workbox/workbox-sw.js');

workbox.setConfig({ modulePathPrefix: '` + PathPrefix + `workbox/' });

// Version de l'ensemble des caches = hash du contenu même de ce SW :
// tout changement (config, générateur, champ version d'un apiCache)
// change le hash => nouveaux noms de caches => purge des anciens à
// l'activation. Aucun changement => mêmes caches, le replay offline
// survit aux fermetures d'onglets.
const CACHE_VERSION = '@@CACHE_VERSION@@';
const ASSETS_CACHE = 'gateway-pwa-assets-' + CACHE_VERSION;

// prend la main dès l'installation : la mise à jour est effective au
// chargement suivant, sans attendre la fermeture de tous les onglets
self.skipWaiting();

self.addEventListener('activate', (event) => {
  event.waitUntil(
    self.clients.claim()
      .then(() => caches.keys())
      .then((keys) =>
        Promise.all(
          keys
            // Purger uniquement les caches dont on connaît le régime de
            // version : assets = hash du SW (CACHE_VERSION) ; api = la
            // version est encodée dans le nom (v<logique>-<hash>) et la
            // purge par CACHE_VERSION ne doit PAS les toucher — seuls
            // les caches API au format périmé sont supprimés.
            .filter((k) =>
              (k.startsWith('gateway-pwa-assets-') && !k.includes(CACHE_VERSION)) ||
              (k.startsWith('gateway-pwa-api-') &&
               !/^gateway-pwa-api-.*-v\d+-[0-9a-f]{8}$/.test(k))
            )
            .map((k) => caches.delete(k))
        )
      )
  );
});

if (workbox) {
  // Stratégie pour les pages et les assets, déclarée dans la politique
  // pwa.assets de la route (défaut : staleWhileRevalidate — le cache
  // répond instantanément, le réseau rafraîchit en arrière-plan ; le
  // CACHE_VERSION purgé à l'activation garantit la fraîcheur après
  // déploiement).
  workbox.routing.registerRoute(
    ({request}) => request.destination === 'document' || request.destination === 'script' || request.destination === 'style',
    new workbox.strategies.ASSETS_STRATEGY({
      cacheName: ASSETS_CACHE@@ASSETS_OPTIONS@@
    })
  );
  // marqueur diagnostic étape 1: assets route enregistrée
  caches.open('gateway-pwa-debug').then((c) => c.put('/step1-assets-route', new Response('ok')));
@@NETWORK_ONLY@@
  // marqueur diagnostic étape 2: routes d'exclusion enregistrées, apiCache va démarrer
  caches.open('gateway-pwa-debug').then((c) => c.put('/step2-before-apicache', new Response('ok')));
` + h.apiCacheJS() + `
  // marqueur de diagnostic: le SW a chargé toutes ses routes
  caches.open('gateway-pwa-debug').then((c) => c.put('/__routes_loaded', new Response('ok')));
  }
self.addEventListener('fetch', () => {}); // no-op: forcer l'attachement du listener
`

	// Stratégie des assets, déclarative (pwa.assets).
	strategy, timeout := h.policy.EffectiveAssets()
	opts := ""
	if timeout > 0 {
		opts = ",\n      networkTimeoutSeconds: " + fmtInt(timeout)
	}
	// La politique résolue donne déjà le nom exact de la classe
	// workbox (cf. EffectiveAssets).
	body = strings.ReplaceAll(body, "ASSETS_STRATEGY", strategy)
	body = strings.ReplaceAll(body, "@@ASSETS_OPTIONS@@", opts)

	// Exclusions réseau-seul, déclaratives (pwa.networkOnly) — rien
	// n'est en dur : quelles URLs ne jamais cacher est un choix de
	// déploiement (la gateway supporte tout serveur d'authentification).
	body = strings.ReplaceAll(body, "@@NETWORK_ONLY@@", h.networkOnlyJS())

	// Passe 2 : hash du corps (placeholder inclus), puis substitution.
	version := fmt.Sprintf("%x", sha256.Sum256([]byte(body)))[:8]
	body = strings.ReplaceAll(body, "@@CACHE_VERSION@@", version)

	js := `// Généré par la gateway — workbox ` + workboxVersion + ` auto-hébergé
// version caches: ` + version + "\n" + body
	return js
}

// networkOnlyJS generates the "never cache" catch-all route declared
// by pwa.networkOnly (empty output when absent): every URL matching one
// of the declared patterns goes straight to the network. The route is
// registered after assets and before the apiCaches/catch-all routes
// (first matching route wins), so an excluded URL reaches no cache.
func (h *Handler) networkOnlyJS() string {
	no := h.policy.NetworkOnly
	if no == nil || len(no.ExcludePatterns) == 0 {
		return ""
	}

	var decls, tests strings.Builder
	for i, pat := range no.ExcludePatterns {
		if pat == "" {
			continue
		}
		decls.WriteString("\n  const NO_CACHE_RE_" + fmtInt(i) + " = new RegExp(" + fmtJSLit(pat) + ");")
		if tests.Len() > 0 {
			tests.WriteString(" || ")
		}
		tests.WriteString("NO_CACHE_RE_" + fmtInt(i) + ".test(url.href)")
	}

	return decls.String() + `
  // URLs déclarées networkOnly (pwa.networkOnly) : jamais cachées,
  // jamais rejouées — authentification, callbacks OAuth/OIDC avec codes
  // à usage unique, tout ce que la configuration du déploiement exclut.
  workbox.routing.registerRoute(
    ({url}) => ` + tests.String() + `,
    new workbox.strategies.NetworkOnly()
  );` + "\n"
}

// apiCacheJS generates the offline-replay routes for the declared API
// cache policies (one block per endpoint). The response is streamed to
// the app via one tee branch while the other branch accumulates and is
// only written to the cache once the stream completes cleanly (partial
// SSE responses are never cached). Keyed by URL + body so identical
// POST payloads replay. Each policy gets its own ExpirationPlugin and
// size guard.
func (h *Handler) apiCacheJS() string {
	caches := core.EffectiveApiCaches(h.policy)
	if len(caches) == 0 && h.policy.ApiGETCache == nil {
		return ""
	}

	var sb strings.Builder
	// Shared helpers, defined once.
	sb.WriteString(`
  // Clé de cache explicite : Cache Storage ignore le corps des requêtes
  // POST dans sa clé (toutes les segmentations s'écraseraient), donc le
  // corps est hashé dans un paramètre artificiel de l'URL.
  async function buildCacheKey(url, bodyText, method) {
    let key = url;
    if (bodyText) {
      const digest = await crypto.subtle.digest('SHA-256',
        new TextEncoder().encode(bodyText));
      const hex = [...new Uint8Array(digest)]
        .map((b) => b.toString(16).padStart(2, '0')).join('');
      key = url + (url.includes('?') ? '&' : '?')
        + '__pwa_key=' + hex + '&__pwa_m=' + method;
    }
    return new Request(key);
  }

  // fetch avec un abort limité à l'attente des HEADERS : dès que la
  // réponse (headers) arrive, le listener abort est retiré et le
  // streaming de la réponse peut durer librement. Un abort n'est
  // donc possible qu'avant toute réponse : DNS/TCP down, serveur
  // muet. Renvoie {response, error} sans lever : le catch du
  // handler décide du replay selon response.ok ou error.
  async function fetchNetwork(req, timeoutSec) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutSec * 1000);
    const done = () => clearTimeout(timer);
    controller.signal.addEventListener('abort', done, { once: true });
    try {
      const response = await fetch(req, { signal: controller.signal });
      done();
      return { response: response, error: null };
    } catch (err) {
      done();
      return { response: null, error: err };
    }
  }

  // Accumule la branche du tee et écrit dans le cache : à la fin propre
  // du flux, OU après 1,5 s sans nouveau chunk (les SSE ne se ferment
  // pas toujours : attendre done indéfiniment ne cacherait jamais
  // rien). Les réponses dépassant maxEntrySizeBytes ne sont pas cachées.
  async function storeCompleteResponse(cache, cacheName, request, stream, expiration, maxSize, idleMs) {
    try {
      let size = 0;
      const parts = [];
      const reader = stream.getReader();
      for (;;) {
        const timeout = new Promise((resolve) => {
          setTimeout(() => resolve({done: true, value: undefined, idle: true}), idleMs);
        });
        const {done, value, idle} = await Promise.race([reader.read(), timeout]);
        if (idle && parts.length > 0) break; // silence prolongé : finaliser
        if (done) break;
        size += value.byteLength;
        if (maxSize > 0 && size > maxSize) {
          await reader.cancel();
          return; // réponse trop volumineuse : pas de cache
        }
        parts.push(value);
      }
      const blob = new Blob(parts);
      const response = new Response(blob, {
        status: 200,
        headers: {'Content-Type': 'text/event-stream'},
      });
      await cache.put(request, response);
      console.log('[gateway-pwa] cache API écrit:', request.url, size + ' octets');
      await expiration.cacheDidUpdate({
        cacheName: cacheName,
        request: request,
        oldResponse: null,
        newResponse: response,
      });
    } catch (err) {
      console.error('[gateway-pwa] cache API ÉCHEC:', err && err.message);
      // flux annulé ou interrompu, ou quota dépassé : rien n'est caché
    }
  }
`)

	for _, c := range caches {
		if c.Path == "" {
			continue
		}
		// method "none" : le path est explicitement hors cache — pas de
		// route générée ; la catch-all l'ignore déjà (path déclaré =
		// maître de son path, toutes méthodes).
		if strings.EqualFold(strings.TrimSpace(c.Method), "none") {
			continue
		}
		sb.WriteString(h.apiCacheRouteJS(c))
	}
	if h.policy.ApiGETCache != nil {
		sb.WriteString(h.apiGETCatchAllJS(caches))
	}
	return sb.String()
}

// apiGETCatchAllJS generates the universal no-config GET catch-all.
// It must be registered AFTER the explicit apiCaches[] routes (the
// first matching route wins), and never matches a declared endpoint's
// path — an endpoint declared in apiCaches[] is master of its path
// for every method. Assets (documents/scripts/styles) are already
// covered by the SWR assets route, registered even earlier.
func (h *Handler) apiGETCatchAllJS(declared []*core.PWAApiCache) string {
	all := h.policy.ApiGETCache

	// Défauts catch-all (sans config déclarable pour l'instant).
	const (
		allMaxEntries = 200
		allMaxAgeSec  = 86400
		allMaxSize    = 2 << 20 // 2 MiB par entrée
		allTimeoutSec = 3
	)

	cacheName := "gateway-pwa-api-all"
	// Versionnement : hash du bloc de configuration (excludes inclus)
	// + la version logique commune. Reconfigurer la catch-all
	// n'invalide pas les caches des endpoints explicites, et inversement.
	polHash := fmt.Sprintf("%x", sha256.Sum256(apiCachePolicyJSON(all)))[:8]
	cacheName += "-v" + apiCacheLogicVersion + "-" + polHash

	// Filtre d'exclusion : préfixe virtuel de la gateway, préfixes
	// déclarés, paths des endpoints déclarés (variante A : un endpoint
	// déclaré est maître de son path, toutes méthodes), et expressions
	// régulières testées contre l'URL COMPLÈTE (pathname + query — un
	// paramètre particulier peut disqualifier une requête).
	excludes := []string{PathPrefix}
	excludes = append(excludes, all.Excludes...)
	for _, c := range declared {
		excludes = append(excludes, c.Path)
	}
	var checks strings.Builder
	for _, ex := range excludes {
		if ex == "" {
			continue
		}
		checks.WriteString(" && !url.pathname.startsWith(" + fmtJSLit(ex) + ")")
	}
	if checks.Len() == 0 {
		checks.WriteString(" && true")
	}
	patternDecls := ""
	patternTests := ""
	for i, pat := range all.ExcludePatterns {
		if pat == "" {
			continue
		}
		// Déclaration d'une RegExp nommée (l'index suffit à l'unicité
		// dans le scope du SW) + test contre l'URL complète.
		patternDecls += "\n  const EXCLUDE_RE_" + fmtInt(i) + " = new RegExp(" + fmtJSLit(pat) + ");"
		patternTests += " && !EXCLUDE_RE_" + fmtInt(i) + ".test(url.href)"
	}

	return `
  // Cache GET universel (apiGETCache) : les requêtes GET que
  // rien d'autre ne couvre (fetch data API, images, fonts). SWR :
  // le cache répond immédiatement, le réseau rafraîchit en fond ;
  // hors ligne -> le cache. Un path déclaré dans apiCaches[] est
  // maître de son path (toutes méthodes) et n'atteint pas ce bloc ;
  // les excludesPatterns sont des RegExp testées contre l'URL
  // complète (pathname + query). Défauts : ` + fmtInt(allMaxEntries) + ` entrées,
  // ` + fmtInt(allMaxAgeSec) + `s, ` + fmtInt64(allMaxSize) + ` octets max, abort ` + fmtInt(allTimeoutSec) + ` s.
  const exp_api_all = new workbox.expiration.ExpirationPlugin({
    maxEntries: ` + fmtInt(allMaxEntries) + `,
    maxAgeSeconds: ` + fmtInt(allMaxAgeSec) + `,
    purgeOnQuotaError: true
  });` + patternDecls + `

  workbox.routing.registerRoute(
    ({url}) => url.pathname.startsWith('/')` + checks.String() + patternTests + `,
    async ({event}) => {
      const req = event.request;
      if (req.method !== 'GET') {
        // la catch-all ne matche que les GET (méthode 'GET' déclarée
        // ci-dessous) — garde-fou défensif pour les GET d'URL
        // exotiques (about:, blob:) déjà exclus par workbox.
        return fetch(req);
      }
      console.log('[gateway-pwa] apiGETCache intercepté:', req.url);
      const cache = await caches.open('` + cacheName + `');
      const hit = await cache.match(req);
      const refresh = () => fetchNetwork(req, ` + fmtInt(allTimeoutSec) + `).then(({response}) => {
        if (!response || !response.ok || !response.body
            || response.headers.has('set-cookie')) return;
        event.waitUntil(response.arrayBuffer().then((buf) =>
          cache.put(req, new Response(buf, {
            status: response.status,
            statusText: response.statusText,
            headers: response.headers,
          }))
        ));
      }).catch(() => {});
      if (hit) {
        refresh();
        return hit;
      }
      const { response, error } = await fetchNetwork(req, ` + fmtInt(allTimeoutSec) + `);
      if (error) throw error;
      if (response.ok && response.body && !response.headers.has('set-cookie')) {
        const clone = response.clone();
        event.waitUntil(clone.arrayBuffer().then((buf) =>
          cache.put(req, new Response(buf, {
            status: clone.status,
            statusText: clone.statusText,
            headers: clone.headers,
          }))
        ));
      }
      return response;
    },
    'GET'
  );
`
}

// apiCacheRouteJS generates one endpoint's route + expiration plugin.
// Method "GET" generates a stale-while-revalidate route (cache answers
// instantly, network refreshes in the background); method "POST" (or
// empty) generates the network-first offline replay.
func (h *Handler) apiCacheRouteJS(c *core.PWAApiCache) string {
	maxEntries := c.MaxEntries
	if maxEntries <= 0 {
		maxEntries = 50
	}
	maxAge := c.MaxAgeSeconds
	if maxAge <= 0 {
		maxAge = 86400
	}
	maxSize := c.MaxEntrySizeBytes
	if maxSize <= 0 {
		maxSize = 2 << 20 // 2 MiB per entry
	}
	idleMs := c.IdleFinalizeMs
	if idleMs <= 0 {
		idleMs = 1500 // finalisation du cache après ce silence du flux
	}
	netTimeout := c.NetworkTimeoutSeconds
	if netTimeout <= 0 {
		netTimeout = 3 // abort du fetch sans réponse au bout de 3 s
	}
	method := strings.ToUpper(c.Method)
	if method != "GET" {
		method = "POST" // défaut (et compat) : replay network-first
	}
	// offlineFastPath : POST seulement (pour un GET, SWR sert déjà le
	// caché immédiatement — sans objet).
	offlineFast := method == "POST" &&
		(c.OfflineFastPath == nil || *c.OfflineFastPath)

	cacheName := "gateway-pwa-api-" + strings.TrimPrefix(c.Path, "/")
	if c.Version != "" {
		cacheName += "-" + c.Version
	}
	cacheName = strings.ReplaceAll(cacheName, "/", "-")

	// Versionnement par endpoint : le nom incorpore le hash du bloc de
	// configuration JSON de CET endpoint (pas du SW entier). Reconfigurer
	// ce worker dans api-routes.json invalide son cache, et lui seul ;
	// le replay des autres endpoints et les caches assets survivent à un
	// déploiement. apiCacheLogicVersion est incrémenté manuellement quand
	// le format des entrées stockées change.
	polHash := fmt.Sprintf("%x", sha256.Sum256(apiCachePolicyJSON(c)))[:8]
	cacheName += "-v" + apiCacheLogicVersion + "-" + polHash

	return `
  // Cache API déclaratif : ` + c.Path + ` (méthode ` + method + `).
  // ` + fmtInt(maxEntries) + ` entrées max, ` + fmtInt(maxAge) + `s,
  // ` + fmtInt64(maxSize) + ` octets max par entrée,
  // offlineFastPath: ` + jsBool(offlineFast) + ` (POST only).
  const OFFLINE_FAST_` + jsIdent(c.Path) + ` = ` + jsBool(offlineFast) + `; // POST only
  const exp_` + jsIdent(c.Path) + ` = new workbox.expiration.ExpirationPlugin({
    maxEntries: ` + fmtInt(maxEntries) + `,
    maxAgeSeconds: ` + fmtInt(maxAge) + `,
    purgeOnQuotaError: true
  });

  workbox.routing.registerRoute(
    ({url}) => url.pathname === '` + c.Path + `',
    async ({event}) => {
      console.log('[gateway-pwa] route apiCache interceptée:', event.request.method, event.request.url);
      const req = event.request;
      const cache = await caches.open('` + cacheName + `');` + func() string {
		if method == "GET" {
			return `
      // SWR : le cache répond immédiatement (même en ligne), le
      // réseau rafraîchit en fond ; offline strict -> le cache.
      // Clé = URL seule (pas de corps pour un GET). Les réponses
      // non-200 ou avec Set-Cookie ne sont pas mises en cache.
      const hit = await cache.match(req);
      const refresh = () => fetchNetwork(req, ` + fmtInt(netTimeout) + `).then(({response}) => {
        if (!response || !response.ok || response.headers.has('set-cookie')) return;
        // réponse opaque ou vide : rien à stocker
        if (!response.body) return;
        event.waitUntil(response.arrayBuffer().then((buf) =>
          cache.put(req, new Response(buf, {
            status: response.status,
            statusText: response.statusText,
            headers: response.headers,
          }))
        ));
      }).catch(() => {});
      if (hit) {
        refresh();
        return hit;
      }
      const { response, error } = await fetchNetwork(req, ` + fmtInt(netTimeout) + `);
      if (error) throw error;
      if (response.ok && response.body && !response.headers.has('set-cookie')) {
        const clone = response.clone();
        event.waitUntil(clone.arrayBuffer().then((buf) =>
          cache.put(req, new Response(buf, {
            status: clone.status,
            statusText: clone.statusText,
            headers: clone.headers,
          }))
        ));
      }
      return response;`
		}
		return `
      // Clé de cache explicite : Cache Storage ignore le corps des POST
      // dans sa clé (toutes les segmentations s'écraseraient), donc on
      // hashe l'URL + le corps dans un paramètre artificiel.
      // IMPORTANT : construite AVANT le fetch — le corps d'une requête
      // ne peut être lu qu'une fois, et après un fetch échoué (offline)
      // req.clone().text() throwerait "Failed to fetch" au lieu du
      // replay attendu.
      let keyReq = null;
      try {
        const bodyText = req.method === 'GET' ? '' : await req.clone().text();
        keyReq = await buildCacheKey(req.url, bodyText, req.method);
        // Diagnostic de clé : la clé = SHA-256 du corps. Deux
        // segmentations "identiques" aux yeux de l'utilisateur mais
        // avec une clé différente => un champ du corps a changé.
        // Logguer le corps permet de voir immédiatement LE champ en
        // cause (phonetic, meters, espace en fin de texte...).
        console.log('[gateway-pwa] clé:', keyReq.url.slice(keyReq.url.indexOf('__pwa_key=')),
          '\n  corps:', bodyText);
      } catch (e) { keyReq = null; } // corps illisible : pas de replay
      try {
        // Hors ligne (l'OS le sait : wifi coupé, avion) : pas de
        // fetch du tout, le cache répond immédiatement (fast-path,
        // offlineFastPath: true par défaut ; false pour un endpoint
        // où rejouer un caché serait faux, p.ex. une écriture).
        // En ligne : fetch d'abord (fraîcheur), aborté au bout de
        // networkTimeoutSeconds si aucune réponse — le replay ne
        // subit plus le timeout TCP complet (~5 s) d'un réseau mort.
        // Le timeout ne couvre QUE l'attente des headers : le
        // listener est retiré dès que la réponse arrive, le
        // streaming de la réponse elle-même reste libre.
        if (OFFLINE_FAST_` + jsIdent(c.Path) + ` && !self.navigator.onLine) {
          const offlineHit = keyReq ? await cache.match(keyReq) : null;
          if (offlineHit) {
            console.log('[gateway-pwa] replay offline (onLine=false):', keyReq.url);
            return offlineHit;
          }
          // rien de caché : tenter le fetch malgré tout (offline
          // pas toujours détecté, p.ex. serveur local)
        }
        const { response, error } = await fetchNetwork(req, ` + fmtInt(netTimeout) + `);
        if (error) throw error;
        if (response.ok && response.body) {
          const [toApp, toCache] = response.body.tee();
          // event.waitUntil est INDISPENSABLE : sans lui, le navigateur
          // peut suspendre le SW dès que la réponse est renvoyée, avant
          // que l'accumulation + cache.put ne finissent (le cache API
          // ne serait jamais écrit, surtout sur Firefox).
          if (keyReq) {
            event.waitUntil(
              storeCompleteResponse(cache, ` + fmtJSLit(cacheName) + `, keyReq, toCache, exp_` + jsIdent(c.Path) + `, ` + fmtInt64(maxSize) + `, ` + fmtInt(idleMs) + `)
            );
          }
          return new Response(toApp, {
            status: response.status,
            statusText: response.statusText,
            headers: response.headers,
          });
        }
        return response;
      } catch (err) {
        // hors ligne (ou réseau instable) : rejouer la réponse
        // précédemment stockée pour cette requête exacte
        if (keyReq) {
          const cached = await cache.match(keyReq);
          if (cached) {
            console.log('[gateway-pwa] replay offline:', keyReq.url);
            return cached;
          }
          console.warn('[gateway-pwa] pas de cache pour cette requête:', keyReq.url);
        }
        throw err;
      }`
	}() + `
    },
    // Cache Storage ignore les POST dans sa clé et workbox route les
    // requêtes non-GET SEULEMENT si la méthode est explicite (Route
    // constructor, method défaut "GET") : sans le 3e argument pour un
    // POST, la route ne matchait aucun POST => "No route found",
    // replay impossible.
    '` + method + `'
  );
`
}

// jsBool rend un booléen Go en littéral JS.
func jsBool(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// jsIdent convertit un chemin en identifiant JS utilisable.
func jsIdent(path string) string {
	ident := strings.TrimPrefix(path, "/")
	ident = strings.ReplaceAll(ident, "/", "_")
	ident = strings.ReplaceAll(ident, "-", "_")
	// préfixe si le premier caractère n'est pas une lettre
	if ident == "" || (ident[0] < 'a' || ident[0] > 'z') && (ident[0] < 'A' || ident[0] > 'Z') {
		ident = "api_" + ident
	}
	return ident
}

// fmtJSLit rend une chaîne Go en littéral JS (chemins contrôlés côté
// générateur : pas de caractères d'échappement attendus).
func fmtJSLit(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "\\'") + "'"
}

// fmtInt évite d'importer strconv pour deux entiers du template.
func fmtInt64(n int64) string {
	return fmtInt(int(n))
}

func fmtInt(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

// pwaIconSizes déduit la taille déclarée du nom de fichier
// (icon-192.png => "192x192"). Défaut : "512x512".
func pwaIconSizes(src string) string {
	for _, size := range []string{"512", "384", "256", "192", "144", "96"} {
		if strings.Contains(src, size) {
			return size + "x" + size
		}
	}
	return "512x512"
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	rest := strings.TrimPrefix(r.URL.Path, PathPrefix)

	switch rest {
	case "manifest.json":
		w.Header().Set("Content-Type", "application/manifest+json")
		w.Header().Set("Cache-Control", "no-cache")
		_, _ = w.Write(h.manifest())
		return

	case "sw.js":
		// A service worker must never be cached stale; the browser
		// re-checks it to detect updates.
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		// The SW is registered from a page on "/" scope; registering
		// from /__gateway_pwa/ would otherwise limit its scope.
		w.Header().Set("Service-Worker-Allowed", "/")
		_, _ = w.Write([]byte(h.swJS()))
		return
	}

	// Vendored Workbox runtime: /__gateway_pwa/workbox/<file>
	if strings.HasPrefix(rest, "workbox/") {
		name := strings.TrimPrefix(rest, "workbox/")
		name = strings.TrimPrefix(name, "/")
		if name == "" || strings.Contains(name, "..") {
			http.NotFound(w, r)
			return
		}

		data, err := fs.ReadFile(workboxFS, "workbox/"+name)
		if err != nil {
			http.NotFound(w, r)
			return
		}

		ct := "application/javascript"
		if strings.HasSuffix(name, ".map") {
			ct = "application/json"
		}
		w.Header().Set("Content-Type", ct)
		// Immutable: versioned build files (path contains the version).
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		_, _ = w.Write(data)
		return
	}

	http.NotFound(w, r)
}
