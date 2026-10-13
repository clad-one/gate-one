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
	// Passe 1 : générer le corps avec le placeholder CACHE_VERSION ;
	// le hash porte sur ce texte (la politique effective y est déjà,
	// via apiCacheJS et ses noms/versions de caches).
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
    caches.keys().then((keys) =>
      Promise.all(
        keys
          .filter((k) => k.startsWith('gateway-pwa-') && !k.includes(CACHE_VERSION))
          .map((k) => caches.delete(k))
      ).then(() => self.clients.claim())
    )
  );
});

if (workbox) {
  // Stratégie pour les pages et les assets (Mode déconnecté de base)
  workbox.routing.registerRoute(
    ({request}) => request.destination === 'document' || request.destination === 'script' || request.destination === 'style',
    new workbox.strategies.NetworkFirst({
      cacheName: ASSETS_CACHE,
    })
  );

  // Sécurité : Ignorer explicitement toutes les requêtes d'authentification
  workbox.routing.registerRoute(
    ({url}) => url.pathname.includes('/protocol/openid-connect') || url.pathname.includes('/auth'),
    new workbox.strategies.NetworkOnly()
  );
` + h.apiCacheJS() + `}
`

	// Passe 2 : hash du corps (placeholder inclus), puis substitution.
	version := fmt.Sprintf("%x", sha256.Sum256([]byte(body)))[:8]
	body = strings.ReplaceAll(body, "@@CACHE_VERSION@@", version)

	js := `// Généré par la gateway — workbox ` + workboxVersion + ` auto-hébergé
// version caches: ` + version + "\n" + body
	return js
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
	if len(caches) == 0 {
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

  // Accumule la branche du tee et écrit dans le cache : à la fin propre
  // du flux, OU après 1,5 s sans nouveau chunk (les SSE ne se ferment
  // pas toujours : attendre done indéfiniment ne cacherait jamais
  // rien). Les réponses dépassant maxEntrySizeBytes ne sont pas cachées.
  async function storeCompleteResponse(cache, request, stream, expiration, maxSize, idleMs) {
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
      await expiration.cacheDidUpdate({
        cacheName: cache._name,
        request: request,
        oldResponse: null,
        newResponse: response,
      });
    } catch (err) {
      // flux annulé ou interrompu, ou quota dépassé : rien n'est caché
    }
  }
`)

	for _, c := range caches {
		if c.Path == "" {
			continue
		}
		sb.WriteString(h.apiCacheRouteJS(c))
	}
	return sb.String()
}

// apiCacheRouteJS generates one endpoint's route + expiration plugin.
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

	cacheName := "gateway-pwa-api-" + strings.TrimPrefix(c.Path, "/")
	if c.Version != "" {
		cacheName += "-" + c.Version
	}
	cacheName = strings.ReplaceAll(cacheName, "/", "-")
	// @@CACHE_VERSION@@ est substitué par swJS (hash du SW entier) ;
	// le nom dépend donc aussi de toute la politique effective.
	cacheName += "-@@CACHE_VERSION@@"

	return `
  // Cache offline déclaratif : ` + c.Path + ` (réponses complètes seulement).
  // ` + fmtInt(maxEntries) + ` entrées max, ` + fmtInt(maxAge) + `s,
  // ` + fmtInt64(maxSize) + ` octets max par entrée,
  // finalisation après ` + fmtInt(idleMs) + ` ms de silence du flux.
  const exp_` + jsIdent(c.Path) + ` = new workbox.expiration.ExpirationPlugin({
    maxEntries: ` + fmtInt(maxEntries) + `,
    maxAgeSeconds: ` + fmtInt(maxAge) + `,
    purgeOnQuotaError: true
  });

  workbox.routing.registerRoute(
    ({url}) => url.pathname === '` + c.Path + `',
    async ({event}) => {
      const req = event.request;
      const cache = await caches.open('` + cacheName + `');
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
      } catch (e) { keyReq = null; } // corps illisible : pas de replay
      try {
        const response = await fetch(req);
        if (response.ok && response.body) {
          const [toApp, toCache] = response.body.tee();
          // event.waitUntil est INDISPENSABLE : sans lui, le navigateur
          // peut suspendre le SW dès que la réponse est renvoyée, avant
          // que l'accumulation + cache.put ne finissent (le cache API
          // ne serait jamais écrit, surtout sur Firefox).
          if (keyReq) {
            event.waitUntil(
              storeCompleteResponse(cache, keyReq, toCache, exp_` + jsIdent(c.Path) + `, ` + fmtInt64(maxSize) + `, ` + fmtInt(idleMs) + `)
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
          if (cached) return cached;
        }
        throw err;
      }
    }
  );
`
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
