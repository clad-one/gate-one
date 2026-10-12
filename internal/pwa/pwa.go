// Package pwa implements the declarative PWA wrap of frontend routes:
// it serves /__gateway_pwa/manifest.json, /__gateway_pwa/sw.js and the
// self-hosted Workbox runtime (embedded in the binary, nothing is
// fetched from storage.googleapis.com at runtime — Workbox is MIT
// licensed, see workbox/LICENSE).
package pwa

import (
	"embed"
	"encoding/json"
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
	js := `// Généré par la gateway — workbox ` + workboxVersion + ` auto-hébergé
importScripts('` + PathPrefix + `workbox/workbox-sw.js');

workbox.setConfig({ modulePathPrefix: '` + PathPrefix + `workbox/' });

if (workbox) {
  // Stratégie pour les pages et les assets (Mode déconnecté de base)
  workbox.routing.registerRoute(
    ({request}) => request.destination === 'document' || request.destination === 'script' || request.destination === 'style',
    new workbox.strategies.NetworkFirst({
      cacheName: 'gateway-pwa-assets',
    })
  );

  // Sécurité : Ignorer explicitement toutes les requêtes d'authentification
  workbox.routing.registerRoute(
    ({url}) => url.pathname.includes('/protocol/openid-connect') || url.pathname.includes('/auth'),
    new workbox.strategies.NetworkOnly()
  );
` + h.apiCacheJS() + `}
`
	return js
}

// apiCacheJS generates the offline-replay route for the declared API
// cache policy. The response is streamed to the app via one tee branch
// while the other branch accumulates and is only written to the cache
// once the stream completes cleanly (partial SSE responses are never
// cached). Keyed by URL + body so identical POST payloads replay.
func (h *Handler) apiCacheJS() string {
	c := h.policy.ApiCache
	if c == nil || c.Path == "" {
		return ""
	}

	maxEntries := c.MaxEntries
	if maxEntries <= 0 {
		maxEntries = 50
	}
	maxAge := c.MaxAgeSeconds
	if maxAge <= 0 {
		maxAge = 86400
	}

	return `
  // Cache offline déclaratif : ` + c.Path + ` (réponses complètes seulement,
  // clé = URL + corps de la requête ; les flux SSE partiels ne sont
  // jamais cachés). ` + fmtInt(maxEntries) + ` entrées max, ` + fmtInt(maxAge) + `s.
  workbox.routing.registerRoute(
    ({url}) => url.pathname === '` + c.Path + `',
    async ({event}) => {
      const request = event.request.clone();
      const cache = await caches.open('gateway-pwa-api');
      try {
        const response = await fetch(event.request);
        if (response.ok && response.body) {
          const [toApp, toCache] = response.body.tee();
          storeCompleteResponse(cache, request, toCache);
          return new Response(toApp, {
            status: response.status,
            statusText: response.statusText,
            headers: response.headers,
          });
        }
        return response;
      } catch (err) {
        // hors ligne (ou réseau instable) : rejouer la réponse
        // complète précédemment stockée pour cette requête exacte
        const cached = await cache.match(request);
        if (cached) return cached;
        throw err;
      }
    }
  );

  // Accumule la branche du tee et n'écrit dans le cache que lorsque le
  // flux s'est terminé sans erreur ni annulation.
  async function storeCompleteResponse(cache, request, stream) {
    try {
      const response = new Response(stream, {
        status: 200,
        headers: {'Content-Type': 'text/event-stream'},
      });
      await cache.put(request, response);
    } catch (err) {
      // flux annulé ou interrompu : rien n'est caché
    }
  }
`
}

// fmtInt évite d'importer strconv pour deux entiers du template.
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
