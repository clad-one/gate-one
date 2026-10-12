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
		manifest["icons"] = []map[string]any{
			{
				"src":   h.policy.Icon,
				"sizes": "192x192",
				"type":  "image/png",
			},
		}
	}

	data, _ := json.MarshalIndent(manifest, "", "  ")
	return data
}

// swJS is the gateway-generated service worker. Workbox is loaded from
// the self-hosted copy embedded below (modulePathPrefix), never from a
// CDN. Auth traffic is explicitly NetworkOnly so the service worker
// never caches or intercepts Keycloak/auth-bridge exchanges.
func (h *Handler) swJS() string {
	return `// Généré par la gateway — workbox ` + workboxVersion + ` auto-hébergé
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
}
`
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
