package core

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

type Match struct {
	Method string `json:"method,omitempty"`

	Query map[string]string `json:"query,omitempty"`

	Header map[string]string `json:"header,omitempty"`

	Body map[string]any `json:"body,omitempty"`

	Roles []string `json:"roles,omitempty"`

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
	// network-first offline replay of POST/SSE calls, or "GET" for a
	// stale-while-revalidate cache of that exact path (offline is
	// covered by SWR itself, so OfflineFastPath does not apply).
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
	// default, or "GET" for a SWR cache of that exact path — declared
	// endpoints are excluded from the apiGETCache catch-all for
	// every method).
	ApiCache  *PWAApiCache   `json:"apiCache,omitempty"`
	ApiCaches []*PWAApiCache `json:"apiCaches,omitempty"`
	// ApiGETCache, when present, adds a catch-all GET cache for
	// the requests nothing else covers (fetch() data calls, images,
	// fonts — anything the assets route does not match). Declared
	// apiCaches[] paths are excluded (an endpoint declared is master
	// of its path, every method); Excludes removes further prefixes.
	ApiGETCache *PWAApiGETCache `json:"apiGETCache,omitempty"`
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

type Route struct {
	Host string `json:"host"`
	Path string `json:"path"`

	Frontend bool   `json:"frontend,omitempty"`
	Backend  string `json:"backend"`

	AutoHead bool `json:"autoHead,omitempty"`

	Auth      *AuthPolicy      `json:"auth,omitempty"`
	RateLimit *RateLimitPolicy `json:"rateLimit,omitempty"`
	Quota     *QuotaPolicy     `json:"quota,omitempty"`

	OpenAPI *OpenAPIPolicy `json:"openapi,omitempty"`
	MCP     *MCPPolicy     `json:"mcp,omitempty"`
	PWA     *PWAPolicy     `json:"pwa,omitempty"`

	AuthGuard *AuthGuardPolicy `json:"authGuard,omitempty"`
}

type Config struct {
	Routes []Route `json:"routes"`
}

func Load(path string) (*Config, error) {

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg Config

	if err := json.Unmarshal(data, &cfg); err != nil {

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

	return &cfg, nil
}
