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

	// Identity conditions: evaluated AFTER authentication
	// (the token does not exist before) — a failure produces a 403.
	Roles []string `json:"roles,omitempty"`

	Scopes []string `json:"scopes,omitempty"`

	// Token claims: value "*" = mere presence, otherwise
	// comparison of the stringified value (JSON boolean →
	// "true"/"false", numbers → Go format).
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

// UIGateRule: config-driven UI gating rule — for frontends whose
// markup cannot be modified (safety net; if you control the HTML,
// prefer the data-gtw-* attributes). The selected element is only
// visible if the session satisfies the conditions (OR over roles,
// OR over scopes, AND over claims, "*" = presence). Optional
// auth/hidden: same semantics as the data-gtw-auth /
// data-gtw-auth-hidden attributes. PRECEDENCE: an element carrying
// at least one data-gtw-* attribute ignores the uiGate rules — the
// declaration closest to the element wins.
type UIGateRule struct {
	// Selector: CSS selector (querySelectorAll) of the targeted elements.
	Selector string `json:"selector"`
	// Roles: visible if AT LEAST ONE of these roles is held.
	Roles []string `json:"roles,omitempty"`
	// Scopes: visible if AT LEAST ONE of these scopes is granted.
	Scopes []string `json:"scopes,omitempty"`
	// Claims: all must match ("*" = presence).
	Claims map[string]string `json:"claims,omitempty"`
	// Auth: "after" (native action preserved + invitation tab)
	// or "before" (click neutralized + direct tab).
	Auth string `json:"auth,omitempty"`
	// Hidden: "before" (hidden before authentication) or "after"
	// (hidden once authenticated).
	Hidden string `json:"hidden,omitempty"`
}

// UserBadgePolicy: user tab injected by the guard script once
// authenticated — collapsed at the top edge (position
// left|right), expanded on hover/focus: the chosen claims + a
// logout button (OIDC end_session). Absent = no badge.
type UserBadgePolicy struct {
	// Position: top edge left or right (default "right").
	Position string `json:"position,omitempty"`
	// Claims / Roles / Scopes: what the expanded tab displays —
	// each accepts true (everything the session carries), false
	// (nothing — the default), or a list (only the selected items;
	// absent ones are omitted, the historical claims form).
	Claims BadgeList `json:"claims,omitempty"`
	Roles  BadgeList `json:"roles,omitempty"`
	Scopes BadgeList `json:"scopes,omitempty"`
	// LogoutLabel: button label (default "Log out").
	LogoutLabel string `json:"logoutLabel,omitempty"`
	// LoginBadge: the badge ALSO appears when anonymous, from the
	// first visit, in invitation mode ("👤 Sign in") —
	// clicked, it opens the login tab. To offer login without
	// touching the site's markup. Default: false
	// (badge only once authenticated; when anonymous it
	// only appears after a detected session death).
	LoginBadge bool `json:"loginBadge,omitempty"`
}

// BadgeList: a badge display switch — bool or list of selected
// items. true = display everything the session carries; false = hide
// the section; a list = display only these items (a claim, role or
// scope the session does not hold is simply omitted). Marshals back
// to the same shapes for the guard script.
type BadgeList struct {
	All   bool
	Items []string
}

func (b *BadgeList) UnmarshalJSON(raw []byte) error {

	raw = bytes.TrimSpace(raw)
	if bytes.Equal(raw, []byte("null")) {
		*b = BadgeList{}
		return nil
	}

	if len(raw) > 0 && raw[0] == '[' {
		var items []string
		if err := json.Unmarshal(raw, &items); err != nil {
			return fmt.Errorf(
				"userBadge: expected a list of strings: %w", err)
		}
		*b = BadgeList{Items: items}
		return nil
	}

	var v bool
	if err := json.Unmarshal(raw, &v); err != nil {
		return fmt.Errorf("userBadge: expected true, false or a list of strings")
	}
	*b = BadgeList{All: v}
	return nil
}

func (b BadgeList) MarshalJSON() ([]byte, error) {
	if b.All {
		return []byte("true"), nil
	}
	if len(b.Items) == 0 {
		return []byte("false"), nil
	}
	return json.Marshal(b.Items)
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

// RewriteExcept: rewriteBody exception. Two declarable forms:
//
//   - a string: "path" — URLs of the origin WHOSE PATH starts with
//     this prefix remain pointed at the origin (no rewriting);
//   - an object {"path", "to"}: the same URLs are rewritten to the
//     alternate public host `to` (https scheme) — the rest of the
//     path, query and fragment is preserved.
//
// Longest prefix wins. Entries are sorted by decreasing length at
// compile time, on the gateway side as well as on the client SW side.
type RewriteExcept struct {
	// Path: path prefix ("/..." — without '?' or '#').
	Path string `json:"path"`
	// To: replacement base "https://alternate.host"; empty =
	// URLs of this prefix remain at the origin (string form).
	To string `json:"to,omitempty"`
}

// UnmarshalJSON accepts both the string form ("path") and the object
// form {"path","to"} of the except array.
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

// RewriteBodyPolicy: streaming rewrite of the origin's absolute URLs
// (upstream.rewriteBody). For a proxified external site, the origin
// HTML cites its own URLs ("https://origin/...",
// "//origin/..."): without rewriting the browser would leave the
// proxy at the first absolute link/asset. The gateway rewrites these
// occurrences to the route's PUBLIC host (same path), in a streaming
// fashion, on 200 HTML bodies — except for the prefixes declared in
// except: a string exception leaves the link at the origin (e.g. a
// reading link kept outside the proxy), a {path,to} exception points
// to another public host (e.g. a hosted reading variant with its own
// features).
//
// The JS/WASM runtime (fetch/XHR, import(), dynamic img…) is covered
// by the route's configured service worker (same policy) +
// rewriting at the call sites in the guard script. JS/CSS file bodies
// are not rewritten (redundant with the SW).
type RewriteBodyPolicy struct {
	Enabled bool `json:"enabled"`
	// Except: path-prefix exceptions — string form (remains
	// at the origin) or object {path, to} (alternate public host).
	Except []RewriteExcept `json:"except,omitempty"`
}

// UpstreamResponseHeaders: adjustment of the backend's RESPONSE
// headers before sending to the browser — typically removing an
// origin Content-Security-Policy that would block the injected guard
// script, or setting a deployment header.
type UpstreamResponseHeaders struct {
	// Set: headers added/overwritten on the response; values with
	// ${VAR} interpolation (container environment); value ""
	// = header removed (never transmitted empty).
	Set map[string]string `json:"set,omitempty"`
	// Remove: header names removed from the response.
	Remove []string `json:"remove,omitempty"`
}

// BrowserCachePolicy: HTTP-cache orientation to the BROWSER for
// asset resources the origin serves with no Cache-Control (and,
// typically, with no Last-Modified either: without these two
// headers the browser never derives its heuristic cache —
// EVERY re-view re-fetches or revalidates each asset, one full
// round-trip each). Only 200 responses of the types image/*,
// Cache-Control absent only, are concerned — never modified when
// the origin declares one.
type BrowserCachePolicy struct {
	// ImagesMaxAgeSeconds: freshness duration granted to the images
	// (content-type image/*), sent as "private, max-age=…" —
	// private: resources under authentication stay out of any
	// SHARED cache; the origin's ETag remains for revalidation
	// after expiry.
	ImagesMaxAgeSeconds int `json:"imagesMaxAgeSeconds,omitempty"`
}

// UpstreamPolicy: how the gateway reaches the backend when it
// is not a service of the internal network — typically a site
// hosted behind Cloudflare (Pages, Access…). Absent =
// unchanged historical behavior (public Host preserved, client
// headers passed through as-is).
type UpstreamPolicy struct {
	// Host: true = the Host header sent to the backend is that of
	// the backend origin (required for an external site that routes
	// by Host, e.g. Cloudflare: otherwise the request arrives with
	// the public host and the origin does not recognize it).
	// Absent/false = public Host passed through as-is (internal
	// backends).
	Host *bool `json:"host,omitempty"`
	// HostOverride: explicit value of the Host header sent to the
	// backend, when it must differ from both the public host and
	// the backend origin (rare). Takes precedence over Host.
	HostOverride string `json:"hostOverride,omitempty"`
	// Headers: static request headers set towards the backend
	// (Set: overwrite any value the client may have sent).
	// Usage: passing through an origin basic auth
	// ("Authorization": "Basic ${MONSITE_BASIC_AUTH}") or the
	// Cloudflare Access service tokens ("CF-Access-Client-Id" /
	// "CF-Access-Client-Secret"). Values with ${VAR} interpolation
	// from the container environment (missing variable = fatal
	// error at load — never a silent empty credential);
	// value "" = header removed from the request. The values are
	// never logged.
	Headers map[string]string `json:"headers,omitempty"`
	// RewriteRedirects: true = ABSOLUTE Locations targeting
	// the backend origin are rewritten to the public host
	// (otherwise the browser would leave the proxy at the first
	// absolute redirect of the target site). Relative Locations and
	// those targeting other origins (e.g. the Cloudflare Access team
	// domain) pass through untouched. Default: false.
	RewriteRedirects *bool `json:"rewriteRedirects,omitempty"`
	// ResponseHeaders: response header adjustment (see
	// UpstreamResponseHeaders).
	ResponseHeaders *UpstreamResponseHeaders `json:"responseHeaders,omitempty"`
	// RewriteBody: rewriting of the origin's absolute URLs in 200
	// HTML bodies (declarative, streaming, with prefix exceptions;
	// the configured client SW covers runtime calls). Default:
	// no body rewriting.
	RewriteBody *RewriteBodyPolicy `json:"rewriteBody,omitempty"`
	// RewriteCookies: translation of the Set-Cookie headers set by
	// the origin (their Domain attribute targets its own namespace,
	// which the browser would reject from the public host).
	// Default: no cookie rewriting.
	RewriteCookies *RewriteCookiesPolicy `json:"rewriteCookies,omitempty"`
	// BrowserCache: cache orientation to the browser when the
	// origin serves its assets with no Cache-Control (see
	// BrowserCachePolicy). Default: headers preserved as-is.
	BrowserCache *BrowserCachePolicy `json:"browserCache,omitempty"`
}

// RewriteCookiesPolicy: translation of the origin's Set-Cookie to
// the public host (see UpstreamPolicy.RewriteCookies).
type RewriteCookiesPolicy struct {
	// Domain: "rewrite" = a Domain targeting the origin host (or one
	// of its parents) rewritten to Domain=<public host> — the sharing
	// scope (host + subdomains) is transposed as-is;
	// "strip" = Domain attribute removed (host-only cookie on the
	// public host). In both modes, a Set-Cookie carrying a name
	// reserved for the gateway session (access_token, refresh_token,
	// id_token, session) is dropped with a warning: set on the same
	// public host, it would overwrite the auth cookies.
	Domain string `json:"domain"`
}

type MCPOperation struct {
	Name        string `json:"name"`
	OperationID string `json:"operationId"`
}

type MCPPolicy struct {
	Enabled bool   `json:"enabled"`
	Path    string `json:"path,omitempty"`
	// Scope: the Keycloak client scope required from MCP clients
	// (carried by the bearer's `scope` claim). Advertised in
	// /.well-known/oauth-protected-resource and verified by
	// auth-bridge (passed via the internal X-MCP-Scope header).
	// Default: defaultMCPScope. The realm must grant the same scope
	// (optional client scope of the same name in cladone-realm.json).
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
	// of the declared apiCaches[] paths and the virtual /__gate-one_pwa/
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
// virtual endpoints under /__gate-one_pwa/ (manifest, service worker,
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
	// strings.ToLower also flattens declared CamelCase values
	// (networkFirst -> networkfirst): comparisons are done in
	// lowercase; only the workbox class generated by swJS restores
	// the casing.
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

	// Wildcard: named host/backend expansion — one route, N sites.
	// Each key is a capture name ({name} in host and backend), its
	// value the ALLOW-LIST of DNS labels it may take. The route is
	// expanded AT LOAD into one concrete route per label (zero
	// per-request cost); a label outside the lists has no route —
	// fail-closed: the backend is never attacker-derived (anti-SSRF).
	Wildcard Wildcard `json:"wildcard,omitempty"`

	Frontend bool   `json:"frontend,omitempty"`
	Backend  string `json:"backend"`

	// Upstream: connection to a backend outside the internal network
	// (proxified external site — e.g. Cloudflare): Host, static
	// headers (basic auth, service tokens), rewriting of redirects
	// and response headers. Absent = historical behavior.
	Upstream *UpstreamPolicy `json:"upstream,omitempty"`

	AutoHead bool `json:"autoHead,omitempty"`

	Auth      *AuthPolicy      `json:"auth,omitempty"`
	RateLimit *RateLimitPolicy `json:"rateLimit,omitempty"`
	Quota     *QuotaPolicy     `json:"quota,omitempty"`

	OpenAPI *OpenAPIPolicy `json:"openapi,omitempty"`
	MCP     *MCPPolicy     `json:"mcp,omitempty"`
	PWA     *PWAPolicy     `json:"pwa,omitempty"`

	// UIGate: UI gating by config (CSS selectors + identity
	// conditions) — for unmodifiable frontends; embedded in
	// the injected guard script. Precedence: an element's
	// data-gtw-* markup wins over the uiGate rules.
	UIGate []*UIGateRule `json:"uiGate,omitempty"`

	// UserBadge: injected user tab (claims + logout).
	UserBadge *UserBadgePolicy `json:"userBadge,omitempty"`

	AuthGuard *AuthGuardPolicy `json:"authGuard,omitempty"`

	// Inject: path of the route's custom injection bundle
	// (JSON: injects = HTML/JS/CSS per named target, patch = data-*
	// rules applied by the guard), relative to the config file —
	// the routing table never grows with the sites' code.
	Inject string `json:"inject,omitempty"`

	// injection: bundle resolved at load (file: contents read,
	// strict validation) — never serialized.
	injection *InjectBundle `json:"-"`

	// wildcardSrc: the wildcard pattern this route was expanded
	// from (route table annotation; never decoded).
	wildcardSrc string `json:"-"`

	// rewriteSiblings: sibling-expansion map (backend origin host →
	// public host) for routes expanded from the same wildcard. Built
	// AT LOAD, shared read-only by rewriteBody (server, SW, guard):
	// an HTML page of one edition links to the origin of another
	// edition, and the link is rewritten to that sibling's public
	// host without any per-request route lookup. nil when there is
	// no unambiguous mapping (one variant, or one origin shared by
	// several public hosts — the alias form).
	rewriteSiblings map[string]string `json:"-"`
}

// Wildcard: a route's expansion allow-lists — key = capture name
// ({name} in host and backend), value = the DNS labels it may take.
type Wildcard map[string][]string

// WildcardSource: the wildcard pattern the route was expanded from
// ("" for a route declared literally) — route table annotation.
func (r *Route) WildcardSource() string { return r.wildcardSrc }

// RewriteSiblings: for a route expanded from a wildcard, the map
// backend-origin-hostname → public-host of the OTHER concrete routes
// of the same expansion (nil when there is no unambiguous mapping).
// Read-only: compiled once at load, shared by the server rewriter,
// the service worker and the guard script. This is what lets an
// interlanguage link ("https://es.wikipedia.org/…") found in the
// English edition be rewritten to the Spanish public host without
// duplicating the host block in the config or the plugin.
func (r *Route) RewriteSiblings() map[string]string { return r.rewriteSiblings }

// wildcardLabel: an allow-list entry — one DNS label, lowercase,
// no dots (the bounded-domain guarantee: a value can never jump to
// another domain).
var wildcardLabel = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)

// wildcardCapture: a host/backend label of the {name} form.
var wildcardCapture = regexp.MustCompile(`^\{([a-z0-9_-]+)\}$`)

// expandWildcards: every wildcard route is EXPANDED AT LOAD into its
// concrete routes (cross product of the allow-lists, stable order) —
// the request path never sees a wildcard: findRoute, rewriteBody,
// redirects and the probe keep running on concrete compiled routes,
// exactly as before (zero per-request cost). A label outside an
// allow-list simply has no route.
func (c *Config) expandWildcards() error {

	if len(c.Routes) == 0 {
		return nil
	}

	// the concrete (host, path) pairs already declared: an expansion
	// colliding with one of them is a config AMBIGUITY — refused (a
	// wildcard must never silently shadow an exact route).
	taken := make(map[string]bool, len(c.Routes))
	for i := range c.Routes {
		r := &c.Routes[i]
		if r.Wildcard == nil {
			taken[wildcardKey(r.Host, r.Path)] = true
		}
	}

	expanded := make([]Route, 0, len(c.Routes))
	for i := range c.Routes {
		r := &c.Routes[i]
		if r.Wildcard == nil {
			expanded = append(expanded, *r)
			continue
		}
		variants, err := r.expandWildcard(taken)
		if err != nil {
			return fmt.Errorf("route %s: %v", r.Host, err)
		}
		expanded = append(expanded, variants...)
	}
	c.Routes = expanded
	return nil
}

// wildcardKey: the collision key — normalized host + path.
func wildcardKey(host, path string) string {
	return strings.ToLower(host) + "|" + path
}

// expandWildcard: one wildcard route → its concrete variants.
func (r *Route) expandWildcard(taken map[string]bool) ([]Route, error) {

	// the host pattern: labels are literals or {name} captures
	labels := strings.Split(r.Host, ".")
	var names []string
	seen := map[string]bool{}
	for _, l := range labels {
		m := wildcardCapture.FindStringSubmatch(l)
		if m == nil {
			if strings.ContainsAny(l, "{}*") {
				return nil, fmt.Errorf(
					"label %q: malformed capture (expected {name})", l)
			}
			continue
		}
		name := m[1]
		if seen[name] {
			return nil, fmt.Errorf("capture {%s}: declared twice", name)
		}
		seen[name] = true
		names = append(names, name)
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("wildcard host without any {capture}")
	}

	// every capture needs its allow-list; every allow-list entry
	// must be referenced (no dead config). The capture MAY be absent
	// from the backend: present = per-label backends (the binding
	// host↔backend), absent = N host aliases on one fixed backend.
	for _, name := range names {
		if len(r.Wildcard[name]) == 0 {
			return nil, fmt.Errorf("capture {%s}: no allow-list", name)
		}
	}
	for name := range r.Wildcard {
		if !seen[name] {
			return nil, fmt.Errorf(
				"wildcard param %q: not present in the host", name)
		}
	}

	// cross product of the allow-lists, sorted parameters AND sorted
	// values (deterministic expansion: same config → same route
	// table, whatever the authoring order)
	sort.Strings(names)
	variants := []map[string]string{{}}
	for _, name := range names {
		labels := make([]string, len(r.Wildcard[name]))
		copy(labels, r.Wildcard[name])
		sort.Strings(labels)
		var next []map[string]string
		for _, v := range variants {
			for _, label := range labels {
				if !wildcardLabel.MatchString(label) {
					return nil, fmt.Errorf(
						"wildcard %s=%q: invalid label (a-z0-9, hyphens, no dots)",
						name, label)
				}
				m := make(map[string]string, len(v)+1)
				for k, val := range v {
					m[k] = val
				}
				m[name] = label
				next = append(next, m)
			}
		}
		variants = next
	}

	out := make([]Route, 0, len(variants))
	for _, vars := range variants {
		host := r.Host
		backend := r.Backend
		for name, label := range vars {
			host = strings.ReplaceAll(host, "{"+name+"}", label)
			backend = strings.ReplaceAll(backend, "{"+name+"}", label)
		}
		key := wildcardKey(host, r.Path)
		if taken[key] {
			return nil, fmt.Errorf(
				"expansion %s collides with an existing route (a wildcard must not shadow an exact route)",
				host)
		}
		taken[key] = true
		e := *r // shared sub-policies: read-only at compile
		e.Host = host
		e.Backend = backend
		e.Wildcard = nil
		e.wildcardSrc = r.Host
		out = append(out, e)
	}
	annotateRewriteSiblings(out)
	return out, nil
}

// annotateRewriteSiblings compiles the cross-route rewrite map of one
// wildcard expansion: backend origin host → public host of the sibling
// variants. It is the compact counterpart of the finite allow-list:
// the config declares one host pattern and its labels; the expansion
// already knows every (origin, public host) pair, so no per-request
// mapping and no duplicated host block are needed.
//
// Ambiguity is left UNMAPPED: the alias form (capture absent from the
// backend) points every public host at one origin, so a link to that
// origin cannot choose a label. The same applies to a HostOverride
// shared by several variants. The route's own origins never appear in
// its map (self-rewrite keeps its existing semantics).
func annotateRewriteSiblings(variants []Route) {
	if len(variants) < 2 || variants[0].UpstreamRewriteBody() == nil {
		return
	}

	type target struct {
		host      string
		ambiguous bool
	}
	byOrigin := make(map[string]*target, len(variants))
	for i := range variants {
		for _, origin := range rewriteOriginHosts(&variants[i]) {
			t := byOrigin[origin]
			if t == nil {
				byOrigin[origin] = &target{host: variants[i].Host}
				continue
			}
			if t.host != variants[i].Host {
				t.ambiguous = true
			}
		}
	}

	for i := range variants {
		self := make(map[string]bool)
		for _, origin := range rewriteOriginHosts(&variants[i]) {
			self[origin] = true
		}
		var siblings map[string]string
		for origin, t := range byOrigin {
			if t.ambiguous || self[origin] {
				continue
			}
			if siblings == nil {
				siblings = make(map[string]string, len(byOrigin))
			}
			siblings[origin] = t.host
		}
		variants[i].rewriteSiblings = siblings
	}
}

// rewriteOriginHosts: origin hostnames a concrete route may cite in
// its own HTML — its backend hostname and the optional Host override.
// Normalized (lowercase, no port), deduplicated, stable order.
func rewriteOriginHosts(r *Route) []string {
	out := make([]string, 0, 2)
	add := func(h string) {
		h = strings.ToLower(strings.TrimSpace(h))
		if h == "" {
			return
		}
		for _, have := range out {
			if have == h {
				return
			}
		}
		out = append(out, h)
	}
	if u, err := url.Parse(r.Backend); err == nil {
		add(u.Hostname())
	}
	if r.Upstream != nil && r.Upstream.HostOverride != "" {
		h := strings.TrimSpace(r.Upstream.HostOverride)
		if u, err := url.Parse("//" + h); err == nil && u.Hostname() != "" {
			add(u.Hostname())
		} else {
			add(strings.Split(h, ":")[0])
		}
	}
	return out
}

// InjectionBundle: the route's resolved injection bundle; nil
// without an "inject" block.
func (r *Route) InjectionBundle() *InjectBundle { return r.injection }

// InjectBundle: a route's custom injection bundle, resolved at
// load (files read, everything validated — a faulty bundle refuses
// startup/reload rather than being ignored).
type InjectBundle struct {
	// Contents: the injections to insert into the pages (sorted by
	// increasing Order = order in the document).
	Contents []InjectContent `json:"injects,omitempty"`
	// Patch: data-* attribution rules per selector, applied
	// client-side by the guard (extension of the uiGate evaluation —
	// same probe, same cycle). Frontend route required.
	Patch []InjectPatch `json:"patch,omitempty"`
}

// InjectContent: a single insertion — content assembled at load
// (inline html/style/script + file: contents), named target in the
// document, per-page filtering (path prefix, same grammar as
// route.path).
type InjectContent struct {
	// Name: bundle identifier (unique, logs).
	Name string `json:"name"`
	// Target: "head" (default — after <head>/meta charset) or
	// "body-end" (before </body>).
	Target string `json:"target,omitempty"`
	// Order: position in the document within a same target
	// (30+ for customs; the guard is 10, the pwa 20).
	Order int `json:"order,omitempty"`
	// WhenPath: path prefix of the targeted pages ("/*" = the whole
	// site); empty = all.
	WhenPath string `json:"when,omitempty"`
	// Content: the ASSEMBLED snippet (html + style + script + file),
	// ready to insert as-is.
	Content string `json:"-"`
}

// InjectPatch: a patch rule — the attributes (typically data-gtw-*)
// are set on the elements matched by the selector. Applies at every
// evaluation cycle of the guard (dynamic elements
// covered); a pre-existing markup attribute is OVERWRITTEN (the patch
// declares the target, the selector finds it).
type InjectPatch struct {
	Selector string            `json:"selector"`
	Attrs    map[string]string `json:"attrs,omitempty"`
}

type Config struct {
	// $schema: optional reference to api-routes.schema.json
	// (editor autocompletion/validation) — ignored at runtime.
	Schema string `json:"$schema,omitempty"`

	// OIDC: the platform's IdP — the gateway is multi-tenant,
	// no IdP URL is hard-coded (routes access it via
	// LoginURLFor / OIDC.Issuer).
	OIDC *OIDCConfig `json:"oidc,omitempty"`

	Routes []Route `json:"routes"`
}

// OIDCConfig: the platform's IdP (top-level block). loginUrl =
// default login page for frontend routes with an active guard
// (overridable per route via authGuard.loginUrl); issuer = OIDC
// issuer advertised in the OAuth metadata of MCP routes.
type OIDCConfig struct {
	LoginURL string `json:"loginUrl,omitempty"`
	Issuer   string `json:"issuer,omitempty"`
}

// GuardActive: is the guard active on this route? (frontend +
// authGuard not disabled) — the same rule as the proxy.
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

// MCPActive: does the route expose an MCP server?
func (r *Route) MCPActive() bool {
	return r.MCP != nil && r.MCP.Enabled
}

// LoginURLFor: a route's login URL — authGuard.loginUrl
// (route) wins over oidc.loginUrl (platform). Guaranteed non-empty
// by load-time validation for any route with an active guard.
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

	// Strict: any unknown field (typically a typo
	// in a policy name) is rejected at load rather than
	// silently ignored.
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

	// Wildcard routes expanded AT LOAD into concrete routes (one per
	// allow-listed label): the request path never sees a wildcard —
	// findRoute, rewriteBody, redirects and the probe keep running on
	// concrete compiled routes exactly as before. A label outside an
	// allow-list = no route (fail-closed: the backend is never
	// attacker-derived).
	if err := cfg.expandWildcards(); err != nil {
		return nil, fmt.Errorf("%s: %v", path, err)
	}

	// Upstream secrets (${VAR} in headers) resolved BEFORE the
	// validation: missing variable = startup refused.
	if err := cfg.expandUpstreamEnv(); err != nil {
		return nil, fmt.Errorf("%s: %v", path, err)
	}

	// Injection bundles resolved (files read at load: a faulty
	// bundle refuses startup, never silently ignored).
	if err := cfg.loadInjectBundles(filepath.Dir(path)); err != nil {
		return nil, fmt.Errorf("%s: %v", path, err)
	}

	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("%s: %v", path, err)
	}

	return &cfg, nil
}

// envVarPattern: interpolation form supported in upstream header
// values — ${NAME} only (never $NA, to avoid distorting a value
// containing a literal $).
var envVarPattern = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

// named insertion targets ("head" = after <head>/meta charset —
// the guard's mechanics; "body-end" = before </body>).
var validInjectTargets = map[string]bool{
	"":         true, // default = head
	"head":     true,
	"body-end": true,
}

// bounds of custom injections: Order >= 30 (the guard is 10, the
// pwa 20 — a custom cannot slip in front of the infrastructure)
// and bounded content.
const (
	minInjectOrder    = 30
	maxInjectOrder    = 10000
	maxInjectContents = 64
	maxInjectPatch    = 64
	maxInjectSnippet  = 256 << 10 // 256 KiB per entry (file included)
)

// rawInjectBundle: serialized form of the bundle (before resolving
// the file: entries).
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

// loadInjectBundles resolves each route's "inject" block: reads the
// bundle (strict JSON), assembles the contents (inline + files) and
// validates. dir = directory of the config file.
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
			return fmt.Errorf("route %s: inject %q: %d entries (max %d)",
				host, ref, len(raw.Injects), maxInjectContents)
		}
		if len(raw.Patch) > maxInjectPatch {
			return fmt.Errorf("route %s: inject %q: %d patches (max %d)",
				host, ref, len(raw.Patch), maxInjectPatch)
		}

		bundle := &InjectBundle{Patch: raw.Patch}
		bundleDir := filepath.Dir(bundlePath)
		seen := make(map[string]bool, len(raw.Injects))

		for j := range raw.Injects {
			in := &raw.Injects[j]
			if in.Name == "" {
				return fmt.Errorf(
					"route %s: inject %q: injects[%d].name empty", host, ref, j)
			}
			if seen[in.Name] {
				return fmt.Errorf(
					"route %s: inject %q: duplicate name %q", host, ref, in.Name)
			}
			seen[in.Name] = true

			if !validInjectTargets[in.Target] {
				return fmt.Errorf(
					"route %s: inject %q: %s.target %q (expected \"head\" or \"body-end\")",
					host, ref, in.Name, in.Target)
			}

			order := 30
			if in.Order != nil {
				order = *in.Order
			}
			if order < minInjectOrder || order > maxInjectOrder {
				return fmt.Errorf(
					"route %s: inject %q: %s.order %d (bounds %d-%d)",
					host, ref, in.Name, order, minInjectOrder, maxInjectOrder)
			}

			// assembly: style and script are WRAPPED
			// (html and file: are injected as-is)
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
						"route %s: inject %q: %s.file %q (path relative to the bundle required)",
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
					"route %s: inject %q: %s without content (html/style/script/file)",
					host, ref, in.Name)
			}
			if len(content) > maxInjectSnippet {
				return fmt.Errorf(
					"route %s: inject %q: %s: %d bytes (max %d)",
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

		// document order = increasing Order (stable sort)
		sort.SliceStable(bundle.Contents, func(a, b int) bool {
			return bundle.Contents[a].Order < bundle.Contents[b].Order
		})

		for k := range raw.Patch {
			p := &raw.Patch[k]
			if p.Selector == "" {
				return fmt.Errorf(
					"route %s: inject %q: patch[%d].selector empty",
					host, ref, k)
			}
			if len(p.Attrs) == 0 {
				return fmt.Errorf(
					"route %s: inject %q: patch[%d] (%s) without attrs",
					host, ref, k, p.Selector)
			}
		}

		c.Routes[i].injection = bundle
	}
	return nil
}

// expandEnvVars replaces each ${VAR} with the corresponding
// environment variable. Missing variable = named error (the gateway
// refuses to start rather than sending an empty credential to the
// backend). PRESENT BUT EMPTY variable = whole value emptied, names
// reported in emptyNames (the caller will treat it as a removed
// header and log the warning) — see the compose "${VAR:-}" idiom,
// which injects an empty string when the variable is missing from
// the .env.
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
			"missing environment variable(s): %s",
			strings.Join(missing, ", "),
		), nil
	}

	if len(emptyNames) > 0 {
		return "", nil, emptyNames
	}

	return out, nil, nil
}

// expandUpstreamEnv resolves the ${VAR} interpolation of the upstream
// headers. Pass targeted at the upstream blocks only (the config is
// committed to git: secrets enter it through the container
// environment, never in clear) — a general-purpose pass could
// corrupt PWA regex patterns containing a '$'.
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
				// Variable present but empty (typically missing
				// from the .env, injected as "" by compose): header
				// removed rather than a truncated stray "Basic".
				// Non-fatal — the upstream will answer 401 and the
				// other sites remain in service.
				log.Printf(
					"CONFIG WARNING route %s: upstream.headers[%q]: empty variable(s): %s — header removed (target site will answer 401)",
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
					"CONFIG WARNING route %s: upstream.responseHeaders.set[%q]: empty variable(s): %s — header removed",
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
				"route %s: guard active without login URL (oidc.loginUrl block or authGuard.loginUrl required)",
				host)
		}

		if route.MCPActive() && (c.OIDC == nil || c.OIDC.Issuer == "") {
			return fmt.Errorf(
				"route %s: MCP active without oidc.issuer (OAuth metadata: authorization_servers)",
				host)
		}

		if p := route.PWA; p != nil {
			for _, pat := range p.networkOnlyPatterns() {
				if _, err := regexp.Compile(pat); err != nil {
					return fmt.Errorf(
						"route %s: invalid expression in the PWA exclusions %q: %v",
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
					"route %s: rewriteCookies.domain %q (expected \"rewrite\" or \"strip\")",
					host, up.RewriteCookies.Domain)
			}
		}

		if up := c.Routes[i].Upstream; up != nil && up.BrowserCache != nil {
			if ma := up.BrowserCache.ImagesMaxAgeSeconds; ma < 1 {
				return fmt.Errorf(
					"route %s: browserCache.imagesMaxAgeSeconds %d (expected: positive integer in seconds, e.g. 604800 for a week)",
					host, ma)
			}
		}
	}
	return nil
}

// UpstreamRewriteBody: accessor of a route's rewriteBody policy
// (nil when absent or disabled).
func (r *Route) UpstreamRewriteBody() *RewriteBodyPolicy {
	if r.Upstream == nil || r.Upstream.RewriteBody == nil ||
		!r.Upstream.RewriteBody.Enabled {
		return nil
	}
	return r.Upstream.RewriteBody
}

// bounds of an except configuration: the rewrite window of the
// streaming engine (and of the client SW) is proportional to the
// origin prefix + the longest exception prefix — they stay
// small and unreasonable configurations are refused at load.
const (
	maxRewriteExcepts = 64
	maxRewritePathLen = 256
)

func validateRewriteBody(rb *RewriteBodyPolicy) error {
	if len(rb.Except) > maxRewriteExcepts {
		return fmt.Errorf(
			"rewriteBody.except: %d entries (max %d)",
			len(rb.Except), maxRewriteExcepts,
		)
	}
	seen := make(map[string]bool, len(rb.Except))
	for i := range rb.Except {
		e := &rb.Except[i]
		if e.Path == "" {
			return fmt.Errorf(
				"rewriteBody.except[%d]: empty path", i)
		}
		if !strings.HasPrefix(e.Path, "/") {
			return fmt.Errorf(
				"rewriteBody.except[%d]: path %q does not start with '/'", i, e.Path)
		}
		if strings.ContainsAny(e.Path, "?#") {
			return fmt.Errorf(
				"rewriteBody.except[%d]: path %q contains '?' or '#' (path prefix only)", i, e.Path)
		}
		if len(e.Path) > maxRewritePathLen {
			return fmt.Errorf(
				"rewriteBody.except[%d]: path %d bytes (max %d)",
				i, len(e.Path), maxRewritePathLen)
		}
		e.Path = strings.TrimRight(e.Path, "/")
		if e.Path == "" {
			return fmt.Errorf(
				"rewriteBody.except[%d]: path \"/\" (root prefix forbidden: it would except everything)", i)
		}
		if seen[e.Path] {
			return fmt.Errorf(
				"rewriteBody.except[%d]: path %q declared twice", i, e.Path)
		}
		seen[e.Path] = true
		if e.To == "" {
			continue
		}
		// To: alternate rewrite base "https://host" — trailing
		// slashes are removed (the origin path follows).
		for strings.HasSuffix(e.To, "/") {
			e.To = strings.TrimSuffix(e.To, "/")
		}
		u, err := url.Parse(e.To)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return fmt.Errorf(
				"rewriteBody.except[%d]: to %q is not an absolute URL (https://host, http://host in demo)", i, e.To)
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return fmt.Errorf(
				"rewriteBody.except[%d]: to %q must be http(s)", i, e.To)
		}
	}
	return nil
}

// AsciiJSON marshals v and escapes EVERY non-ASCII character as
// \uXXXX: the injected payloads (guard script, service worker)
// remain decodable whatever encoding the receiving site declares —
// or omits. Fallback if Marshal fails (impossible for
// these structs).
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
