package core

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"cladone/gate-one/internal/license"
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

// WhenList: the auth.when policy — technical conditions
// (method/query/header/body) deciding WHEN authentication is
// required. Accepts one object (AND of its conditions) or an array
// (OR of ANDs, DNF): the request triggers the authentication
// requirement if ANY element matches. Absent or empty = always
// required. Identity conditions (roles/scopes/claims/user) do NOT
// belong here — they go to auth.identity (see validateAuth).
type WhenList []Match

// UnmarshalJSON accepts both the object and the array forms, with
// the same strictness as the top-level decode (unknown fields are
// rejected rather than silently ignored).
func (w *WhenList) UnmarshalJSON(b []byte) error {

	raw := bytes.TrimSpace(b)
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		*w = nil
		return nil
	}

	if raw[0] == '[' {
		var list []Match
		if err := strictUnmarshal(raw, &list); err != nil {
			return fmt.Errorf("auth.when: %w", err)
		}
		*w = list
		return nil
	}

	var one Match
	if err := strictUnmarshal(raw, &one); err != nil {
		return fmt.Errorf("auth.when: %w", err)
	}
	*w = WhenList{one}
	return nil
}

// strictUnmarshal decodes with DisallowUnknownFields — used by the
// custom UnmarshalJSON methods, which would otherwise lose the
// strictness set on the top-level decoder.
func strictUnmarshal(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
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
	// or "before" (click neutralized + direct tab). Same activation-
	// only semantics as data-gtw-auth: value controls (select/range/
	// date/…) are gated on change, with their default value as the
	// OFF value (data-gtw-auth-off on the element overrides it).
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
	// When: technical conditions (method/query/header/body) deciding
	// WHEN authentication is required. One object = AND of its
	// conditions; an array = OR of ANDs. Absent/empty = always
	// required.
	When WhenList `json:"when,omitempty"`

	// Identity: identity conditions (roles/scopes/claims/user)
	// enforced AFTER successful authentication (403 otherwise). A
	// single AND clause, applied only to requests that were actually
	// authenticated (when the gate did not trigger, identity is not
	// evaluated: there is no token).
	Identity *Match `json:"identity,omitempty"`
}

type OpenAPIPolicy struct {
	// URL: the OpenAPI document (JSON, OpenAPI 3.x) of the host.
	// Absolute (production), or relative to the route backend.
	// Also the source used to resolve the mcp policy's operations.
	URL string `json:"url"`
	// Public: when false, /openapi.json is forbidden on this host.
	Public bool `json:"public,omitempty"`
}

// AuthGuardPolicy controls the injection of the gateway's 401 guard
// script into HTML responses of frontend routes. Unlike the AuthPolicy
// (which enforces authentication on a route), the guard only reacts to
// answers already produced: a fetch() 401 opens a login flow without
// reloading; the gateway's OWN identity 403 is left to the app, with
// an opt-in hint banner (Forbidden). Absent policy = guard active on
// frontend routes, no-op elsewhere.
type AuthGuardPolicy struct {
	Enabled  *bool  `json:"enabled,omitempty"`  // false = opt-out
	LoginURL string `json:"loginUrl,omitempty"` // default: shared constant

	// Forbidden: opt-in UX for the gateway's OWN identity 403 (rights
	// refusal — auth.identity not satisfied). A 403 originating from
	// the backend is never concerned.
	Forbidden *AuthGuardForbiddenPolicy `json:"forbidden,omitempty"`
}

// AuthGuardForbiddenPolicy is the opt-in UX for a request the gateway
// refuses on identity conditions (403). Two surfaces, both optional:
//
//   - a browser NAVIGATION gets a readable built-in HTML page (or a
//     redirect to pageUrl) instead of the raw JSON body;
//   - a fetch()/XHR gets the JSON 403 UNCHANGED, plus — when banner is
//     true — a dismissable hint injected by the guard script inviting
//     the front authors to hide the feature (uiGate / data-gtw-*).
//
// The banner reacts ONLY to the gateway's own 403: the gateway stamps
// it with the response header X-Gate-One-Forbidden; a backend 403
// never carries it (and the header is stripped from proxied responses).
type AuthGuardForbiddenPolicy struct {
	// Banner: the injected guard script shows a dismissable banner
	// when a fetch() sees the gateway's identity 403. Default false.
	Banner bool `json:"banner,omitempty"`
	// PageURL: a browser navigation refused on identity is redirected
	// there (302) instead of the built-in HTML page.
	PageURL string `json:"pageUrl,omitempty"`
	// Message: overrides the built-in forbidden page's text.
	Message string `json:"message,omitempty"`
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

	// Targets: explicit cross-route rewrites — backend origin host →
	// public route host. Hosts only (no scheme, no port): the
	// request's scheme and port are inherited, and the target must be
	// a declared route host. Keys must be origins of declared
	// routes. Resolved at load into the same compiled map as the
	// automatic wildcard expansion.
	Targets map[string]string `json:"targets,omitempty"`

	// FollowRoutes: selectors over declared routes BY PUBLIC HOST
	// (exact host or "*.suffix"). Each selected route's backend
	// origins are rewritten to its public host. Resolved after
	// wildcard expansion; no match, self-only match or ambiguous
	// mapping refuses the load.
	FollowRoutes []string `json:"followRoutes,omitempty"`
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
	// StripCookies: REQUEST-side filtering of the browser's cookies
	// toward the backend. The gateway session cookies are scoped to
	// the parent domain (COOKIE_DOMAIN, e.g. .cladone.com) and are
	// therefore presented by the browser to EVERY public host — a
	// proxified third-party site would otherwise receive the user's
	// access/refresh tokens on every request. "all" = every cookie
	// removed except the names listed in Keep (the proxified app's
	// own cookies); "none" = historical behavior, everything
	// forwarded. Default: "all" as soon as an upstream policy is
	// declared (fail-closed).
	StripCookies string `json:"stripCookies,omitempty"`
	// Keep: cookie names preserved when StripCookies is "all" —
	// typically the proxified application's own session. Names
	// reserved for the gateway session (access_token,
	// refresh_token, id_token, session) are refused at load: they
	// must never reach an external origin.
	Keep []string `json:"keep,omitempty"`
	// BrowserCache: cache orientation to the browser when the
	// origin serves its assets with no Cache-Control (see
	// BrowserCachePolicy). Default: headers preserved as-is.
	BrowserCache *BrowserCachePolicy `json:"browserCache,omitempty"`
	// Delegated: per-user credentials fetched from the token broker
	// for the authenticated caller and injected into the backend
	// request. Provider names are broker-owned; Gate One never
	// stores a provider secret. Requires route.auth (a user must be
	// authenticated to have a delegated token).
	Delegated *DelegatedCredentialPolicy `json:"delegated,omitempty"`
}

// DelegatedCredentialPolicy: how a per-user upstream token is
// obtained and injected. The token broker returns the access token
// for the authenticated user; the gateway sets the configured header
// on the backend request (default Authorization: Bearer …).
type DelegatedCredentialPolicy struct {
	// Provider: broker provider name (e.g. "github"). Validated
	// against GET /providers at startup.
	Provider string `json:"provider"`
	// Header: request header receiving the token. Default
	// Authorization. Header names reserved for the gateway identity
	// or the HTTP transport are refused at load.
	Header string `json:"header,omitempty"`
	// Prefix: value prepended to the access token. Default
	// "Bearer ". An explicit empty string sends the raw token.
	Prefix *string `json:"prefix,omitempty"`
}

// HeaderValue returns the normalized header name (default
// Authorization).
func (d *DelegatedCredentialPolicy) HeaderValue() string {
	if d == nil || d.Header == "" {
		return "Authorization"
	}
	return d.Header
}

// PrefixValue returns the value prepended to the access token.
func (d *DelegatedCredentialPolicy) PrefixValue() string {
	if d == nil || d.Prefix == nil {
		return "Bearer "
	}
	return *d.Prefix
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

// ReservedCookieNames: cookie names reserved for the gateway session.
// auth-bridge sets them on the parent domain (COOKIE_DOMAIN, e.g.
// .cladone.com), so the browser presents them to every public host —
// including proxified third-party sites. They are never accepted from
// an origin's Set-Cookie (it would overwrite the auth) and never
// forwarded to an external upstream (see UpstreamPolicy.StripCookies).
var ReservedCookieNames = map[string]bool{
	"access_token":  true,
	"refresh_token": true,
	"id_token":      true,
	"session":       true,
}

// IsReservedCookieName reports whether name belongs to the gateway
// session and must not cross to a proxified origin.
func IsReservedCookieName(name string) bool { return ReservedCookieNames[name] }

type MCPOperation struct {
	// Name: the tool name exposed to MCP clients.
	Name string `json:"name"`
	// OperationID: the operationId to resolve in the OpenAPI
	// document of the same host (openapi policy). The gateway
	// derives the method, path, parameters and request body from
	// it — no per-operation code.
	OperationID string `json:"operationId"`
}

type MCPPolicy struct {
	Enabled bool   `json:"enabled"`
	Path    string `json:"path,omitempty"`

	// Name: service name, referenced by mcpSets members. Empty = the
	// route cannot be a set member.
	Name string `json:"name,omitempty"`

	// Standalone: expose this service on its own endpoint (default
	// true). false = the service is served only through the mcpSets
	// that reference it (the set carries the access rights).
	Standalone *bool `json:"standalone,omitempty"`

	// Resource: OAuth protected-resource identifier (audience) of the
	// standalone service. Empty = the endpoint URL. Ignored when the
	// service is reached through a set (the set's resource applies).
	Resource string `json:"resource,omitempty"`

	// Scope: the Keycloak client scope required from MCP clients
	// (carried by the bearer's `scope` claim). Advertised in
	// /.well-known/oauth-protected-resource and verified by
	// auth-bridge (passed via the internal X-MCP-Scope header).
	// Default: defaultMCPScope. The realm must grant the same scope
	// (optional client scope of the same name in cladone-realm.json).
	Scope string `json:"scope,omitempty"`
	// Operations: the REST operations exposed as MCP tools. Resolved
	// at load time against the host's OpenAPI document (JSON,
	// OpenAPI 3.x); an unresolvable operationId refuses the config.
	// Empty = no tool, but the MCP endpoint (metadata, initialize)
	// stays available. Mutually exclusive with Upstream.
	Operations []MCPOperation `json:"operations"`
	// Upstream: proxy an EXTERNAL MCP server (Streamable HTTP)
	// instead of deriving local REST tools. Tool names are filtered
	// on both tools/list and tools/call; the upstream receives the
	// per-user token of upstream.delegated (or static upstream
	// headers) — never the Gate One bearer.
	Upstream *MCPUpstreamPolicy `json:"upstream,omitempty"`
}

// IsStandalone reports whether the service is exposed on its own
// endpoint (default true).
func (m *MCPPolicy) IsStandalone() bool {
	return m == nil || m.Standalone == nil || *m.Standalone
}

// AccessPath returns the public path of the MCP endpoint (mcp.path,
// else the route path, else /mcp), with a leading slash.
func (m *MCPPolicy) AccessPath(routePath string) string {
	p := ""
	if m != nil {
		p = m.Path
	}
	if p == "" {
		p = routePath
	}
	if p == "" {
		p = "/mcp"
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return p
}

// MCPUpstreamPolicy: external MCP server proxied by the gateway.
type MCPUpstreamPolicy struct {
	// URL: upstream Streamable HTTP endpoint. Empty = route backend.
	URL string `json:"url,omitempty"`
	// Tools: allow/deny filter applied to tools/list and enforced on
	// tools/call. Absent = all upstream tools exposed.
	Tools *MCPToolFilter `json:"tools,omitempty"`
}

// MCPToolFilter: glob patterns (path.Match syntax) over tool names.
// Include non-empty = only matching names are exposed; Exclude always
// wins. Filtering is enforced at call time too, so a hidden tool
// cannot be invoked by guessing its name.
type MCPToolFilter struct {
	Include []string `json:"include,omitempty"`
	Exclude []string `json:"exclude,omitempty"`
}

// Allows reports whether a tool name passes the filter.
func (f *MCPToolFilter) Allows(name string) bool {
	if f == nil {
		return true
	}
	if len(f.Include) > 0 {
		matched := false
		for _, p := range f.Include {
			if ok, _ := path.Match(p, name); ok {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	for _, p := range f.Exclude {
		if ok, _ := path.Match(p, name); ok {
			return false
		}
	}
	return true
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

	// StripPrefix: exact public path prefix removed from the request
	// before it reaches the backend. "/api" turns "/api/foo" into
	// "/foo"; the backend base path is then prepended as usual.
	// Path only (no query/fragment/wildcard), matched on segment
	// boundaries, normalized at load (trailing slash removed).
	//
	// The SAME mapping is applied to response paths: Location,
	// Content-Location, Refresh/Link headers, Set-Cookie Path, and
	// HTML URL attributes (href/src/action/srcset/style url()…)
	// are brought back under the public prefix. Relative references
	// and other origins are left untouched.
	StripPrefix string `json:"stripPrefix,omitempty"`

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

	// CSP: Content-Security-Policy emitted (or amended) by the
	// gateway — the only place where a per-response nonce can be
	// generated and written into the HTML the gateway already
	// rewrites. Absent = no policy of our own, the origin's passes
	// as-is.
	CSP *CSPPolicy `json:"csp,omitempty"`

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

	// rewriteTargets: compiled cross-route map (backend origin host →
	// public host) for this concrete route. Built AT LOAD from the
	// automatic wildcard expansion, explicit rewriteBody.targets and
	// rewriteBody.followRoutes; shared read-only by rewriteBody
	// (server, SW, guard). nil when there is no mapping.
	rewriteTargets map[string]string `json:"-"`
}

// Wildcard: a route's expansion allow-lists — key = capture name
// ({name} in host and backend), value = the DNS labels it may take.
type Wildcard map[string][]string

// WildcardSource: the wildcard pattern the route was expanded from
// ("" for a route declared literally) — route table annotation.
func (r *Route) WildcardSource() string { return r.wildcardSrc }

// RewriteTargets: compiled cross-route map for this route, origin
// hostname → public host. It combines the automatic wildcard sibling
// expansion, explicit rewriteBody.targets and rewriteBody.followRoutes.
// Read-only: compiled once at load, shared by the server rewriter, the
// service worker and the guard script. nil when there is no mapping.
func (r *Route) RewriteTargets() map[string]string { return r.rewriteTargets }

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
	annotateRewriteTargets(out)
	return out, nil
}

// annotateRewriteTargets compiles the automatic cross-route map of one
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
func annotateRewriteTargets(variants []Route) {
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
		var targets map[string]string
		for origin, t := range byOrigin {
			if t.ambiguous || self[origin] {
				continue
			}
			if targets == nil {
				targets = make(map[string]string, len(byOrigin))
			}
			targets[origin] = t.host
		}
		variants[i].rewriteTargets = targets
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
// are added or their value updated on the elements matched by the
// selector. Applies at every evaluation cycle of the guard (dynamic
// elements covered). Other attributes are left untouched; an existing
// attribute with the same exact name is updated (the patch declares
// the target, the selector finds it).
type InjectPatch struct {
	Selector string            `json:"selector"`
	Attrs    map[string]string `json:"attrs,omitempty"`
}

type Config struct {
	// $schema: optional reference to api-routes.schema.json
	// (editor autocompletion/validation) — ignored at runtime.
	Schema string `json:"$schema,omitempty"`

	// OIDC: legacy platform IdP block. Kept for backward
	// compatibility: when authProvider is absent it is translated
	// into an http provider (auth-bridge) at load.
	OIDC *OIDCConfig `json:"oidc,omitempty"`

	// AuthProvider selects how requests are authenticated:
	//   dev  — embedded development IdP (loopback only);
	//   http — external service implementing the auth contract
	//          (auth-bridge/Keycloak, or a custom adapter).
	// Absent = legacy auth-bridge via oidc/-authBridge.
	AuthProvider *AuthProviderConfig `json:"authProvider,omitempty"`

	// TokenBroker: internal per-user credential broker, used only
	// by routes declaring upstream.delegated. The shared secret is
	// read from the named environment variable at load; it is never
	// serialized.
	TokenBroker *TokenBrokerConfig `json:"tokenBroker,omitempty"`

	// MCPDefaults: optional defaults shared by every MCP access unit
	// (currently the scope).
	MCPDefaults *MCPDefaults `json:"mcpDefaults,omitempty"`

	// MCPSets: named groups of MCP services exposed with their own
	// access rights (resource/scope/identity) and per-member tool
	// filters.
	MCPSets map[string]*MCPSet `json:"mcpSets,omitempty"`

	// License: optional offline signed licence (see internal/license).
	// Absent/invalid/expired = evaluation/personal mode (the gateway
	// keeps serving; the guard badge only shows a notice).
	License *license.Config `json:"license,omitempty"`

	// SecurityHeaders: platform-wide response hardening (HSTS,
	// X-Content-Type-Options, Referrer-Policy), emitted on every
	// response the gateway serves. Absent = nothing (a deploy behind
	// an edge proxy that already sets them can opt out).
	SecurityHeaders *SecurityHeadersPolicy `json:"securityHeaders,omitempty"`

	Routes []Route `json:"routes"`
}

// MCPDefaults: optional defaults for MCP access units.
type MCPDefaults struct {
	// Scope: default MCP scope when a service/set declares none.
	Scope string `json:"scope,omitempty"`
}

// MCPSet: an MCP access unit grouping services under one endpoint.
type MCPSet struct {
	// Host: public host serving the set.
	Host string `json:"host"`
	// Endpoint: mount path of the set on that host ("/" allowed).
	Endpoint string `json:"endpoint"`
	// Resource: OAuth protected-resource identifier (audience) of the
	// set. Empty = the set endpoint URL.
	Resource string `json:"resource,omitempty"`
	// Scope: MCP scope required from clients of this set.
	Scope string `json:"scope,omitempty"`
	// Identity: post-auth conditions applied to every member.
	Identity *Match `json:"identity,omitempty"`
	// Enabled: expose the set (default true). false = the whole set is
	// skipped — no endpoint, no validation — an easy way to disable a
	// group without removing it (its services then need another set or
	// their own rights).
	Enabled *bool `json:"enabled,omitempty"`
	// Members: services exposed under this set.
	Members []MCPSetMember `json:"members"`
}

// IsEnabled reports whether the set is active (default true).
func (s *MCPSet) IsEnabled() bool {
	return s == nil || s.Enabled == nil || *s.Enabled
}

// MCPSetMember: one service mounted under a set.
type MCPSetMember struct {
	// Service: mcp.name of the referenced service.
	Service string `json:"service"`
	// Path: path relative to the set endpoint ("/" = the set
	// endpoint itself).
	Path string `json:"path"`
	// Tools: optional glob allow-list restricting the service's tools
	// inside this set.
	Tools []string `json:"tools,omitempty"`
	// Enabled: expose this member (default true). false = the member is
	// not materialized, and its service is neither compiled (no OpenAPI
	// fetch) nor provider-validated — a safe way to prepare a source
	// whose provider or document is not available yet. The member's
	// structure is still validated, so enabling it later is a one-line
	// change.
	Enabled *bool `json:"enabled,omitempty"`
}

// IsEnabled reports whether the member is exposed (default true).
func (m *MCPSetMember) IsEnabled() bool {
	return m == nil || m.Enabled == nil || *m.Enabled
}

// TokenBrokerConfig: connection to the internal token broker.
type TokenBrokerConfig struct {
	// URL: broker base URL (default http://token-broker:4000 —
	// Docker network service name).
	URL string `json:"url,omitempty"`
	// SecretEnv: name of the environment variable carrying the
	// X-Broker-Secret shared secret (default
	// TOKEN_BROKER_SHARED_SECRET).
	SecretEnv string `json:"secretEnv,omitempty"`
	// SecretValue: resolved secret — never serialized.
	SecretValue string `json:"-"`
}

// OIDCConfig: the platform's IdP (top-level block). loginUrl =
// default login page for frontend routes with an active guard
// (overridable per route via authGuard.loginUrl); issuer = OIDC
// issuer advertised in the OAuth metadata of MCP routes.
type OIDCConfig struct {
	LoginURL string `json:"loginUrl,omitempty"`
	Issuer   string `json:"issuer,omitempty"`
}

// AuthProviderConfig selects and configures the authentication
// provider. Three implementations are possible behind the same
// contract; only the ones implemented by this build are accepted.
type AuthProviderConfig struct {
	// Type: dev | http. Empty = http (or dev when the dev block is
	// present).
	Type string `json:"type,omitempty"`

	// BaseURL: service root for type http (default
	// http://auth-bridge:3000, or AUTH_BRIDGE_URL).
	BaseURL string `json:"baseUrl,omitempty"`

	// LoginBaseURL: public origin of the login service. For dev it
	// hosts the embedded login page (e.g.
	// http://login.demo.localhost:3000).
	LoginBaseURL string `json:"loginBaseUrl,omitempty"`

	// LoginURL: full login page URL. Defaults to
	// LoginBaseURL + "/login"; for type http it defaults to the
	// legacy oidc.loginUrl, then BaseURL + "/login".
	LoginURL string `json:"loginUrl,omitempty"`

	// Issuer: OIDC issuer advertised in MCP metadata. Defaults to
	// the legacy oidc.issuer, or LoginBaseURL + "/dev" for dev.
	Issuer string `json:"issuer,omitempty"`

	// CookieDomain: shared parent domain for the session cookie
	// (dev). e.g. demo.localhost.
	CookieDomain string `json:"cookieDomain,omitempty"`

	// Endpoint overrides (type http). Defaults:
	// BaseURL + /auth, /auth/mcp, /health.
	VerifyURL    string `json:"verifyUrl,omitempty"`
	MCPVerifyURL string `json:"mcpVerifyUrl,omitempty"`
	HealthURL    string `json:"healthUrl,omitempty"`

	// Headers maps the identity response headers (type http).
	Headers *AuthHeadersConfig `json:"headers,omitempty"`

	// OIDC native Relying Party (type oidc).
	ClientID          string   `json:"clientId,omitempty"`
	ClientSecretEnv   string   `json:"clientSecretEnv,omitempty"`
	ClientSecret      string   `json:"-"`
	Scopes            []string `json:"scopes,omitempty"`
	RedirectURL       string   `json:"redirectUrl,omitempty"`
	RoleClaims        []string `json:"roleClaims,omitempty"`
	ScopesClaim       string   `json:"scopesClaim,omitempty"`
	MCPAudience       string   `json:"mcpAudience,omitempty"`
	SessionTTLSeconds int      `json:"sessionTtlSeconds,omitempty"`

	// Dev configures the embedded provider.
	Dev *DevAuthConfig `json:"dev,omitempty"`
}

// AuthHeadersConfig maps the Gate One identity contract to the
// response headers of an external provider. Empty = auth-bridge
// defaults.
type AuthHeadersConfig struct {
	UserID   string `json:"userId,omitempty"`
	Username string `json:"username,omitempty"`
	Email    string `json:"email,omitempty"`
	Roles    string `json:"roles,omitempty"`
	Scopes   string `json:"scopes,omitempty"`
	Claims   string `json:"claims,omitempty"`
}

// DevAuthConfig configures the embedded development IdP.
type DevAuthConfig struct {
	// Users: empty = alice/alice and bob/bob.
	Users []DevUserConfig `json:"users,omitempty"`
	// SessionTTLSeconds defaults to 43200 (12h).
	SessionTTLSeconds int `json:"sessionTtlSeconds,omitempty"`
}

// DevUserConfig is one development account. Passwords are plaintext
// by design: this provider is loopback-only.
type DevUserConfig struct {
	Username string         `json:"username"`
	Password string         `json:"password"`
	Roles    []string       `json:"roles,omitempty"`
	Scopes   []string       `json:"scopes,omitempty"`
	Claims   map[string]any `json:"claims,omitempty"`
	MCPToken string         `json:"mcpToken,omitempty"`
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

// ForbiddenPolicy returns the route's authGuard.forbidden policy, if
// any (nil = the identity-403 UX is left at its default: raw JSON for
// fetches, built-in HTML page for navigations).
func (r *Route) ForbiddenPolicy() *AuthGuardForbiddenPolicy {
	if r == nil || r.AuthGuard == nil {
		return nil
	}
	return r.AuthGuard.Forbidden
}

// MCPActive: does the route expose an MCP server?
func (r *Route) MCPActive() bool {
	return r.MCP != nil && r.MCP.Enabled
}

// DelegatedCredentials returns the route's per-user upstream
// credential policy, if any. Delegation is declared under upstream
// because it describes how the backend is called.
func (r *Route) DelegatedCredentials() *DelegatedCredentialPolicy {
	if r == nil || r.Upstream == nil {
		return nil
	}
	return r.Upstream.Delegated
}

// LoginURLFor: a route's login URL — authGuard.loginUrl
// (route) wins over the platform provider. Guaranteed non-empty by
// load-time validation for any route that can actually log in.
func (c *Config) LoginURLFor(route *Route) string {
	if route.AuthGuard != nil && route.AuthGuard.LoginURL != "" {
		return route.AuthGuard.LoginURL
	}
	if c.AuthProvider != nil && c.AuthProvider.LoginURL != "" {
		return c.AuthProvider.LoginURL
	}
	if c.OIDC != nil {
		return c.OIDC.LoginURL
	}
	return ""
}

// AuthIssuer is the OIDC issuer advertised in MCP metadata
// (authProvider first, legacy oidc fallback).
func (c *Config) AuthIssuer() string {
	if c.AuthProvider != nil && c.AuthProvider.Issuer != "" {
		return c.AuthProvider.Issuer
	}
	if c.OIDC != nil {
		return c.OIDC.Issuer
	}
	return ""
}

// LoadOptions carries CLI/environment overrides into the config
// loader. They are resolved before validation so -check and startup
// see exactly the same provider.
type LoadOptions struct {
	// AuthBridgeURL: -authBridge flag (highest precedence for the
	// legacy http provider).
	AuthBridgeURL string
}

func Load(path string) (*Config, error) {
	return LoadWithOptions(path, LoadOptions{})
}

func LoadWithOptions(path string, opts LoadOptions) (*Config, error) {

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

	// Token broker shared secret resolved from the environment
	// BEFORE validation. A delegated route without a usable broker
	// configuration refuses startup instead of serving requests
	// without credentials.
	if err := cfg.resolveTokenBroker(); err != nil {
		return nil, fmt.Errorf("%s: %v", path, err)
	}

	// Authentication provider: explicit authProvider block, or a
	// legacy (oidc + auth-bridge) translation. Resolved before
	// validation so LoginURLFor/AuthIssuer see the final values.
	if err := cfg.resolveAuthProvider(opts.AuthBridgeURL); err != nil {
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

	// Cross-route rewrite map: automatic wildcard siblings + explicit
	// rewriteBody.targets + rewriteBody.followRoutes, resolved against
	// the expanded route table. Compiled once here; a bad target, an
	// unmatched selector or an ambiguous origin refuses the load.
	if err := cfg.compileRewriteTargets(); err != nil {
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
	// Schema: optional reference to inject-bundle.schema.json (editor
	// autocompletion/validation) — ignored at runtime.
	Schema string `json:"$schema,omitempty"`

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
	if c.SecurityHeaders != nil {
		if err := validateSecurityHeaders(c.SecurityHeaders); err != nil {
			return err
		}
	}
	for i := range c.Routes {
		host := c.Routes[i].Host
		route := &c.Routes[i]

		// A login URL is required only when a BROWSER route can
		// actually log a user in: an authenticated frontend route, or
		// a frontend user badge whose logout button needs the login
		// origin. API routes only answer 401, and a purely public
		// frontend route starts with no oidc/authProvider block at all
		// (the onboarding "static site" case).
		if route.Frontend &&
			(route.Auth != nil || route.UserBadge != nil) &&
			c.LoginURLFor(route) == "" {
			return fmt.Errorf(
				"route %s: authentication is configured but no login URL is available\n"+
					"hint: set authProvider.loginUrl, or use authProvider.type \"dev\" for "+
					"local onboarding, or authGuard.loginUrl on this route",
				host)
		}

		if route.MCPActive() && c.AuthIssuer() == "" {
			return fmt.Errorf(
				"route %s: MCP active without an OIDC issuer\n"+
					"hint: set authProvider.issuer (or the legacy oidc.issuer)",
				host)
		}

		if err := validateAuth(route); err != nil {
			return fmt.Errorf("route %s: %v", host, err)
		}

		if err := validateStripPrefix(route); err != nil {
			return fmt.Errorf("route %s: %v", host, err)
		}

		if err := validateDelegatedCredentials(route); err != nil {
			return fmt.Errorf("route %s: %v", host, err)
		}

		if err := validateMCPUpstream(route); err != nil {
			return fmt.Errorf("route %s: %v", host, err)
		}

		if route.MCPActive() {
			if err := validateMCPStaticHeaders(route); err != nil {
				return fmt.Errorf("route %s: %v", host, err)
			}
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

		if csp := route.CSP; csp != nil {
			if err := validateCSP(csp); err != nil {
				return fmt.Errorf("route %s: %v", host, err)
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

		if up := c.Routes[i].Upstream; up != nil {
			switch up.StripCookies {
			case "", "all", "none":
			default:
				return fmt.Errorf(
					"route %s: upstream.stripCookies %q (expected \"all\" or \"none\")",
					host, up.StripCookies)
			}
			for _, name := range up.Keep {
				if name == "" || strings.ContainsAny(name, " \t\r\n;=\"") {
					return fmt.Errorf(
						"route %s: upstream.keep %q (invalid cookie name)",
						host, name)
				}
				if IsReservedCookieName(name) {
					return fmt.Errorf(
						"route %s: upstream.keep %q — name reserved for the gateway session, never forwarded to an external origin",
						host, name)
				}
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
	if err := c.validateMCPSets(); err != nil {
		return err
	}
	return nil
}

// validateMCPSets checks the MCP services/sets model:
//   - mcp.name is unique; a standalone service has its own access
//     unit (auth), a non-standalone one belongs to at least one set;
//   - each set has a host, an endpoint, an explicit absolute resource
//     and at least one member;
//   - members reference an existing service, have unique paths and
//     valid tool globs;
//   - composed endpoints and access-unit resources are unique;
//   - a host carrying several sets emits a compatibility warning.
func (c *Config) validateMCPSets() error {
	services := map[string]*Route{}
	standalone := map[string]bool{}

	for i := range c.Routes {
		r := &c.Routes[i]
		if r.MCP == nil || !r.MCP.Enabled || r.MCP.Name == "" {
			continue
		}
		if _, dup := services[r.MCP.Name]; dup {
			return fmt.Errorf(
				"route %s: mcp.name %q declared twice",
				r.Host, r.MCP.Name)
		}
		services[r.MCP.Name] = r
		standalone[r.MCP.Name] = r.MCP.IsStandalone()

		if !r.MCP.IsStandalone() {
			continue
		}
		// No MCP exposed without an access unit: a standalone
		// service must require authentication.
		if r.Auth == nil {
			return fmt.Errorf(
				"route %s: standalone MCP service %q requires auth "+
					"(no MCP without an access unit)",
				r.Host, r.MCP.Name)
		}
		if r.MCP.Resource != "" {
			u, err := url.Parse(r.MCP.Resource)
			if err != nil || u.Scheme == "" || u.Host == "" {
				return fmt.Errorf(
					"route %s: mcp.resource %q must be an absolute URL",
					r.Host, r.MCP.Resource)
			}
		}
	}

	resources := map[string]string{}
	for name, r := range services {
		if !standalone[name] || r.MCP.Resource == "" {
			continue
		}
		if other, dup := resources[r.MCP.Resource]; dup {
			return fmt.Errorf(
				"mcp.resource %q used by %s and service %q",
				r.MCP.Resource, other, name)
		}
		resources[r.MCP.Resource] = "service " + name
	}

	// existing public paths per host, for collision checks (a
	// non-standalone service is not exposed directly)
	routePaths := map[string]bool{}
	for i := range c.Routes {
		r := &c.Routes[i]
		if r.MCP != nil && r.MCP.Enabled && !r.MCP.IsStandalone() {
			continue
		}
		p := r.Path
		if r.MCP != nil && r.MCP.Enabled {
			p = r.MCP.AccessPath(r.Path)
		}
		routePaths[normalizeHostName(r.Host)+"|"+
			normalizeMCPEndpoint(p)] = true
	}

	referenced := map[string]bool{}
	composed := map[string]string{}
	setsByHost := map[string]int{}

	for name, set := range c.MCPSets {
		if set == nil {
			return fmt.Errorf("mcpSets[%q]: empty set", name)
		}
		if !set.IsEnabled() {
			// A disabled set is skipped entirely: no endpoint, no
			// member validation, and it does not reference services.
			continue
		}
		if strings.TrimSpace(set.Host) == "" {
			return fmt.Errorf("mcpSets[%q]: host required", name)
		}
		if !strings.HasPrefix(strings.TrimSpace(set.Endpoint), "/") {
			return fmt.Errorf(
				"mcpSets[%q]: endpoint must start with /", name)
		}
		ep := normalizeMCPEndpoint(set.Endpoint)
		if ep == "" {
			return fmt.Errorf("mcpSets[%q]: endpoint required", name)
		}

		// hasLive: at least one enabled member. A set whose members are
		// all disabled is a placeholder: no endpoint, no resource
		// reservation, no host count.
		hasLive := false
		for _, m := range set.Members {
			if m.IsEnabled() {
				hasLive = true
				break
			}
		}

		if set.Resource != "" {
			if u, err := url.Parse(set.Resource); err != nil ||
				u.Scheme == "" || u.Host == "" {
				return fmt.Errorf(
					"mcpSets[%q]: resource %q must be an absolute URL",
					name, set.Resource)
			}
			if hasLive {
				if other, dup := resources[set.Resource]; dup {
					return fmt.Errorf(
						"mcpSets[%q]: resource %q already used by %s",
						name, set.Resource, other)
				}
				resources[set.Resource] = "set " + name
			}
		}
		if id := set.Identity; id != nil &&
			(id.Method != "" || len(id.Query) > 0 ||
				len(id.Header) > 0 || len(id.Body) > 0) {
			return fmt.Errorf(
				"mcpSets[%q].identity: technical conditions belong in "+
					"a route's auth.when", name)
		}
		if len(set.Members) == 0 {
			return fmt.Errorf(
				"mcpSets[%q]: at least one member required", name)
		}
		if hasLive {
			setsByHost[normalizeHostName(set.Host)]++
		}

		memberPaths := map[string]bool{}
		for _, m := range set.Members {
			if _, ok := services[m.Service]; !ok {
				return fmt.Errorf(
					"mcpSets[%q]: unknown service %q\n"+
						"hint: declare a route whose mcp.name is %q with mcp.enabled=true, "+
						"or remove this member / disable it (members[].enabled=false)",
					name, m.Service, m.Service)
			}
			referenced[m.Service] = true

			if !strings.HasPrefix(strings.TrimSpace(m.Path), "/") {
				return fmt.Errorf(
					"mcpSets[%q] member %q: path must start with /",
					name, m.Service)
			}
			mp := normalizeMCPEndpoint(m.Path)
			if memberPaths[mp] {
				return fmt.Errorf(
					"mcpSets[%q]: duplicate member path %q",
					name, mp)
			}
			memberPaths[mp] = true

			for _, g := range m.Tools {
				if _, err := path.Match(g, ""); err != nil {
					return fmt.Errorf(
						"mcpSets[%q] member %q: invalid tool pattern %q: %v",
						name, m.Service, g, err)
				}
			}

			if !m.IsEnabled() {
				// Prepared but not exposed: the structure above is
				// validated, no endpoint collision (not materialized).
				continue
			}

			full := joinMCPEndpoint(ep, mp)
			key := normalizeHostName(set.Host) + "|" + full
			if other, dup := composed[key]; dup {
				return fmt.Errorf(
					"mcpSets[%q]: endpoint %s already used by %s",
					name, full, other)
			}
			if routePaths[key] {
				return fmt.Errorf(
					"mcpSets[%q]: endpoint %s collides with an existing route",
					name, full)
			}
			composed[key] = "set " + name
		}
	}

	for name := range services {
		if !standalone[name] && !referenced[name] {
			return fmt.Errorf(
				"MCP service %q is not standalone and belongs to no mcpSet\n"+
					"hint: give it its own rights (mcp.standalone=true with auth) or "+
					"reference it from an mcpSet member",
				name)
		}
	}

	for host, n := range setsByHost {
		if n > 1 {
			log.Printf(
				"WARNING: host %s carries %d MCP sets; clients that "+
					"only support origin-based RFC 9728 metadata will "+
					"only see one.\n"+
					"hint: serve each set from its own host (one host per "+
					"set); per-endpoint metadata lives at "+
					"/.well-known/oauth-protected-resource<set endpoint>",
				host, n)
		}
	}

	return nil
}

// normalizeMCPEndpoint normalizes a public path prefix: leading slash,
// no trailing slash (except "/").
func normalizeMCPEndpoint(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return ""
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	p = strings.TrimRight(p, "/")
	if p == "" {
		p = "/"
	}
	return p
}

// joinMCPEndpoint joins a set endpoint and a member path.
func joinMCPEndpoint(base, rel string) string {
	base = normalizeMCPEndpoint(base)
	rel = normalizeMCPEndpoint(rel)
	switch {
	case rel == "/":
		return base
	case base == "/":
		return rel
	default:
		return base + rel
	}
}

// resolveAuthProvider materializes the authentication provider
// configuration:
//
//   - an explicit authProvider block is completed with defaults;
//   - without it, a legacy (oidc + auth-bridge) configuration is
//     translated to an http provider, so existing deployments keep
//     working unchanged.
//
// The provider itself is constructed by the proxy (it needs the
// listen address and the route hosts).
func (c *Config) resolveAuthProvider(authBridgeURL string) error {
	authBridgeURL = strings.TrimRight(strings.TrimSpace(authBridgeURL), "/")

	if c.AuthProvider == nil {
		if c.OIDC == nil && authBridgeURL == "" {
			return nil
		}
		ap := &AuthProviderConfig{Type: "http"}
		if c.OIDC != nil {
			ap.LoginURL = c.OIDC.LoginURL
			ap.Issuer = c.OIDC.Issuer
		}
		if authBridgeURL != "" {
			ap.BaseURL = authBridgeURL
		}
		c.AuthProvider = ap
	}

	ap := c.AuthProvider
	if ap.Type == "" {
		switch {
		case ap.Dev != nil:
			ap.Type = "dev"
		case ap.ClientID != "" || ap.ClientSecretEnv != "":
			ap.Type = "oidc"
		default:
			ap.Type = "http"
		}
	}

	switch ap.Type {

	case "dev":
		if ap.LoginBaseURL == "" && ap.LoginURL != "" {
			if u, err := url.Parse(ap.LoginURL); err == nil && u.Host != "" {
				ap.LoginBaseURL = u.Scheme + "://" + u.Host
			}
		}
		ap.LoginBaseURL = strings.TrimRight(
			strings.TrimSpace(ap.LoginBaseURL), "/")
		if ap.LoginBaseURL == "" {
			return fmt.Errorf(
				"authProvider.type dev: loginBaseUrl is required " +
					"(e.g. http://login.demo.localhost:3000)")
		}
		u, err := url.Parse(ap.LoginBaseURL)
		if err != nil || u.Host == "" {
			return fmt.Errorf(
				"authProvider.loginBaseUrl %q: invalid URL", ap.LoginBaseURL)
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return fmt.Errorf(
				"authProvider.loginBaseUrl %q: scheme must be http or https",
				ap.LoginBaseURL)
		}
		if u.RawQuery != "" || u.Fragment != "" {
			return fmt.Errorf(
				"authProvider.loginBaseUrl %q: query and fragment forbidden",
				ap.LoginBaseURL)
		}
		if u.Path != "" && u.Path != "/" {
			return fmt.Errorf(
				"authProvider.loginBaseUrl %q: a path is not supported "+
					"(use an origin such as http://login.example.com:3000)",
				ap.LoginBaseURL)
		}
		if ap.LoginURL == "" {
			ap.LoginURL = ap.LoginBaseURL + "/login"
		}
		if ap.Issuer == "" {
			ap.Issuer = ap.LoginBaseURL + "/dev"
		}
		ap.CookieDomain = strings.Trim(
			strings.ToLower(strings.TrimSpace(ap.CookieDomain)), ".")
		if ap.CookieDomain == "" {
			return fmt.Errorf(
				"authProvider.type dev: cookieDomain is required " +
					"(e.g. demo.localhost)")
		}
		if ap.Dev == nil {
			ap.Dev = &DevAuthConfig{}
		}
		if ap.Dev.SessionTTLSeconds < 0 {
			return fmt.Errorf(
				"authProvider.dev.sessionTtlSeconds: must be positive")
		}
		seenUsers := map[string]bool{}
		seenTokens := map[string]bool{}
		for i, du := range ap.Dev.Users {
			name := strings.TrimSpace(du.Username)
			if name == "" {
				return fmt.Errorf(
					"authProvider.dev.users[%d]: username is required", i)
			}
			if du.Password == "" {
				return fmt.Errorf(
					"authProvider.dev.users[%d] (%s): password is required",
					i, name)
			}
			if seenUsers[name] {
				return fmt.Errorf(
					"authProvider.dev.users: duplicate username %q", name)
			}
			seenUsers[name] = true
			token := du.MCPToken
			if token == "" {
				token = "dev-" + name
			}
			if seenTokens[token] {
				return fmt.Errorf(
					"authProvider.dev.users: duplicate mcpToken %q", token)
			}
			seenTokens[token] = true
		}

	case "oidc":
		if ap.LoginBaseURL == "" && ap.LoginURL != "" {
			if u, err := url.Parse(ap.LoginURL); err == nil && u.Host != "" {
				ap.LoginBaseURL = u.Scheme + "://" + u.Host
			}
		}
		ap.LoginBaseURL = strings.TrimRight(
			strings.TrimSpace(ap.LoginBaseURL), "/")
		if ap.LoginBaseURL == "" {
			return fmt.Errorf(
				"authProvider.type oidc: loginBaseUrl is required " +
					"(e.g. https://login.example.com)")
		}
		u, err := url.Parse(ap.LoginBaseURL)
		if err != nil || u.Host == "" {
			return fmt.Errorf(
				"authProvider.loginBaseUrl %q: invalid URL", ap.LoginBaseURL)
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return fmt.Errorf(
				"authProvider.loginBaseUrl %q: scheme must be http or https",
				ap.LoginBaseURL)
		}
		if u.RawQuery != "" || u.Fragment != "" ||
			(u.Path != "" && u.Path != "/") {
			return fmt.Errorf(
				"authProvider.loginBaseUrl %q: origin only (no path/query)",
				ap.LoginBaseURL)
		}
		ap.CookieDomain = strings.Trim(
			strings.ToLower(strings.TrimSpace(ap.CookieDomain)), ".")
		if ap.CookieDomain == "" {
			return fmt.Errorf(
				"authProvider.type oidc: cookieDomain is required " +
					"(e.g. example.com)")
		}
		ap.Issuer = strings.TrimSpace(ap.Issuer)
		if ap.Issuer == "" {
			return fmt.Errorf(
				"authProvider.type oidc: issuer is required " +
					"(the IdP discovery issuer, e.g. " +
					"https://auth.example.com/realms/example)")
		}
		iu, err := url.Parse(ap.Issuer)
		if err != nil || iu.Host == "" ||
			(iu.Scheme != "http" && iu.Scheme != "https") {
			return fmt.Errorf(
				"authProvider.issuer %q: invalid http(s) URL", ap.Issuer)
		}
		ap.ClientID = strings.TrimSpace(ap.ClientID)
		if ap.ClientID == "" {
			return fmt.Errorf(
				"authProvider.type oidc: clientId is required")
		}
		ap.ClientSecretEnv = strings.TrimSpace(ap.ClientSecretEnv)
		if ap.ClientSecretEnv != "" {
			if !envVarName.MatchString(ap.ClientSecretEnv) {
				return fmt.Errorf(
					"authProvider.clientSecretEnv %q: invalid environment variable name",
					ap.ClientSecretEnv)
			}
			secret, ok := os.LookupEnv(ap.ClientSecretEnv)
			if !ok || secret == "" {
				return fmt.Errorf(
					"authProvider.type oidc: environment variable %s is empty",
					ap.ClientSecretEnv)
			}
			ap.ClientSecret = secret
		}
		if ap.LoginURL == "" {
			ap.LoginURL = ap.LoginBaseURL + "/login"
		}
		if ap.RedirectURL == "" {
			ap.RedirectURL = ap.LoginBaseURL + "/auth/callback"
		}
		ru, err := url.Parse(ap.RedirectURL)
		if err != nil || ru.Host == "" ||
			(ru.Scheme != "http" && ru.Scheme != "https") {
			return fmt.Errorf(
				"authProvider.redirectUrl %q: invalid http(s) URL",
				ap.RedirectURL)
		}
		if ap.SessionTTLSeconds < 0 {
			return fmt.Errorf(
				"authProvider.sessionTtlSeconds: must be positive")
		}

	case "http":
		if authBridgeURL != "" {
			// CLI flag: highest precedence, and it resets derived
			// endpoints so they follow the new base.
			ap.BaseURL = authBridgeURL
			ap.VerifyURL = ""
			ap.MCPVerifyURL = ""
			ap.HealthURL = ""
		}
		base := strings.TrimRight(
			strings.TrimSpace(ap.BaseURL), "/")
		if base == "" {
			base = strings.TrimRight(
				strings.TrimSpace(os.Getenv("AUTH_BRIDGE_URL")), "/")
		}
		if base == "" {
			base = "http://auth-bridge:3000"
		}
		ap.BaseURL = base
		u, err := url.Parse(base)
		if err != nil || u.Host == "" {
			return fmt.Errorf(
				"authProvider.baseUrl %q: invalid URL", base)
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return fmt.Errorf(
				"authProvider.baseUrl %q: scheme must be http or https",
				base)
		}
		if ap.VerifyURL == "" {
			ap.VerifyURL = base + "/auth"
		}
		if ap.MCPVerifyURL == "" {
			ap.MCPVerifyURL = base + "/auth/mcp"
		}
		if ap.HealthURL == "" {
			ap.HealthURL = base + "/health"
		}
		if ap.LoginURL == "" {
			if c.OIDC != nil && c.OIDC.LoginURL != "" {
				ap.LoginURL = c.OIDC.LoginURL
			} else {
				ap.LoginURL = base + "/login"
			}
		}
		if ap.Issuer == "" && c.OIDC != nil {
			ap.Issuer = c.OIDC.Issuer
		}
		for name, raw := range map[string]string{
			"loginUrl":     ap.LoginURL,
			"verifyUrl":    ap.VerifyURL,
			"mcpVerifyUrl": ap.MCPVerifyURL,
			"healthUrl":    ap.HealthURL,
		} {
			if raw == "" {
				continue
			}
			pu, err := url.Parse(raw)
			if err != nil || pu.Host == "" ||
				(pu.Scheme != "http" && pu.Scheme != "https") {
				return fmt.Errorf(
					"authProvider.%s %q: invalid http(s) URL", name, raw)
			}
		}

	default:
		return fmt.Errorf(
			"authProvider.type %q: unknown provider "+
				"(expected dev, http or oidc)",
			ap.Type)
	}

	return nil
}

// resolveTokenBroker loads the shared secret for routes that use
// delegated upstream credentials. No delegated route = no broker
// dependency (the service remains optional in deployments).
func (c *Config) resolveTokenBroker() error {
	needs := false
	for i := range c.Routes {
		if c.Routes[i].DelegatedCredentials() != nil {
			needs = true
			break
		}
	}
	if !needs {
		return nil
	}

	if c.TokenBroker == nil {
		return fmt.Errorf(
			"tokenBroker block required by upstream.delegated")
	}
	tb := c.TokenBroker

	if tb.URL == "" {
		tb.URL = strings.TrimSpace(os.Getenv("TOKEN_BROKER_URL"))
		if tb.URL == "" {
			tb.URL = "http://token-broker:4000"
		}
	}
	u, err := url.Parse(tb.URL)
	if err != nil || u.Host == "" {
		return fmt.Errorf("tokenBroker.url %q: invalid URL", tb.URL)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf(
			"tokenBroker.url %q: scheme must be http or https", tb.URL)
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf(
			"tokenBroker.url %q: query and fragment forbidden", tb.URL)
	}

	if tb.SecretEnv == "" {
		tb.SecretEnv = "TOKEN_BROKER_SHARED_SECRET"
	}
	if !envVarName.MatchString(tb.SecretEnv) {
		return fmt.Errorf(
			"tokenBroker.secretEnv %q: invalid environment variable name",
			tb.SecretEnv)
	}
	secret, ok := os.LookupEnv(tb.SecretEnv)
	if !ok || secret == "" {
		return fmt.Errorf(
			"tokenBroker: environment variable %s is empty",
			tb.SecretEnv)
	}
	tb.SecretValue = secret
	return nil
}

var envVarName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

var delegatedProviderName = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

// RFC 7230 token characters (header field name).
var headerFieldName = regexp.MustCompile("^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")

// validateAuth enforces the strict split between the two condition
// families of the authentication policy: auth.when accepts technical
// conditions only (method/query/header/body — they decide WHETHER
// authentication is required), auth.identity accepts identity
// conditions only (roles/scopes/claims/user — checked after
// authentication). Mixing them is refused at load rather than
// silently reinterpreted.
func validateAuth(route *Route) error {

	a := route.Auth
	if a == nil {
		return nil
	}

	for i := range a.When {
		if m := a.When[i]; len(m.Roles) > 0 || len(m.Scopes) > 0 ||
			len(m.Claims) > 0 || m.User != "" {
			return fmt.Errorf(
				"auth.when[%d]: identity conditions (roles/scopes/claims/user) belong in auth.identity, not auth.when",
				i)
		}
	}

	if id := a.Identity; id != nil {
		if id.Method != "" || len(id.Query) > 0 || len(id.Header) > 0 ||
			len(id.Body) > 0 {
			return fmt.Errorf(
				"auth.identity: technical conditions (method/query/header/body) belong in auth.when, not auth.identity")
		}
	}

	return nil
}

// validateDelegatedCredentials normalizes and validates the
// upstream.delegated policy. The constraints keep the gateway in
// control of its own identity headers and of hop-by-hop headers.
func validateDelegatedCredentials(route *Route) error {
	d := route.DelegatedCredentials()
	if d == nil {
		return nil
	}

	if route.Auth == nil {
		return fmt.Errorf(
			"upstream.delegated requires auth (a user token is needed)")
	}
	if !delegatedProviderName.MatchString(d.Provider) {
		return fmt.Errorf(
			"upstream.delegated.provider %q (expected lowercase name)",
			d.Provider)
	}

	header := d.HeaderValue()
	if !headerFieldName.MatchString(header) {
		return fmt.Errorf(
			"upstream.delegated.header %q: invalid header name", header)
	}
	header = http.CanonicalHeaderKey(header)
	d.Header = header

	lower := strings.ToLower(header)
	switch lower {
	case "host", "cookie", "content-length", "transfer-encoding",
		"connection", "proxy-authorization", "proxy-authenticate",
		"te", "trailer", "upgrade", "keep-alive", "forwarded",
		"x-user-id", "x-username", "x-email", "x-roles", "x-scopes":
		return fmt.Errorf(
			"upstream.delegated.header %q is reserved", header)
	}
	if strings.HasPrefix(lower, "x-forwarded-") ||
		strings.HasPrefix(lower, "x-gate-one-") {
		return fmt.Errorf(
			"upstream.delegated.header %q is reserved", header)
	}

	for name := range route.Upstream.Headers {
		if strings.EqualFold(name, header) {
			return fmt.Errorf(
				"upstream.headers[%q] conflicts with upstream.delegated.header",
				name)
		}
	}

	if strings.ContainsAny(d.PrefixValue(), "\r\n") {
		return fmt.Errorf(
			"upstream.delegated.prefix: control characters forbidden")
	}

	return nil
}

// validateMCPUpstream checks the external MCP proxy policy. The
// URL may be empty (route backend); static upstream headers must not
// override the MCP transport or the gateway identity.
func validateMCPUpstream(route *Route) error {
	if route.MCP == nil || !route.MCP.Enabled || route.MCP.Upstream == nil {
		return nil
	}
	up := route.MCP.Upstream

	if len(route.MCP.Operations) > 0 {
		return fmt.Errorf(
			"mcp.upstream and mcp.operations are mutually exclusive")
	}

	if up.URL != "" {
		u, err := url.Parse(up.URL)
		if err != nil || u.Host == "" {
			return fmt.Errorf("mcp.upstream.url %q: invalid URL", up.URL)
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return fmt.Errorf(
				"mcp.upstream.url %q: scheme must be http or https",
				up.URL)
		}
		if u.Fragment != "" {
			return fmt.Errorf(
				"mcp.upstream.url %q: fragment forbidden", up.URL)
		}
		if u.User != nil {
			return fmt.Errorf(
				"mcp.upstream.url %q: userinfo forbidden (use upstream.headers)", up.URL)
		}
	}

	if up.Tools != nil {
		for _, p := range append(
			append([]string{}, up.Tools.Include...),
			up.Tools.Exclude...,
		) {
			if p == "" {
				return fmt.Errorf(
					"mcp.upstream.tools: empty pattern")
			}
			if _, err := path.Match(p, ""); err != nil {
				return fmt.Errorf(
					"mcp.upstream.tools: invalid pattern %q: %v", p, err)
			}
		}
	}

	return nil
}

// validateMCPStaticHeaders rejects upstream.headers that would override
// the MCP transport or the gateway identity. Applied to every MCP route
// (local REST-derived tools or external MCP proxy), because those
// headers now reach the tool calls. Plain REST routes are unaffected
// (they legitimately use Authorization/Accept/Cookie).
func validateMCPStaticHeaders(route *Route) error {
	if route.Upstream == nil {
		return nil
	}
	for name, value := range route.Upstream.Headers {
		if !headerFieldName.MatchString(name) {
			return fmt.Errorf(
				"upstream.headers[%q]: invalid header name", name)
		}
		lower := strings.ToLower(name)
		switch lower {
		case "host", "content-length", "transfer-encoding",
			"connection", "cookie", "content-type", "accept",
			"accept-encoding", "content-encoding", "expect",
			"proxy-authorization", "proxy-authenticate", "te",
			"trailer", "upgrade", "keep-alive", "forwarded",
			"x-user-id", "x-username", "x-email", "x-roles",
			"x-scopes", "mcp-session-id", "mcp-protocol-version",
			"mcp-method", "mcp-name", "last-event-id":
			return fmt.Errorf(
				"upstream.headers[%q] is reserved for the MCP proxy",
				name)
		}
		if strings.HasPrefix(lower, "x-forwarded-") ||
			strings.HasPrefix(lower, "x-gate-one-") {
			return fmt.Errorf(
				"upstream.headers[%q] is reserved for the MCP proxy",
				name)
		}
		for i := 0; i < len(value); i++ {
			c := value[i]
			if c == '\r' || c == '\n' ||
				(c < 0x20 && c != '\t') || c == 0x7f {
				return fmt.Errorf(
					"upstream.headers[%q]: control character in value",
					name)
			}
		}
	}
	return nil
}

// maxStripPrefixLen: same bound as the other path-prefix settings.
const maxStripPrefixLen = 256

// validateStripPrefix normalizes and validates route.StripPrefix.
// The prefix is a PUBLIC path prefix: it must overlap the route's
// declared path, otherwise no request could ever be stripped.
func validateStripPrefix(route *Route) error {

	p := route.StripPrefix
	if p == "" {
		return nil
	}

	if !strings.HasPrefix(p, "/") {
		return fmt.Errorf("stripPrefix %q does not start with '/'", p)
	}
	if p == "/" {
		return fmt.Errorf("stripPrefix %q: root prefix forbidden", p)
	}
	if strings.ContainsAny(p, "?#*") {
		return fmt.Errorf("stripPrefix %q contains '?', '#' or '*' (exact path prefix only)", p)
	}
	if len(p) > maxStripPrefixLen {
		return fmt.Errorf("stripPrefix %d bytes (max %d)", len(p), maxStripPrefixLen)
	}
	if strings.Contains(p, "//") {
		return fmt.Errorf("stripPrefix %q contains an empty path segment", p)
	}
	for _, r := range p {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("stripPrefix %q contains a control character", p)
		}
	}

	p = strings.TrimRight(p, "/")
	if p == "" || p == "/" {
		return fmt.Errorf("stripPrefix %q: root prefix forbidden", route.StripPrefix)
	}

	for _, seg := range strings.Split(strings.TrimPrefix(p, "/"), "/") {
		if seg == "." || seg == ".." {
			return fmt.Errorf("stripPrefix %q contains a relative segment", p)
		}
	}

	if !routePathOverlapsPrefix(route.Path, p) {
		return fmt.Errorf(
			"stripPrefix %q is outside route.path %q (no matched request would be stripped)",
			p, route.Path)
	}

	route.StripPrefix = p
	return nil
}

// routePathOverlapsPrefix: does a route path (exact or "/*" form)
// cover at least one path under prefix? "/*" covers everything.
func routePathOverlapsPrefix(routePath, prefix string) bool {
	if routePath == "/*" {
		return true
	}
	base := routePath
	if strings.HasSuffix(base, "/*") {
		base = strings.TrimSuffix(base, "/*")
	}
	return base == prefix || strings.HasPrefix(base, prefix+"/")
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

// bounds of the cross-route rewrite configuration. The compiled map is
// scanned by the streaming engine: a few hundred entries are cheap,
// thousands would not be. maxTargetsEntries applies to the explicit
// targets map; maxRewriteTargets applies to the compiled result
// (automatic wildcard siblings included).
const (
	maxTargetsEntries = 256
	maxRewriteTargets = 1024
	maxFollowRoutes   = 64
	maxRewriteHostLen = 253
)

// compileRewriteTargets builds each route's cross-route rewrite map:
// automatic wildcard siblings, explicit targets (origin host → public
// host) and followRoutes selectors over declared routes. The route
// table is the source of truth: explicit targets must name known
// origins/targets, selectors must match known public hosts, and no
// origin may resolve to two different public hosts.
func (c *Config) compileRewriteTargets() error {

	if len(c.Routes) == 0 {
		return nil
	}

	publicHosts := make(map[string]bool, len(c.Routes))
	declaredOrigins := make(map[string]bool, len(c.Routes))
	for i := range c.Routes {
		r := &c.Routes[i]
		publicHosts[normalizeHostName(r.Host)] = true
		for _, origin := range rewriteOriginHosts(r) {
			declaredOrigins[origin] = true
		}
	}

	for i := range c.Routes {
		r := &c.Routes[i]
		rb := r.UpstreamRewriteBody()
		if rb == nil {
			if up := r.Upstream; up != nil && up.RewriteBody != nil &&
				(len(up.RewriteBody.Targets) > 0 ||
					len(up.RewriteBody.FollowRoutes) > 0) {
				return fmt.Errorf(
					"route %s: rewriteBody.targets/followRoutes require enabled: true",
					r.Host)
			}
			continue
		}

		if len(rb.Targets) > maxTargetsEntries {
			return fmt.Errorf(
				"route %s: rewriteBody.targets: %d entries (max %d)",
				r.Host, len(rb.Targets), maxTargetsEntries)
		}
		if len(rb.FollowRoutes) > maxFollowRoutes {
			return fmt.Errorf(
				"route %s: rewriteBody.followRoutes: %d entries (max %d)",
				r.Host, len(rb.FollowRoutes), maxFollowRoutes)
		}

		selfOrigins := make(map[string]bool)
		for _, origin := range rewriteOriginHosts(r) {
			selfOrigins[origin] = true
		}
		selfHost := normalizeHostName(r.Host)

		// start from the automatic wildcard-expansion map
		targets := make(map[string]string, len(r.rewriteTargets)+len(rb.Targets))
		for origin, host := range r.rewriteTargets {
			targets[origin] = host
		}

		// explicit targets: deterministic error order
		keys := make([]string, 0, len(rb.Targets))
		for k := range rb.Targets {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, rawOrigin := range keys {
			origin, err := validateRewriteHost(
				rawOrigin, "rewriteBody.targets key")
			if err != nil {
				return fmt.Errorf("route %s: %v", r.Host, err)
			}
			if !declaredOrigins[origin] {
				return fmt.Errorf(
					"route %s: rewriteBody.targets[%q]: not an origin of a declared route (backend host or hostOverride)",
					r.Host, rawOrigin)
			}
			rawTarget := rb.Targets[rawOrigin]
			target, err := validateRewriteHost(
				rawTarget, fmt.Sprintf("rewriteBody.targets[%q]", rawOrigin))
			if err != nil {
				return fmt.Errorf("route %s: %v", r.Host, err)
			}
			if !publicHosts[target] {
				return fmt.Errorf(
					"route %s: rewriteBody.targets[%q]: %q is not the public host of a declared route",
					r.Host, rawOrigin, rawTarget)
			}
			if selfOrigins[origin] {
				return fmt.Errorf(
					"route %s: rewriteBody.targets[%q]: this is the route's own origin",
					r.Host, rawOrigin)
			}
			if target == selfHost {
				return fmt.Errorf(
					"route %s: rewriteBody.targets[%q]: target %q is this route's own public host",
					r.Host, rawOrigin, rawTarget)
			}
			if err := mergeRewriteTarget(targets, origin, target); err != nil {
				return fmt.Errorf(
					"route %s: rewriteBody.targets[%q]: %v",
					r.Host, rawOrigin, err)
			}
		}

		// followRoutes: select declared routes by their PUBLIC host,
		// then derive origin → public host from each selected route.
		seenPatterns := make(map[string]bool, len(rb.FollowRoutes))
		for idx, raw := range rb.FollowRoutes {
			pattern, err := validateFollowPattern(raw)
			if err != nil {
				return fmt.Errorf(
					"route %s: rewriteBody.followRoutes[%d]: %v",
					r.Host, idx, err)
			}
			if seenPatterns[pattern] {
				continue
			}
			seenPatterns[pattern] = true

			matched, matchedOther := 0, 0
			for j := range c.Routes {
				tr := &c.Routes[j]
				if !matchRouteHost(pattern, normalizeHostName(tr.Host)) {
					continue
				}
				matched++
				if tr == r {
					continue
				}
				matchedOther++
				target := normalizeHostName(tr.Host)
				if target == selfHost {
					continue
				}
				for _, origin := range rewriteOriginHosts(tr) {
					if selfOrigins[origin] {
						continue // shared/alias origin: self keeps its semantics
					}
					if err := mergeRewriteTarget(targets, origin, target); err != nil {
						return fmt.Errorf(
							"route %s: rewriteBody.followRoutes[%d] (%q) via %s: %v",
							r.Host, idx, raw, tr.Host, err)
					}
				}
			}
			if matched == 0 {
				return fmt.Errorf(
					"route %s: rewriteBody.followRoutes[%d] (%q): matches no declared route",
					r.Host, idx, raw)
			}
			if matchedOther == 0 {
				return fmt.Errorf(
					"route %s: rewriteBody.followRoutes[%d] (%q): matches only this route",
					r.Host, idx, raw)
			}
		}

		if len(targets) > maxRewriteTargets {
			return fmt.Errorf(
				"route %s: %d compiled rewrite targets (max %d)",
				r.Host, len(targets), maxRewriteTargets)
		}
		if len(targets) == 0 {
			targets = nil
		}
		r.rewriteTargets = targets
	}

	return nil
}

// mergeRewriteTarget adds origin → target, refusing a conflicting
// mapping. Same origin + same target is a harmless duplicate (an
// explicit target can repeat an automatic wildcard sibling).
func mergeRewriteTarget(m map[string]string, origin, target string) error {
	if prev, ok := m[origin]; ok {
		if prev != target {
			return fmt.Errorf(
				"origin %s already targets %s (conflict with %s)",
				origin, prev, target)
		}
		return nil
	}
	m[origin] = target
	return nil
}

// validateRewriteHost: a bare hostname for targets/selectors —
// lowercase, no scheme, no port, no path, max 253 bytes, DNS labels
// (a-z0-9, hyphen; no underscore, no empty label). The gateway
// derives the scheme and port from the request.
func validateRewriteHost(raw, what string) (string, error) {
	h := strings.ToLower(strings.TrimSpace(raw))
	if h == "" {
		return "", fmt.Errorf("%s: empty host", what)
	}
	if strings.Contains(h, "://") || strings.ContainsAny(h, "/\\?#@") {
		return "", fmt.Errorf(
			"%s: %q must be a bare host (no scheme, port or path)",
			what, raw)
	}
	if strings.Contains(h, ":") {
		return "", fmt.Errorf(
			"%s: %q must not contain a port", what, raw)
	}
	if len(h) > maxRewriteHostLen {
		return "", fmt.Errorf(
			"%s: %q is %d bytes (max %d)",
			what, raw, len(h), maxRewriteHostLen)
	}
	if strings.HasPrefix(h, ".") || strings.HasSuffix(h, ".") ||
		strings.Contains(h, "..") {
		return "", fmt.Errorf(
			"%s: %q has an empty label", what, raw)
	}
	for _, label := range strings.Split(h, ".") {
		if len(label) > 63 || !wildcardLabel.MatchString(label) {
			return "", fmt.Errorf(
				"%s: %q is not a valid hostname", what, raw)
		}
	}
	return h, nil
}

// validateFollowPattern: exact public host or "*.suffix" (any depth,
// subdomains only — not the bare suffix itself). A bare "*" is refused:
// it would silently map every route and hide ambiguity.
func validateFollowPattern(raw string) (string, error) {
	p := strings.ToLower(strings.TrimSpace(raw))
	if p == "" {
		return "", fmt.Errorf("empty selector")
	}
	if p == "*" {
		return "", fmt.Errorf(
			"%q: bare * is refused; use *.suffix or exact hosts", raw)
	}
	if strings.HasPrefix(p, "*.") {
		suffix, err := validateRewriteHost(
			p[2:], "followRoutes suffix")
		if err != nil {
			return "", err
		}
		return "*." + suffix, nil
	}
	if strings.ContainsAny(p, "*?") {
		return "", fmt.Errorf(
			"%q: wildcard only allowed as a leading *. (e.g. *.example.com)",
			raw)
	}
	h, err := validateRewriteHost(p, "followRoutes selector")
	if err != nil {
		return "", err
	}
	return h, nil
}

// matchRouteHost: exact host or suffix selector. "*.example.com"
// matches a.example.com and a.b.example.com, not example.com.
func matchRouteHost(pattern, host string) bool {
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // ".example.com"
		return strings.HasSuffix(host, suffix) && len(host) > len(suffix)
	}
	return pattern == host
}

// normalizeHostName: lowercase, no port (route hosts are hostnames;
// this mirrors the proxy-side normalizeHost without importing proxy).
func normalizeHostName(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	if i := strings.IndexByte(h, ':'); i >= 0 {
		h = h[:i]
	}
	return h
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
