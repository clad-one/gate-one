// Package pwa implements the declarative PWA wrap of frontend routes:
// it serves /__gate-one_pwa/manifest.json, /__gate-one_pwa/sw.js and the
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

	"cladone/gate-one/internal/core"
)

// Virtual prefix served by the gateway itself, before any route proxying.
const PathPrefix = "/__gate-one_pwa/"

// GatewayInternalPrefix: gateway-served endpoints (auth-state probe,
// stats). They must NEVER be cached by the client runtime: a stale
// identity answer would show the wrong gating after login/logout, and
// the probe explicitly answers Cache-Control: no-store (2026-10-25
// incident: the universal GET cache served a cached "authenticated"
// 200 after logout). Hard-coded like PathPrefix — these paths are the
// gateway's own contract, not a deployment choice.
const GatewayInternalPrefix = "/__gate-one/"

// SwURL: URL of the unified service worker (PWA and/or client-side
// rewriting), served by the gateway pre-authentication,
// pass-through no-cache, requested scope '/'. Shared by the PWA
// injection and the guard script.
const SwURL = PathPrefix + "sw.js"

// SwFile: path component of the SW under the virtual prefix.
const SwFile = "sw.js"

//go:embed workbox
var workboxFS embed.FS

// workboxVersion must match the vendored build in workbox/.
const workboxVersion = "7.4.1"

// apiCacheLogicVersion versions the FORMAT of the API cache entries
// (key shape, stored headers, storeCompleteResponse logic).
// Increment it when the storage logic changes: the existing caches
// will be purged at the new SW's activation. It is deliberately
// independent of the SW hash, so that a deployment that does not
// touch this format does not wipe the offline replay.
const apiCacheLogicVersion = "1"

// apiCachePolicyJSON serializes the declarative policy of an apiCache
// endpoint for its cache's hash: any reconfiguration of the block
// in api-routes.json changes the hash, hence the cache name.
func apiCachePolicyJSON(c any) []byte {
	data, _ := json.Marshal(c)
	return data
}

// RewriteSpec: client-side rewriting data (the route's
// upstream.rewriteBody), serialized into the generated service
// worker. Origins are the origin hosts whose absolute URLs are
// intercepted; Target the default replacement base
// ("https://public.host"); Targets the compiled cross-route map
// origin-host → target public host (wildcard siblings, explicit
// targets and followRoutes; rewritten on the SW's own scheme/port,
// before the exceptions); Except the path-prefix exceptions (sorted:
// longest prefix first), whose entries without To remain at the
// origin.
type RewriteSpec struct {
	Origins []string             `json:"origins"`
	Target  string               `json:"target"`
	Targets map[string]string    `json:"targets,omitempty"`
	Except  []core.RewriteExcept `json:"except,omitempty"`
}

type Handler struct {
	policy *core.PWAPolicy
	rw     *RewriteSpec
}

// New builds a route's client-runtime handler. policy=nil (or
// disabled) with non-nil rw = purely rewriting pass-through SW
// (no cache); active policy = full workbox SW, with the rewriting
// wired on top when rw is provided (optional parameter —
// non-rewritten routes do not pass it).
func New(policy *core.PWAPolicy, rw ...*RewriteSpec) *Handler {
	h := &Handler{policy: policy}
	if len(rw) > 0 {
		h.rw = rw[0]
	}
	return h
}

// rwEnabled: does the route carry client-side rewriting?
func (h *Handler) rwEnabled() bool { return h.rw != nil }

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

	// Rewriting pass-through SW (rewriteBody without PWA): no
	// caching, no interception outside targets; only the route's
	// rewriting policy drives the fetches.
	if h.rwEnabled() && (h.policy == nil || !h.policy.Enabled) {
		return h.plainRewriteSW()
	}

	// Pass 1: generate the body with the CACHE_VERSION placeholder.
	// This hash only versions ASSETS_CACHE (pages/scripts/styles).
	// API caches are versioned independently, per endpoint:
	// see apiCacheRouteJS (hash of the config block +
	// apiCacheLogicVersion) so that the offline replay survives
	// unrelated deployments.
	body := `importScripts('` + PathPrefix + `workbox/workbox-sw.js');

workbox.setConfig({ modulePathPrefix: '` + PathPrefix + `workbox/' });

// Version of the whole cache set = hash of this SW's very content:
// any change (config, generator, an apiCache's version field)
// changes the hash => new cache names => purge of the old ones at
// activation. No change => same caches, the offline replay
// survives tab closures.
const CACHE_VERSION = '@@CACHE_VERSION@@';
const ASSETS_CACHE = 'gate-one-pwa-assets-' + CACHE_VERSION;
// Legacy cache names from before the "Cladone Gate One" rename —
// delete-only: caches actually installed by a predecessor SW stay in
// storage and must be wiped at activation, they can never be matched
// (let alone cleaned) by the current-version filters below.
const LEGACY_PREFIXES = ['gateway-pwa-'];

// The Cache API ignores HTTP caching directives: cache.put() stores a
// response whatever its Cache-Control. The generated SW therefore
// enforces the origin's HARD prohibition itself — no-store means "do
// not store", and a session probe or a per-user endpoint relies on it
// (2026-10-25: the auth probe was cached and replayed a stale
// identity). "private" stays cacheable (this cache is per-user, not a
// shared one) and "no-cache" is approximated by the SWR background
// revalidation.
const NO_STORE_RE = /(?:^|,)\s*no-store\b/;
function cacheForbidden(response) {
  if (!response) return true;
  return NO_STORE_RE.test(
    (response.headers.get('cache-control') || '').toLowerCase());
}
// Same rule for the Workbox assets route (documents/scripts/styles):
// a no-store page is never stored either.
const CACHE_POLICY = {
  cacheWillUpdate: async ({response}) => {
    if (!response) return null;
    if (response.type === 'opaque') return response;
    if (response.status !== 200 || cacheForbidden(response)) return null;
    return response;
  }
};

// takes control as soon as installed: the update takes effect at
// the next load, without waiting for all tabs to close
self.skipWaiting();

self.addEventListener('activate', (event) => {
  event.waitUntil(
    self.clients.claim()
      .then(() => caches.keys())
      .then((keys) =>
        Promise.all(
          keys
            // Purge only the caches whose versioning scheme we
            // know: assets = SW hash (CACHE_VERSION); api = the
            // version is encoded in the name (v<logic>-<hash>) and
            // the CACHE_VERSION purge must NOT touch them — only
            // API caches with the outdated format are deleted.
            // Plus the LEGACY_PREFIXES, deleted unconditionally (see
            // above): a pre-rename SW never matches the current
            // prefixes, its caches would linger forever.
            .filter((k) =>
              LEGACY_PREFIXES.some((p) => k.startsWith(p)) ||
              (k.startsWith('gate-one-pwa-assets-') && !k.includes(CACHE_VERSION)) ||
              (k.startsWith('gate-one-pwa-api-') &&
               !/^gate-one-pwa-api-.*-v\d+-[0-9a-f]{8}$/.test(k))
            )
            .map((k) => caches.delete(k))
        )
      )
  );
});

if (workbox) {
  // Strategy for pages and assets, declared in the route's
  // pwa.assets policy (default: staleWhileRevalidate — the cache
  // answers instantly, the network refreshes in the background; the
  // CACHE_VERSION purged at activation guarantees freshness after
  // deployment).
@@NETWORK_ONLY@@
  workbox.routing.registerRoute(
    ({request}) => request.destination === 'document' || request.destination === 'script' || request.destination === 'style',
    new workbox.strategies.ASSETS_STRATEGY({
      cacheName: ASSETS_CACHE@@ASSETS_OPTIONS@@@@ASSETS_PLUGINS@@
    })
  );
  // diagnostic marker step 1: networkOnly + assets routes registered
  caches.open('gate-one-pwa-debug').then((c) => c.put('/step1-assets-route', new Response('ok')));
  // diagnostic marker step 2: apiCache about to start
  caches.open('gate-one-pwa-debug').then((c) => c.put('/step2-before-apicache', new Response('ok')));
` + h.apiCacheJS() + `
  // diagnostic marker: the SW has loaded all its routes
  caches.open('gate-one-pwa-debug').then((c) => c.put('/__routes_loaded', new Response('ok')));
  }
self.addEventListener('fetch', () => {}); // no-op: force listener attachment
`

	// Assets strategy, declarative (pwa.assets).
	strategy, timeout := h.policy.EffectiveAssets()
	opts := ""
	if timeout > 0 {
		opts = ",\n      networkTimeoutSeconds: " + fmtInt(timeout)
	}
	// The resolved policy already gives the exact workbox class
	// name (see EffectiveAssets).
	body = strings.ReplaceAll(body, "ASSETS_STRATEGY", strategy)
	body = strings.ReplaceAll(body, "@@ASSETS_OPTIONS@@", opts)
	// The origin's no-store prohibition is enforced on the assets
	// route too (documents/scripts/styles): the Cache API does not
	// honour it by itself.
	body = strings.ReplaceAll(body, "@@ASSETS_PLUGINS@@", ",\n      plugins: [CACHE_POLICY]")

	// Network-only exclusions, declarative (pwa.networkOnly) —
	// nothing is hard-coded: which URLs to never cache is a
	// deployment choice (the gateway supports any authentication
	// server).
	body = strings.ReplaceAll(body, "@@NETWORK_ONLY@@", h.networkOnlyJS())

	// Client-side rewriting (upstream.rewriteBody): data + raw
	// interception, inserted BEFORE the workbox routes. The latter
	// exclude the rewrite targets — otherwise double respondWith
	// (raw listener + router) and wrong cross-origin caching. The
	// config JSON is part of the SW hash: reconfiguring rewriteBody
	// renews the caches.
	if h.rwEnabled() {
		body = strings.ReplaceAll(
			body,
			"if (workbox) {",
			h.rewritePreludeJS()+"\nif (workbox) {",
		)
		body = strings.ReplaceAll(
			body,
			"({request}) => request.destination === 'document'",
			"({url, request}) => !rwMatch(url) && request.destination === 'document'",
		)
	}

	// Pass 2: hash of the body (placeholder included), then substitution.
	version := fmt.Sprintf("%x", sha256.Sum256([]byte(body)))[:8]
	body = strings.ReplaceAll(body, "@@CACHE_VERSION@@", version)

	js := `// Generated by the gateway — workbox ` + workboxVersion + ` self-hosted
// caches version: ` + version + "\n" + body
	return js
}

// SwJS: the generated service worker, exposed to external tests (the
// internal name remains swJS).
func (h *Handler) SwJS() string { return h.swJS() }

// rwData marshals the rewriting policy into a JSON object for the
// client payloads (SW).
func (h *Handler) rwData() string { return core.AsciiJSON(h.rw, "{}") }

// rewritePreludeJS: block injected into the workbox SW when the route
// carries upstream.rewriteBody — RW data + matching function +
// raw fetch listener. The listener is DECLARED BEFORE the workbox
// routes (body writing order) and the workbox matchers exclude the
// RW targets: a target URL is never touched by the caches
// (first match wins otherwise), and only this listener answers with
// the rewritten request (no double respondWith).
//
// Matching = rewriteBody semantics: origin hostname (without port,
// see url.hostname), longest path prefix first; entry
// with "to" → alternate host, entry without "to" → null (the fetch
// goes as-is to the origin: reading exception), otherwise → Target.
// The rewritten request keeps method/headers/body (new Request);
// no cache touches it: interception = re-fetch towards the gateway.
func (h *Handler) rewritePreludeJS() string {
	return `
// == Client-side rewriting (upstream.rewriteBody) ==
const RW = ` + h.rwData() + `;

function rwMatch(url) {
  if (RW.origins.indexOf(url.hostname) === -1) return null;
  // cross-route target (wildcard sibling or explicit mapping): its
  // PUBLIC host, on the SW's own scheme/port (the gateway serves all
  // routes on one listener).
  var target = RW.targets && RW.targets[url.hostname];
  if (target) {
    var alt = new URL(self.location.origin);
    alt.hostname = target;
    return alt.origin;
  }
  for (var i = 0; i < RW.except.length; i++) {
    if (RW.except[i].path &&
        url.pathname.indexOf(RW.except[i].path) === 0) {
      return RW.except[i].to || null; // exception: alternative or remains at the origin
    }
  }
  return RW.target; // standard rewrite to the public host
}

self.addEventListener('fetch', (event) => {
  let url, base;
  try {
    url = new URL(event.request.url);
    base = rwMatch(url);
  } catch (e) { return; }
  if (!base) return; // outside targets: leave to the existing routes
  try {
    const target = new URL(base);
    target.pathname = url.pathname;
    target.search = url.search;
    event.respondWith(fetch(new Request(target, event.request)));
  } catch (e) {
    // non-rewritable body/mode: normal network request
  }
});
`
}

// plainRewriteSW: PURELY rewriting pass-through service worker
// (route with upstream.rewriteBody and no PWA service worker): no
// workbox, NO cache, no matching outside RW targets — skipWaiting
// + clients.claim to take control as soon as installed (same
// versioning mechanism as the PWA SW: changing content triggers
// the update).
func (h *Handler) plainRewriteSW() string {
	return `// Generated by the gateway — rewriting pass-through service worker.
// No caching, no interception outside RW targets; calls
// (fetch/XHR/…) to the site's origin hosts go back
// to the public host (through the gateway: sessions and quotas
// applicable). The prefix exceptions (RW.except) remain at
// the origin or point to their alternate host.
const RW = ` + h.rwData() + `

function rwMatch(url) {
  if (RW.origins.indexOf(url.hostname) === -1) return null;
  // cross-route target (wildcard sibling or explicit mapping): its
  // PUBLIC host, on the SW's own scheme/port (the gateway serves all
  // routes on one listener).
  var target = RW.targets && RW.targets[url.hostname];
  if (target) {
    var alt = new URL(self.location.origin);
    alt.hostname = target;
    return alt.origin;
  }
  for (var i = 0; i < RW.except.length; i++) {
    if (RW.except[i].path &&
        url.pathname.indexOf(RW.except[i].path) === 0) {
      return RW.except[i].to || null; // exception: alternative or remains at the origin
    }
  }
  // the SW lives on the public host: ITS origin IS the target
  // (actual scheme — http in demo, https in production)
  return self.location.origin;
}

self.skipWaiting();

self.addEventListener('activate', (event) => {
  // immediate claim: by taking control of the open pages, the
  // window of calls sent to the origin before control closes.
  event.waitUntil(self.clients.claim());
});

self.addEventListener('fetch', (event) => {
  let url, base;
  try {
    url = new URL(event.request.url);
    base = rwMatch(url);
  } catch (e) { return; }
  if (!base) return; // outside targets (or exceptions to the origin)
  try {
    const target = new URL(base);
    target.pathname = url.pathname;
    target.search = url.search;
    event.respondWith(fetch(new Request(target, event.request)));
  } catch (e) {
    // non-rewritable body/mode: normal network request
  }
});
`
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
  // URLs declared networkOnly (pwa.networkOnly): never cached,
  // never replayed — authentication, OAuth/OIDC callbacks with
  // one-time codes, everything the deployment configuration excludes.
  workbox.routing.registerRoute(
    ({url}) => ` + tests.String() + (func() string {
		if h.rwEnabled() {
			return " && !rwMatch(url)"
		}
		return ""
	}()) + `,
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
  // Explicit cache key: Cache Storage ignores the body of POST
  // requests in its key (all segmentations would overwrite each
  // other), so the body is hashed into an artificial URL parameter.
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

  // fetch with an abort limited to waiting for the HEADERS: as soon
  // as the response (headers) arrives, the abort listener is removed
  // and the response streaming can freely take its time. An abort is
  // therefore only possible before any response: DNS/TCP down,
  // silent server. Returns {response, error} without throwing: the
  // handler's catch decides on replay based on response.ok or error.
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

  // Accumulates the tee branch and writes to the cache: at the clean
  // end of the stream, OR after 1.5 s without a new chunk (SSE
  // streams do not always close: waiting for done indefinitely would
  // never cache anything). Responses exceeding maxEntrySizeBytes are
  // not cached.
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
        if (idle && parts.length > 0) break; // prolonged silence: finalize
        if (done) break;
        size += value.byteLength;
        if (maxSize > 0 && size > maxSize) {
          await reader.cancel();
          return; // response too large: no caching
        }
        parts.push(value);
      }
      const blob = new Blob(parts);
      const response = new Response(blob, {
        status: 200,
        headers: {'Content-Type': 'text/event-stream'},
      });
      await cache.put(request, response);
      console.log('[gate-one-pwa] API cache written:', request.url, size + ' bytes');
      await expiration.cacheDidUpdate({
        cacheName: cacheName,
        request: request,
        oldResponse: null,
        newResponse: response,
      });
    } catch (err) {
      console.error('[gate-one-pwa] API cache FAILURE:', err && err.message);
      // stream cancelled or interrupted, or quota exceeded: nothing is cached
    }
  }
`)

	for _, c := range caches {
		if c.Path == "" {
			continue
		}
		// method "none": the path is explicitly out of cache — no
		// route generated; the catch-all already ignores it (declared
		// path = master of its path, every method).
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

	// Catch-all defaults (no declarable config for now).
	const (
		allMaxEntries = 200
		allMaxAgeSec  = 86400
		allMaxSize    = 2 << 20 // 2 MiB per entry
		allTimeoutSec = 3
	)

	cacheName := "gate-one-pwa-api-all"
	// Versioning: hash of the configuration block (excludes
	// included) + the common logic version. Reconfiguring the
	// catch-all does not invalidate the explicit endpoints' caches,
	// and vice versa.
	polHash := fmt.Sprintf("%x", sha256.Sum256(apiCachePolicyJSON(all)))[:8]
	cacheName += "-v" + apiCacheLogicVersion + "-" + polHash

	// Exclusion filter: the gateway's virtual prefixes (PWA assets and
	// its own endpoints — auth probe, stats), declared prefixes,
	// declared endpoints' paths (variant A: a declared endpoint is
	// master of its path, every method), and regular expressions
	// tested against the COMPLETE URL (pathname + query — a particular
	// parameter can disqualify a request).
	excludes := []string{PathPrefix, GatewayInternalPrefix}
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
		// Declaration of a named RegExp (the index is enough for
		// uniqueness in the SW's scope) + test against the complete URL.
		patternDecls += "\n  const EXCLUDE_RE_" + fmtInt(i) + " = new RegExp(" + fmtJSLit(pat) + ");"
		patternTests += " && !EXCLUDE_RE_" + fmtInt(i) + ".test(url.href)"
	}

	return `
  // Universal GET cache (apiGETCache): the GET requests
  // nothing else covers (data API fetches, images, fonts). SWR:
  // the cache answers instantly, the network refreshes in the
  // background; offline -> the cache. A path declared in
  // apiCaches[] is master of its path (every method) and does not
  // reach this block; the excludesPatterns are RegExps tested
  // against the complete URL (pathname + query). Defaults: ` + fmtInt(allMaxEntries) + ` entries,
  // ` + fmtInt(allMaxAgeSec) + `s, ` + fmtInt64(allMaxSize) + ` bytes max, abort ` + fmtInt(allTimeoutSec) + ` s.
  const exp_api_all = new workbox.expiration.ExpirationPlugin({
    maxEntries: ` + fmtInt(allMaxEntries) + `,
    maxAgeSeconds: ` + fmtInt(allMaxAgeSec) + `,
    purgeOnQuotaError: true
  });` + patternDecls + `

  workbox.routing.registerRoute(
    ({url}) => url.pathname.startsWith('/')` + checks.String() + patternTests + (func() string {
		if h.rwEnabled() {
			return " && !rwMatch(url)"
		}
		return ""
	}()) + `,
    async ({event}) => {
      const req = event.request;
      if (req.method !== 'GET') {
        // the catch-all only matches GETs (method 'GET' declared
        // below) — defensive guard for GETs of exotic
        // URLs (about:, blob:) already excluded by workbox.
        return fetch(req);
      }
      console.log('[gate-one-pwa] apiGETCache intercepted:', req.url);
      const cache = await caches.open('` + cacheName + `');
      // An entry written by a previous SW may predate the rule:
      // ignore (and let it expire) if it says no-store.
      let hit = await cache.match(req);
      if (hit && cacheForbidden(hit)) hit = null;
      const refresh = () => fetchNetwork(req, ` + fmtInt(allTimeoutSec) + `).then(({response}) => {
        if (!response || !response.ok || !response.body
            || response.headers.has('set-cookie')
            || cacheForbidden(response)) return;
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
      if (response.ok && response.body && !response.headers.has('set-cookie')
          && !cacheForbidden(response)) {
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
		idleMs = 1500 // cache finalization after this stream silence
	}
	netTimeout := c.NetworkTimeoutSeconds
	if netTimeout <= 0 {
		netTimeout = 3 // fetch abort when there is no response after 3 s
	}
	method := strings.ToUpper(c.Method)
	if method != "GET" {
		method = "POST" // default (and compat): network-first replay
	}
	// offlineFastPath: POST only (for a GET, SWR already serves the
	// cached response instantly — pointless).
	offlineFast := method == "POST" &&
		(c.OfflineFastPath == nil || *c.OfflineFastPath)

	cacheName := "gate-one-pwa-api-" + strings.TrimPrefix(c.Path, "/")
	if c.Version != "" {
		cacheName += "-" + c.Version
	}
	cacheName = strings.ReplaceAll(cacheName, "/", "-")

	// Per-endpoint versioning: the name incorporates the hash of
	// THIS endpoint's JSON configuration block (not the whole SW).
	// Reconfiguring this worker in api-routes.json invalidates its
	// cache, and its alone; the other endpoints' replay and the
	// assets caches survive a deployment. apiCacheLogicVersion is
	// incremented manually when the stored entries' format changes.
	polHash := fmt.Sprintf("%x", sha256.Sum256(apiCachePolicyJSON(c)))[:8]
	cacheName += "-v" + apiCacheLogicVersion + "-" + polHash

	return `
  // Declarative API cache: ` + c.Path + ` (method ` + method + `).
  // ` + fmtInt(maxEntries) + ` entries max, ` + fmtInt(maxAge) + `s,
  // ` + fmtInt64(maxSize) + ` bytes max per entry,
  // offlineFastPath: ` + jsBool(offlineFast) + ` (POST only).
  const OFFLINE_FAST_` + jsIdent(c.Path) + ` = ` + jsBool(offlineFast) + `; // POST only
  const exp_` + jsIdent(c.Path) + ` = new workbox.expiration.ExpirationPlugin({
    maxEntries: ` + fmtInt(maxEntries) + `,
    maxAgeSeconds: ` + fmtInt(maxAge) + `,
    purgeOnQuotaError: true
  });

  workbox.routing.registerRoute(
    ({url}) => ` + (func() string {
		// a declared endpoint route never targets a rewrite
		// target: identical hostname + path cross-origin are
		// possible, and first match would win otherwise
		if h.rwEnabled() {
			return "!rwMatch(url) && "
		}
		return ""
	}()) + `url.pathname === '` + c.Path + `',
    async ({event}) => {
      console.log('[gate-one-pwa] apiCache route intercepted:', event.request.method, event.request.url);
      const req = event.request;
      const cache = await caches.open('` + cacheName + `');` + func() string {
		if method == "GET" {
			return `
      // SWR: the cache answers instantly (even online), the
      // network refreshes in the background; strict offline ->
      // the cache. Key = URL alone (no body for a GET). Responses
      // non-200 or with Set-Cookie are not cached.
      // An entry written by a previous SW may predate the rule:
      // ignore (and let it expire) if it says no-store.
      let hit = await cache.match(req);
      if (hit && cacheForbidden(hit)) hit = null;
      const refresh = () => fetchNetwork(req, ` + fmtInt(netTimeout) + `).then(({response}) => {
        if (!response || !response.ok || response.headers.has('set-cookie')) return;
        // opaque or empty response: nothing to store
        if (!response.body) return;
        if (cacheForbidden(response)) return;
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
      if (response.ok && response.body && !response.headers.has('set-cookie')
          && !cacheForbidden(response)) {
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
      // Explicit cache key: Cache Storage ignores the body of POSTs
      // in its key (all segmentations would overwrite each other),
      // so we hash the URL + body into an artificial parameter.
      // IMPORTANT: built BEFORE the fetch — a request's body
      // can only be read once, and after a failed fetch (offline)
      // req.clone().text() would throw "Failed to fetch" instead of
      // the expected replay.
      let keyReq = null;
      try {
        const bodyText = req.method === 'GET' ? '' : await req.clone().text();
        keyReq = await buildCacheKey(req.url, bodyText, req.method);
        // Key diagnostics: the key = SHA-256 of the body. Two
        // segmentations "identical" from the user's point of view but
        // with a different key => a body field changed.
        // Logging the body makes it possible to immediately see THE
        // field at fault (phonetic, meters, trailing space in the
        // text...).
        console.log('[gate-one-pwa] key:', keyReq.url.slice(keyReq.url.indexOf('__pwa_key=')),
          '\n  body:', bodyText);
      } catch (e) { keyReq = null; } // unreadable body: no replay
      try {
        // Offline (the OS knows: wifi off, airplane): no
        // fetch at all, the cache answers instantly (fast-path,
        // offlineFastPath: true by default; false for an endpoint
        // where replaying a cached response would be wrong, e.g. a
        // write). Online: fetch first (freshness), aborted after
        // networkTimeoutSeconds if no response — the replay no
        // longer suffers the full TCP timeout (~5 s) of a dead
        // network. The timeout only covers waiting for the headers:
        // the listener is removed as soon as the response arrives,
        // and streaming the response itself stays free.
        if (OFFLINE_FAST_` + jsIdent(c.Path) + ` && !self.navigator.onLine) {
          const offlineHit = keyReq ? await cache.match(keyReq) : null;
          if (offlineHit) {
            console.log('[gate-one-pwa] replay offline (onLine=false):', keyReq.url);
            return offlineHit;
          }
          // nothing cached: try the fetch anyway (offline
          // not always detected, e.g. local server)
        }
        const { response, error } = await fetchNetwork(req, ` + fmtInt(netTimeout) + `);
        if (error) throw error;
        if (response.ok && response.body && !cacheForbidden(response)) {
          const [toApp, toCache] = response.body.tee();
          // event.waitUntil is INDISPENSABLE: without it, the browser
          // may suspend the SW as soon as the response is returned,
          // before the accumulation + cache.put finish (the API cache
          // would never be written, especially on Firefox).
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
        // offline (or unstable network): replay the previously
        // stored response for this exact request
        if (keyReq) {
          const cached = await cache.match(keyReq);
          if (cached) {
            console.log('[gate-one-pwa] replay offline:', keyReq.url);
            return cached;
          }
          console.warn('[gate-one-pwa] no cache for this request:', keyReq.url);
        }
        throw err;
      }`
	}() + `
    },
    // Cache Storage ignores POSTs in its key and workbox routes
    // non-GET requests ONLY if the method is explicit (Route
    // constructor, default method "GET"): without the 3rd argument
    // for a POST, the route matched no POST => "No route found",
    // replay impossible.
    '` + method + `'
  );
`
}

// jsBool renders a Go bool as a JS literal.
func jsBool(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// jsIdent converts a path into a usable JS identifier.
func jsIdent(path string) string {
	ident := strings.TrimPrefix(path, "/")
	ident = strings.ReplaceAll(ident, "/", "_")
	ident = strings.ReplaceAll(ident, "-", "_")
	// prefix if the first character is not a letter
	if ident == "" || (ident[0] < 'a' || ident[0] > 'z') && (ident[0] < 'A' || ident[0] > 'Z') {
		ident = "api_" + ident
	}
	return ident
}

// fmtJSLit renders a Go string as a JS literal (paths controlled on
// the generator side: no escape characters expected).
func fmtJSLit(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "\\'") + "'"
}

// fmtInt avoids importing strconv for two template integers.
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

// pwaIconSizes infers the declared size from the file name
// (icon-192.png => "192x192"). Default: "512x512".
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
		// Route without PWA (rewriteBody only): no manifest — the
		// SW remains available (sw.js) and the workbox runtime
		// serves a 404 identical to before.
		if h.policy == nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/manifest+json")
		w.Header().Set("Cache-Control", "no-cache")
		_, _ = w.Write(h.manifest())
		return

	case SwFile:
		// A service worker must never be cached stale; the browser
		// re-checks it to detect updates.
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		// The SW is registered from a page on "/" scope; registering
		// from /__gate-one_pwa/ would otherwise limit its scope.
		w.Header().Set("Service-Worker-Allowed", "/")
		_, _ = w.Write([]byte(h.swJS()))
		return
	}

	// Vendored Workbox runtime: /__gate-one_pwa/workbox/<file>
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
