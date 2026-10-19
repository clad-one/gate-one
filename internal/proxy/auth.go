package proxy

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var ErrRedirect = errors.New("auth redirect")
var ErrUnauthorized = errors.New("unauthorized")

func writeMCPAuthChallenge(w http.ResponseWriter, resourceMetadataURL, scope string) {
	w.Header().Set(
		"WWW-Authenticate",
		fmt.Sprintf(
			`Bearer resource_metadata="%s", scope="%s"`,
			resourceMetadataURL,
			scope,
		),
	)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)

	_, _ = w.Write([]byte(`{
  "error": "unauthorized",
  "error_description": "Bearer token required"
}`))
}

func splitRoles(s string) []string {
	if s == "" {
		return nil
	}

	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))

	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}

	return out
}

// authCacheEntry: gateway-side cached identity. Without it, EVERY
// request (including each image of a heavy page: the proxified book
// = 878 images) pays an auth-bridge round-trip + a jwtVerify. The
// key = hash of the authentication header + cookies (specific to one
// browser session); short TTL: a re-sign-in or a silent refresh
// changes the cookies → new key → natural miss.
type authCacheEntry struct {
	identity *RequestContext
	expires  time.Time
}

var (
	authCache     sync.Map
	authCacheTTL  = 30 * time.Second
	authCacheSize = 0
)

func authCacheKey(r *http.Request) string {
	h := sha256.New()
	h.Write([]byte(r.Header.Get("Authorization")))
	for _, c := range r.Header["Cookie"] {
		h.Write([]byte{0})
		h.Write([]byte(c))
	}
	return string(h.Sum(nil))
}

func cachedAuth(key string) (*RequestContext, bool) {
	v, ok := authCache.Load(key)
	if !ok {
		return nil, false
	}
	e := v.(*authCacheEntry)
	if time.Now().After(e.expires) {
		authCache.Delete(key)
		authCacheSize--
		return nil, false
	}
	return e.identity, true
}

func cacheAuth(key string, identity *RequestContext) {
	if authCacheSize > 500 {
		// soft bound: purge expired entries before adding
		now := time.Now()
		authCache.Range(func(k, v any) bool {
			if now.After(v.(*authCacheEntry).expires) {
				authCache.Delete(k)
				authCacheSize--
			}
			return true
		})
	}
	if authCacheSize > 2000 {
		return // never grow without bound (abusive upstream proxy)
	}
	cp := *identity
	// the copy carries ONLY the identity: the caller's request
	// fields (method/path/…) must not leak to the next one
	cp.Method, cp.Path, cp.Query = "", "", nil
	cp.Host, cp.Body, cp.Headers = "", nil, nil
	authCache.Store(key, &authCacheEntry{identity: &cp, expires: time.Now().Add(authCacheTTL)})
	authCacheSize++
}

// clearAuthCache: test usage — the cache is global to the process,
// every test must start from a neutral state.
func clearAuthCache() {
	authCache.Range(func(k, v any) bool {
		authCache.Delete(k)
		return true
	})
	authCacheSize = 0
}

func (g *Gateway) checkAuth(
	w http.ResponseWriter,
	r *http.Request,
	ctx *RequestContext,
) (*RequestContext, error) {
	log.Printf(
		"AUTH CHECK method=%s host=%s uri=%s authorization=%t",
		r.Method,
		r.Host,
		r.RequestURI,
		r.Header.Get("Authorization") != "",
	)

	// Identity cache: one auth-bridge round-trip per session and per
	// TTL instead of one per request. A silent refresh's Set-Cookie
	// is only propagated on the fresh call (the cache does not have
	// one) — after rotation, cookies change → new key.
	if cached, ok := cachedAuth(authCacheKey(r)); ok {
		atomic.AddInt64(&statAuthCacheHi, 1)
		log.Printf("AUTH CACHE hit user=%q", cached.Username)
		ctx.UserID = cached.UserID
		ctx.Username = cached.Username
		ctx.Email = cached.Email
		ctx.Roles = cached.Roles
		ctx.Scopes = cached.Scopes
		ctx.Claims = cached.Claims
		return ctx, nil
	}

	req, err := http.NewRequest(
		http.MethodGet,
		g.authBridgeBaseURLFor()+"/auth",
		nil,
	)
	if err != nil {
		return nil, err
	}

	if auth := r.Header.Get("Authorization"); auth != "" {
		req.Header.Set("Authorization", auth)
	}
	for _, c := range r.Cookies() {
		req.AddCookie(c)
	}
	req.Header.Set("X-Forwarded-Host", r.Host)
	req.Header.Set("X-Forwarded-Uri", r.RequestURI)
	req.Header.Set("X-Forwarded-Method", r.Method)

	resp, err := g.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	atomic.AddInt64(&statAuthBridge, 1)

	log.Printf(
		"AUTH BRIDGE status=%d user=%q username=%q roles=%q",
		resp.StatusCode,
		resp.Header.Get("X-User-Id"),
		resp.Header.Get("X-Username"),
		resp.Header.Get("X-Roles"),
	)

	// Propagate any cookies auth-bridge issued (e.g. a silently
	// refreshed access_token/refresh_token) back to the browser,
	// regardless of whether auth ultimately succeeded or not.
	for _, c := range resp.Header["Set-Cookie"] {
		w.Header().Add("Set-Cookie", c)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("authentication failed")
	}
	ctx.UserID = resp.Header.Get("X-User-Id")
	ctx.Username = resp.Header.Get("X-Username")
	ctx.Email = resp.Header.Get("X-Email")
	ctx.Roles = splitRoles(resp.Header.Get("X-Roles"))
	ctx.Scopes = splitRoles(resp.Header.Get("X-Scopes"))

	// Token claims (base64-JSON of the full payload): consumed by
	// the when.claims conditions and the /__gateway/auth probe.
	if xc := resp.Header.Get("X-Claims"); xc != "" {
		if raw, derr := base64.StdEncoding.DecodeString(xc); derr == nil {
			var claims map[string]any
			if jerr := json.Unmarshal(raw, &claims); jerr == nil {
				ctx.Claims = claims
			} else {
				log.Printf("AUTH BRIDGE: unreadable X-Claims: %v", jerr)
			}
		} else {
			log.Printf("AUTH BRIDGE: non-base64 X-Claims: %v", derr)
		}
	}
	cacheAuth(authCacheKey(r), ctx)
	return ctx, nil
}

func (g *Gateway) checkMCPAuth(
	w http.ResponseWriter,
	r *http.Request,
	ctx *RequestContext,
	resourceMetadataURL string,
	scope string,
) (*RequestContext, error) {

	req, err := http.NewRequest(
		http.MethodGet,
		g.authBridgeBaseURLFor()+"/auth/mcp",
		nil,
	)
	if err != nil {
		return nil, err
	}

	if auth := r.Header.Get("Authorization"); auth != "" {
		req.Header.Set("Authorization", auth)
	}

	// Internal header: the required scope declared by the route's
	// mcp policy (X-MCP-Scope). The request is built here, never
	// copied from input headers: an external client cannot forge it.
	req.Header.Set("X-MCP-Scope", scope)

	resp, err := g.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	atomic.AddInt64(&statAuthBridge, 1)

	log.Printf(
		"MCP AUTH BRIDGE status=%d user=%q username=%q roles=%q",
		resp.StatusCode,
		resp.Header.Get("X-User-Id"),
		resp.Header.Get("X-Username"),
		resp.Header.Get("X-Roles"),
	)

	switch resp.StatusCode {

	case http.StatusUnauthorized:
		writeMCPAuthChallenge(w, resourceMetadataURL, scope)
		return nil, ErrUnauthorized

	case http.StatusForbidden:
		// resource_metadata is expected on the 403 too
		// (MCP 2026-07-28, consistency with the 401).
		w.Header().Set(
			"WWW-Authenticate",
			fmt.Sprintf(
				`Bearer error="insufficient_scope", scope="%s", resource_metadata="%s"`,
				scope,
				resourceMetadataURL,
			),
		)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)

		_, _ = w.Write([]byte(fmt.Sprintf(`{
  "error": "insufficient_scope",
  "error_description": "%s scope required"
}`, scope)))

		return nil, ErrUnauthorized

	case http.StatusOK:
		// continue

	default:
		return nil, errors.New("MCP authentication failed")
	}

	ctx.UserID = resp.Header.Get("X-User-Id")
	ctx.Username = resp.Header.Get("X-Username")
	ctx.Email = resp.Header.Get("X-Email")
	ctx.Roles = splitRoles(resp.Header.Get("X-Roles"))

	return ctx, nil
}
