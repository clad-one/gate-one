package proxy

import (
	"cladone/gate-one/internal/authn"
	"crypto/sha256"
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

// writeMCPInsufficientScope answers an authenticated MCP caller that
// lacks the required scope. resource_metadata is present on the 403
// too (MCP 2026-07-28, consistency with the 401).
func writeMCPInsufficientScope(
	w http.ResponseWriter,
	resourceMetadataURL, scope string,
) {
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
	authCacheSize atomic.Int64
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
		// CompareAndDelete: concurrent misses on the same expired key
		// must not decrement the size twice.
		if authCache.CompareAndDelete(key, v) {
			authCacheSize.Add(-1)
		}
		return nil, false
	}
	return e.identity, true
}

// deleteAuth drops one cached identity (revoked session).
func deleteAuth(key string) {
	if _, ok := authCache.LoadAndDelete(key); ok {
		authCacheSize.Add(-1)
	}
}

func cacheAuth(key string, identity *RequestContext) {
	if authCacheSize.Load() > 500 {
		// soft bound: purge expired entries before adding
		now := time.Now()
		authCache.Range(func(k, v any) bool {
			if now.After(v.(*authCacheEntry).expires) {
				if authCache.CompareAndDelete(k, v) {
					authCacheSize.Add(-1)
				}
			}
			return true
		})
	}
	if authCacheSize.Load() > 2000 {
		return // never grow without bound (abusive upstream proxy)
	}
	cp := *identity
	// the copy carries ONLY the identity: the caller's request
	// fields (method/path/…) must not leak to the next one
	cp.Method, cp.Path, cp.Query = "", "", nil
	cp.Host, cp.Body, cp.Headers = "", nil, nil
	authCache.Store(key, &authCacheEntry{identity: &cp, expires: time.Now().Add(authCacheTTL)})
	authCacheSize.Add(1)
}

// clearAuthCache: test usage — the cache is global to the process,
// every test must start from a neutral state.
func clearAuthCache() {
	authCache.Range(func(k, v any) bool {
		authCache.Delete(k)
		return true
	})
	authCacheSize.Store(0)
}

// ResetAuthCache drops every cached identity. Called on SIGHUP: a new
// config may select another provider/store/key, and a cached identity
// must not survive it.
func ResetAuthCache() { clearAuthCache() }

func (g *Gateway) checkAuth(
	w http.ResponseWriter,
	r *http.Request,
	ctx *RequestContext,
) (*RequestContext, error) {
	return g.checkAuthWithProvider(w, r, ctx, g.providerFor(nil))
}

func (g *Gateway) checkAuthWithProvider(
	w http.ResponseWriter,
	r *http.Request,
	ctx *RequestContext,
	entry *providerEntry,
) (*RequestContext, error) {
	log.Printf(
		"AUTH CHECK method=%s host=%s uri=%s authorization=%t",
		r.Method,
		r.Host,
		r.RequestURI,
		r.Header.Get("Authorization") != "",
	)

	if !entry.usable() {
		return nil, authn.ErrProviderUnavailable
	}
	provider := entry.provider

	// Identity cache: one provider round-trip per session and per
	// TTL instead of one per request. A silent refresh's Set-Cookie
	// is only propagated on the fresh call (the cache does not have
	// one) — after rotation, cookies change → new key. The provider
	// name is part of the key so a config reload with another
	// provider cannot reuse a stale identity.
	// The provider ID (not the implementation name: two OIDC/JWT
	// providers both return "oidc"/"jwt") is part of the cache key.
	key := entry.id + "|" + provider.Name() + "|" + authCacheKey(r)
	if cached, ok := cachedAuth(key); ok {
		atomic.AddInt64(&statAuthCacheHi, 1)
		log.Printf("AUTH CACHE hit user=%q", cached.Username)
		id := authn.Identity{
			UserID:    cached.UserID,
			SessionID: cached.SessionID,
			IssuedAt:  cached.IssuedAt,
			Username:  cached.Username,
			Email:     cached.Email,
			Roles:     cached.Roles,
			Scopes:    cached.Scopes,
			Claims:    cached.Claims,
		}
		// Revocation is checked BEFORE the cache: a back-channel
		// logout can kill the session while its identity is still
		// cached. A store error is fail-closed.
		revoked, rerr := provider.CheckRevoked(r.Context(), id)
		if rerr != nil {
			return nil, fmt.Errorf(
				"%w: %v", authn.ErrProviderUnavailable, rerr)
		}
		if revoked {
			deleteAuth(key)
			return nil, authn.ErrUnauthenticated
		}
		applyIdentity(ctx, id)
		return ctx, nil
	}

	res, err := provider.Verify(r.Context(), r)
	if res != nil {
		// Propagate any session refresh issued by the provider
		// (auth-bridge silently refreshes access tokens).
		for _, c := range res.SetCookies {
			w.Header().Add("Set-Cookie", c)
		}
	}
	if err != nil {
		return nil, err
	}
	atomic.AddInt64(&statAuthBridge, 1)

	log.Printf(
		"AUTH PROVIDER %s user=%q username=%q roles=%q",
		provider.Name(),
		res.UserID,
		res.Username,
		res.Roles,
	)

	if res.UserID == "" && res.Username == "" {
		return nil, authn.ErrUnauthenticated
	}
	applyIdentity(ctx, res.Identity)
	cacheAuth(key, ctx)
	return ctx, nil
}

func applyIdentity(ctx *RequestContext, id authn.Identity) {
	ctx.UserID = id.UserID
	ctx.SessionID = id.SessionID
	ctx.IssuedAt = id.IssuedAt
	ctx.Username = id.Username
	ctx.Email = id.Email
	ctx.Roles = id.Roles
	ctx.Scopes = id.Scopes
	ctx.Claims = id.Claims
}

func (g *Gateway) checkMCPAuth(
	w http.ResponseWriter,
	r *http.Request,
	ctx *RequestContext,
	resource string,
	resourceMetadataURL string,
	scope string,
) (*RequestContext, error) {
	return g.checkMCPAuthWithProvider(
		w, r, ctx, resource, resourceMetadataURL, scope, g.providerFor(nil))
}

func (g *Gateway) checkMCPAuthWithProvider(
	w http.ResponseWriter,
	r *http.Request,
	ctx *RequestContext,
	resource string,
	resourceMetadataURL string,
	scope string,
	entry *providerEntry,
) (*RequestContext, error) {

	if !entry.usable() {
		return nil, authn.ErrProviderUnavailable
	}
	provider := entry.provider

	res, err := provider.VerifyMCP(r.Context(), r, scope, resource)
	if err != nil {
		switch {
		case errors.Is(err, authn.ErrInsufficientScope):
			writeMCPInsufficientScope(w, resourceMetadataURL, scope)
			return nil, ErrUnauthorized
		case errors.Is(err, authn.ErrUnauthenticated):
			writeMCPAuthChallenge(w, resourceMetadataURL, scope)
			return nil, ErrUnauthorized
		default:
			return nil, err
		}
	}
	atomic.AddInt64(&statAuthBridge, 1)

	log.Printf(
		"MCP AUTH PROVIDER %s user=%q username=%q roles=%q",
		provider.Name(),
		res.UserID,
		res.Username,
		res.Roles,
	)

	applyIdentity(ctx, res.Identity)
	return ctx, nil
}
