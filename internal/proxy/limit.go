package proxy

import (
	"cladone/gate-one/internal/core"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Fixed window per key (route+identity): beyond the limit, 429 with
// Retry-After. In memory (single instance) — a restart resets the
// counters, acceptable for this service.

type limitBucket struct {
	windowStart time.Time
	count       int64
}

type limiter struct {
	mu      sync.Mutex
	buckets map[string]*limitBucket
	period  time.Duration
}

func newLimiter(period time.Duration) *limiter {
	return &limiter{buckets: map[string]*limitBucket{}, period: period}
}

// allow consumes one unit: ok=false when the window is full
// (retryAfter = time left before reset).
func (l *limiter) allow(key string, limit int64) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	b := l.buckets[key]
	if b == nil || now.Sub(b.windowStart) >= l.period {
		b = &limitBucket{windowStart: now}
		l.buckets[key] = b
	}
	b.count++
	if b.count > limit {
		return false, l.period - now.Sub(b.windowStart)
	}
	return true, 0
}

// parsePeriod: "second"|"minute"|"hour"|"day" (default minute).
func parsePeriod(s string) time.Duration {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "second":
		return time.Second
	case "minute":
		return time.Minute
	case "hour":
		return time.Hour
	case "day":
		return 24 * time.Hour
	default:
		return time.Minute
	}
}

// per-route limiters (built once at config load)
type routeLimiters struct {
	rate *limiter
	// quota: same mechanics, longer window in practice
	quota *limiter
}

// clientIP: the client's REAL address. Behind Traefik, RemoteAddr
// = Traefik itself (everyone would share the same bucket) — the
// last link of X-Forwarded-For is the peer seen by Traefik, hence
// the client's real IP (Traefik adds it, a client cannot forge it).
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[len(parts)-1])
	}
	ip := r.RemoteAddr
	if i := strings.LastIndex(ip, ":"); i > 0 {
		ip = ip[:i]
	}
	return ip
}

// limitIdentity: the counting key = the authenticated user if any,
// otherwise their IP.
func limitIdentity(r *http.Request, ctx *RequestContext) string {
	if ctx.UserID != "" {
		return "u:" + ctx.UserID
	}
	return "ip:" + clientIP(r)
}

// enforceLimits applies a route's rateLimit/quota policies (fixed
// window; 429 + Retry-After). Answers and returns true if the
// request must be rejected.
func enforceLimits(
	w http.ResponseWriter,
	r *http.Request,
	cr *compiledRoute,
	ctx *RequestContext,
) bool {
	route := cr.route
	if route.RateLimit == nil && route.Quota == nil {
		return false
	}

	ident := limitIdentity(r, ctx)
	rk := routeKey(route.Host, route.Path)

	if route.RateLimit != nil &&
		matches(route.RateLimit.When, ctx) {
		if cr.limiters == nil || cr.limiters.rate == nil {
			cr.limiters = initLimiters(route)
		}
		if ok, wait := cr.limiters.rate.allow(
			rk+"|"+ident,
			int64(route.RateLimit.Requests),
		); !ok {
			limitRejected(w, wait)
			return true
		}
	}

	if route.Quota != nil &&
		matches(route.Quota.When, ctx) {
		if cr.limiters == nil || cr.limiters.quota == nil {
			cr.limiters = initLimiters(route)
		}
		if ok, wait := cr.limiters.quota.allow(
			rk+"|"+ident,
			int64(route.Quota.Limit),
		); !ok {
			limitRejected(w, wait)
			return true
		}
	}

	return false
}

func initLimiters(route *core.Route) *routeLimiters {
	l := &routeLimiters{}
	if route.RateLimit != nil {
		l.rate = newLimiter(parsePeriod(route.RateLimit.Period))
	}
	if route.Quota != nil {
		l.quota = newLimiter(parsePeriod(route.Quota.Period))
	}
	return l
}

func limitRejected(w http.ResponseWriter, wait time.Duration) {
	secs := int(wait.Seconds())
	if secs < 1 {
		secs = 1
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Retry-After", strconv.Itoa(secs))
	w.WriteHeader(http.StatusTooManyRequests)
	w.Write([]byte(`{"error":"rate_limited"}`))
}
