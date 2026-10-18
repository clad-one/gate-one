package proxy

import (
	"cladone/gateway/internal/core"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Fenêtre fixe par clé (route+identité) : au-delà de la limite, 429
// avec Retry-After. En mémoire (instance unique) — un restart remet
// les compteurs, acceptable pour ce service.

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

// allow consomme une unité : ok=false quand la fenêtre est pleine
// (retryAfter = temps restant avant remise à zéro).
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

// parsePeriod : "second"|"minute"|"hour"|"day" (défaut minute).
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

// limiters par route (construits une fois au chargement de la config)
type routeLimiters struct {
	rate *limiter
	// quota : même mécanique, fenêtre plus longue en pratique
	quota *limiter
}

// clientIP : la VRAIE adresse du client. Derrière Traefik, RemoteAddr
// = Traefik lui-même (tout le monde partagerait le même bucket) — le
// dernier maillon de X-Forwarded-For est le pair vu par Traefik, donc
// l'IP réelle du client (Traefik l'ajoute, un client ne peut pas la
// falsifier).
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

// limitIdentity : la clé de comptage = l'utilisateur authentifié
// s'il existe, sinon son IP.
func limitIdentity(r *http.Request, ctx *RequestContext) string {
	if ctx.UserID != "" {
		return "u:" + ctx.UserID
	}
	return "ip:" + clientIP(r)
}

// enforceLimits applique les policies rateLimit/quota d'une route
// (fenêtre fixe ; 429 + Retry-After). Répond et retourne true si la
// requête doit être refusée.
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
