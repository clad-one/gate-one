package proxy

import (
	"encoding/json"
	"net/http"
	"sort"
	"sync"
	"sync/atomic"
)

// Lightweight statistics: per-route counters (requests, statuses) +
// auth cache activity. Exposed on /__gate-one/stats (JSON) —
// counters only, no user data.

type routeStats struct {
	Requests int64         `json:"requests"`
	Status   map[int]int64 `json:"byStatus"`
}

var (
	statsMu             sync.Mutex
	statsByRoute        = map[string]*routeStats{}
	statAuthBridge      int64 // fresh calls toward auth-bridge
	statAuthCacheHi     int64 // identity cache hits
	statLandingFallback int64 // incomplete login landing pages
)

func statRecord(routeKey string, status int) {
	statsMu.Lock()
	defer statsMu.Unlock()
	s := statsByRoute[routeKey]
	if s == nil {
		s = &routeStats{Status: map[int]int64{}}
		statsByRoute[routeKey] = s
	}
	s.Requests++
	if status != 0 {
		s.Status[status]++
	}
}

// statsWriter accounts for the response's FINAL status.
type statsWriter struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (w *statsWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statsWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(b)
	w.bytes += int64(n)
	return n, err
}

// serveStats answers /__gate-one/stats.
func serveStats(w http.ResponseWriter, r *http.Request) {
	statsMu.Lock()
	defer statsMu.Unlock()

	keys := make([]string, 0, len(statsByRoute))
	for k := range statsByRoute {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	routes := make(map[string]*routeStats, len(keys))
	for _, k := range keys {
		routes[k] = statsByRoute[k]
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"authBridgeCalls":  atomic.LoadInt64(&statAuthBridge),
		"authCacheHits":    atomic.LoadInt64(&statAuthCacheHi),
		"landingFallbacks": atomic.LoadInt64(&statLandingFallback),
		"routes":           routes,
	})
}
