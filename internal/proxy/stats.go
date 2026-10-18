package proxy

import (
	"encoding/json"
	"net/http"
	"sort"
	"sync"
	"sync/atomic"
)

// Statistiques légères : compteurs par route (requêtes, statuts) +
// l'activité du cache d'auth. Exposées sur /__gateway/stats (JSON) —
// compteurs seulement, aucune donnée utilisateur.

type routeStats struct {
	Requests int64         `json:"requests"`
	Status   map[int]int64 `json:"byStatus"`
}

var (
	statsMu         sync.Mutex
	statsByRoute    = map[string]*routeStats{}
	statAuthBridge  int64 // appels frais vers auth-bridge
	statAuthCacheHi int64 // hits du cache d'identité
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

// statsWriter comptabilise le statut FINAL de la réponse.
type statsWriter struct {
	http.ResponseWriter
	status int
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
	return w.ResponseWriter.Write(b)
}

// serveStats répond /__gateway/stats.
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
		"authBridgeCalls": atomic.LoadInt64(&statAuthBridge),
		"authCacheHits":   atomic.LoadInt64(&statAuthCacheHi),
		"routes":          routes,
	})
}
