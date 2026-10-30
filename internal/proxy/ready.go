package proxy

import (
	"encoding/json"
	"net/http"
)

// readyProvider is one provider's readiness state.
type readyProvider struct {
	Status string `json:"status"` // ok | degraded
	Error  string `json:"error,omitempty"`
}

// serveReady answers /readyz (and /__gate-one/health/providers).
//
// Readiness is LOCAL state only: a provider that could not be built at
// load time is degraded until a reload succeeds. No upstream call is
// made on every probe.
//
// The gateway stays ready as long as at least one configured provider
// is usable: one broken tenant must not remove the whole instance from
// the load balancer. A single-provider deployment is therefore 503
// when its provider is degraded, which is the intended fail-closed
// signal.
func (g *Gateway) serveReady(w http.ResponseWriter, r *http.Request) {
	verbose := r.URL.Query().Get("verbose") == "1"

	providers := make(map[string]readyProvider, len(g.providers))
	configured, usable := 0, 0
	for id, entry := range g.providers {
		configured++
		if entry.usable() {
			usable++
			providers[id] = readyProvider{Status: "ok"}
			continue
		}
		st := readyProvider{Status: "degraded"}
		if verbose && entry.err != nil {
			st.Error = entry.err.Error()
		}
		providers[id] = st
	}

	code := http.StatusOK
	status := "ready"
	if configured > 0 && usable == 0 {
		code = http.StatusServiceUnavailable
		status = "degraded"
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":    status,
		"providers": providers,
	})
}
