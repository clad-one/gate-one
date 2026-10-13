package pwa

import (
	"strings"
	"testing"

	"cladone/gateway/internal/core"
)

func TestSWAssetsStrategyDefault(t *testing.T) {
	sw := New(&core.PWAPolicy{Enabled: true}).swJS()
	if !strings.Contains(sw, "workbox.strategies.StaleWhileRevalidate") {
		t.Fatalf("défaut attendu staleWhileRevalidate:\n%s", sw[:600])
	}
	if strings.Contains(sw, "networkTimeoutSeconds") {
		t.Fatal("pas de timeout attendu par défaut")
	}
}

func TestSWAssetsStrategyNetworkFirst(t *testing.T) {
	pol := &core.PWAPolicy{Enabled: true, Assets: &core.PWAAssetsPolicy{
		Strategy: "networkFirst", NetworkTimeoutSeconds: 5,
	}}
	sw := New(pol).swJS()
	if !strings.Contains(sw, "workbox.strategies.NetworkFirst") {
		t.Fatalf("networkFirst attendu:\n%s", sw[:600])
	}
	if !strings.Contains(sw, "networkTimeoutSeconds: 5") {
		t.Fatal("timeout 5 attendu")
	}
}

func TestSWAssetsStrategyUnknownFallsBack(t *testing.T) {
	pol := &core.PWAPolicy{Enabled: true, Assets: &core.PWAAssetsPolicy{Strategy: "zzz"}}
	sw := New(pol).swJS()
	if !strings.Contains(sw, "workbox.strategies.StaleWhileRevalidate") {
		t.Fatal("stratégie inconnue doit retomber sur staleWhileRevalidate")
	}
}

// emptyPolicyWithApiCache retourne une politique PWA active avec un
// apiCache par défaut (le endpoint utilisé en prod).
func emptyPolicyWithApiCache() *core.PWAPolicy {
	pol := emptyPolicy()
	pol.ApiCaches = []*core.PWAApiCache{{Path: "/api/process_stream"}}
	return pol
}

// Le replay offline ne doit pas subir le timeout TCP complet d'un
// réseau mort : navigator.onLine=false court-circuite le fetch, et
// en ligne le fetch est aborté après networkTimeoutSeconds (défaut 3).
func TestSWApiCacheOfflineFastPath(t *testing.T) {
	sw := New(emptyPolicyWithApiCache()).swJS()

	for _, want := range []string{
		"const OFFLINE_FAST_api_process_stream = true;", // fast-path par défaut
		"if (OFFLINE_FAST_api_process_stream && !self.navigator.onLine)", // court-circuit offline
		"replay offline (onLine=false)",       // log distinct
		"function fetchNetwork(req, timeoutSec)", // helper abort
		"AbortController()",
		"await fetchNetwork(req, 3)", // défaut 3 s rendu
	} {
		if !strings.Contains(sw, want) {
			t.Errorf("sw.js apiCache offline fast path missing %s", want)
		}
	}
}

// networkTimeoutSeconds déclaré : le timeout généré le reflète.
func TestSWApiCacheNetworkTimeoutDeclared(t *testing.T) {
	pol := emptyPolicyWithApiCache()
	pol.ApiCaches[0].NetworkTimeoutSeconds = 5
	sw := New(pol).swJS()
	if !strings.Contains(sw, "await fetchNetwork(req, 5)") {
		t.Error("networkTimeoutSeconds=5 non rendu dans le SW")
	}
	if strings.Contains(sw, "await fetchNetwork(req, 3)") {
		t.Error("le défaut 3 s ne doit pas apparaître avec un timeout déclaré")
	}
}

// offlineFastPath par endpoint : actif par défaut, désactivable.
func TestSWApiCacheOfflineFastPathConfig(t *testing.T) {
	// par défaut : fast-path actif
	sw := New(emptyPolicyWithApiCache()).swJS()
	if !strings.Contains(sw, "const OFFLINE_FAST_api_process_stream = true;") {
		t.Error("offlineFastPath devrait être actif par défaut")
	}

	// désactivé : le check onLine ne doit plus court-circuiter CETTE
	// endpoint (const false), et la logique réseau reste inchangée
	falseVal := false
	pol := emptyPolicyWithApiCache()
	pol.ApiCaches[0].OfflineFastPath = &falseVal
	sw2 := New(pol).swJS()
	if !strings.Contains(sw2, "const OFFLINE_FAST_api_process_stream = false;") {
		t.Error("offlineFastPath=false non rendu dans le SW")
	}

	// deux endpoints : chacun son flag
	pol2 := emptyPolicy()
	pol2.ApiCaches = []*core.PWAApiCache{
		{Path: "/api/process_stream", OfflineFastPath: &falseVal},
		{Path: "/api/other"},
	}
	sw3 := New(pol2).swJS()
	if !strings.Contains(sw3, "const OFFLINE_FAST_api_process_stream = false;") {
		t.Error("endpoint 1: fast-path désactivé non rendu")
	}
	if !strings.Contains(sw3, "const OFFLINE_FAST_api_other = true;") {
		t.Error("endpoint 2: fast-path actif par défaut non rendu")
	}
}
