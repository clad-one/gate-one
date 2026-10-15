package pwa

import (
	"strings"
	"testing"

	"cladone/gateway/internal/core"
)

// method:"GET" sur un endpoint déclaré => route SWR (cache répond
// immédiatement, réseau rafraîchit en fond), pas le replay network-first.
func TestSWApiCacheMethodGET(t *testing.T) {
	pol := emptyPolicy()
	pol.ApiCaches = []*core.PWAApiCache{{Path: "/openapi.json", Method: "GET"}}
	sw := New(pol).swJS()

	for _, want := range []string{
		"url.pathname === '/openapi.json'",
		"StaleWhileRevalidate-like SWR marker absent", // see below
	} {
		_ = want // nothing: assertions below use dedicated checks
	}
	if !strings.Contains(sw, "workbox.routing.registerRoute(\n    ({url}) => url.pathname === '/openapi.json'") {
		t.Fatalf("route GET non générée:\n%s", sw)
	}
	if !strings.Contains(sw, "cache.match(req)") {
		t.Error("GET: cache.match(req) (clé = URL seule) attendu")
	}
	if !strings.Contains(sw, "'GET'\n  );") {
		t.Error("GET: route enregistrée méthode 'GET' attendue")
	}
	if strings.Contains(sw, "storeCompleteResponse(cache, 'gateway-pwa-api-openapi.json") {
		t.Error("GET: pas de storeCompleteResponse (pas de tee/idle SSE)")
	}
}

// Défaut : method vide = POST, comportement inchangé (replay).
func TestSWApiCacheMethodDefaultPOST(t *testing.T) {
	pol := emptyPolicy()
	pol.ApiCaches = []*core.PWAApiCache{{Path: "/api/process_stream"}}
	sw := New(pol).swJS()
	if !strings.Contains(sw, "'POST'\n  );") {
		t.Error("POST: route enregistrée méthode 'POST' attendue")
	}
	if !strings.Contains(sw, "storeCompleteResponse") {
		t.Error("POST: storeCompleteResponse (tee/idle) attendu")
	}
}

// apiGETCache présent => catch-all GET en dernier, excluant le préfixe
// virtuel, les paths déclarés et les excludes déclarés.
func TestSWApiGETCatchAll(t *testing.T) {
	pol := emptyPolicy()
	pol.ApiCaches = []*core.PWAApiCache{{Path: "/api/process_stream"}}
	pol.ApiGETCache = &core.PWAApiGETCache{Excludes: []string{"/api/auth/"}}
	sw := New(pol).swJS()

	// catch-all enregistrée après les routes explicites
	iExplicit := strings.Index(sw, "url.pathname === '/api/process_stream'")
	iAll := strings.Index(sw, "gateway-pwa-api-all-v")
	if iExplicit < 0 || iAll < 0 {
		t.Fatalf("routes attendues absentes: explicit=%d all=%d", iExplicit, iAll)
	}
	if iAll < iExplicit {
		t.Error("catch-all enregistrée AVANT la route explicite")
	}

	for _, want := range []string{
		"!url.pathname.startsWith('" + PathPrefix + "')",
		"!url.pathname.startsWith('/api/process_stream')",
		"!url.pathname.startsWith('/api/auth/')",
		"maxEntries: 200",
		"maxAgeSeconds: 86400",
		"purgeOnQuotaError: true",
	} {
		if !strings.Contains(sw, want) {
			t.Errorf("catch-all attendu %q:\n%s", want, sw[iAll-200:])
		}
	}
}

// apiGETCache absent => aucune régression : pas de catch-all générée.
func TestSWApiGETCatchAllAbsent(t *testing.T) {
	sw := New(emptyPolicy()).swJS()
	if strings.Contains(sw, "gateway-pwa-api-all-v") {
		t.Error("catch-all générée sans apiGETCache")
	}
}

// Reconfigurer la catch-all n'invalide pas les caches des endpoints
// explicites, et inversement (hachage par bloc, cf. versionnage).
func TestApiGETCatchAllVersioning(t *testing.T) {
	pol1 := emptyPolicy()
	pol1.ApiGETCache = &core.PWAApiGETCache{}
	name1 := extractCatchAllName(New(pol1).swJS())

	pol2 := emptyPolicy()
	pol2.ApiGETCache = &core.PWAApiGETCache{Excludes: []string{"/x/"}}
	name2 := extractCatchAllName(New(pol2).swJS())

	if name1 == "" || name2 == "" {
		t.Fatalf("noms vides: %q / %q", name1, name2)
	}
	if name1 == name2 {
		t.Errorf("changer excludes n'a pas invalidé la catch-all: %q", name1)
	}

	// endpoint déclaré reconfiguré : la catch-all garde son nom
	pol3 := emptyPolicy()
	pol3.ApiGETCache = &core.PWAApiGETCache{}
	pol3.ApiCaches = []*core.PWAApiCache{{Path: "/api/a"}}
	nA := extractCatchAllName(New(pol3).swJS())
	pol4 := emptyPolicy()
	pol4.ApiGETCache = &core.PWAApiGETCache{}
	pol4.ApiCaches = []*core.PWAApiCache{{Path: "/api/a", MaxEntries: 9}}
	nB := extractCatchAllName(New(pol4).swJS())
	if nA != nB {
		t.Errorf("reconfigurer un endpoint a invalidé la catch-all: %q vs %q", nA, nB)
	}
}

func extractCatchAllName(sw string) string {
	marker := "caches.open('gateway-pwa-api-all-"
	i := strings.Index(sw, marker)
	if i < 0 {
		return ""
	}
	rest := sw[i+len(marker):]
	j := strings.Index(rest, "'")
	if j < 0 {
		return ""
	}
	return rest[:j]
}

// method "none" : le path est opt-out du caching — aucune route
// générée pour lui, la catch-all l'ignore (path déclaré = maître).
func TestSWApiCacheMethodNone(t *testing.T) {
	pol := emptyPolicy()
	pol.ApiCaches = []*core.PWAApiCache{
		{Path: "/api/live", Method: "none"},
		{Path: "/api/poems", Method: "GET"},
	}
	pol.ApiGETCache = &core.PWAApiGETCache{}
	sw := New(pol).swJS()

	// aucune route pour /api/live
	if strings.Contains(sw, "url.pathname === '/api/live'") {
		t.Error("method none: aucune route ne doit être générée pour le path")
	}
	if strings.Contains(sw, "gateway-pwa-api-api-live-") {
		t.Error("method none: aucun cache dédié ne doit être créé")
	}
	// la catch-all l'exclut tout de même (défense en profondeur si un
	// autre jour l'exclusion des paths déclarés change de forme)
	if !strings.Contains(sw, "!url.pathname.startsWith('/api/live')") {
		t.Error("method none: le path doit rester exclu de la catch-all")
	}
	// l'autre endpoint fonctionne normalement
	if !strings.Contains(sw, "url.pathname === '/api/poems'") {
		t.Error("method none: l'endpoint voisin doit rester générés")
	}
	// case-insensitive
	pol2 := emptyPolicy()
	pol2.ApiCaches = []*core.PWAApiCache{{Path: "/api/x", Method: "NONE"}}
	sw2 := New(pol2).swJS()
	if strings.Contains(sw2, "url.pathname === '/api/x'") {
		t.Error("method NONE (majuscule) doit aussi opt-out")
	}
}
