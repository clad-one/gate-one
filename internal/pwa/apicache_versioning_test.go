package pwa

import (
	"strings"
	"testing"

	"cladone/gateway/internal/core"
)

// extractApiCacheName returns the generated apiCache cache name from a
// generated SW body.
func extractApiCacheName(sw string) string {
	marker := "caches.open('gateway-pwa-api-"
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

// Reconfigurer UN endpoint n'invalide que son cache : l'autre endpoint
// garde son nom (et donc son contenu), les caches assets aussi.
func TestApiCacheVersioningPerEndpoint(t *testing.T) {
	pol1 := emptyPolicy()
	pol1.ApiCaches = []*core.PWAApiCache{
		{Path: "/api/process_stream"},
		{Path: "/api/other"},
	}
	n1 := extractApiCacheName(New(pol1).swJS())

	// changement de config sur un autre endpoint : process_stream conserve
	// son nom de cache
	pol2 := emptyPolicy()
	pol2.ApiCaches = []*core.PWAApiCache{
		{Path: "/api/process_stream"},
		{Path: "/api/other", MaxEntries: 99},
	}
	n2 := extractApiCacheName(New(pol2).swJS())
	if n1 == "" || n2 == "" {
		t.Fatalf("noms vides: %q / %q", n1, n2)
	}
	if n1 != n2 {
		t.Errorf("reconfigurer /api/other a invalidé /api/process_stream: %q vs %q", n1, n2)
	}

	// reconfigurer le endpoint lui-même change son nom de cache
	pol3 := emptyPolicy()
	pol3.ApiCaches = []*core.PWAApiCache{
		{Path: "/api/process_stream", MaxEntries: 99},
		{Path: "/api/other", MaxEntries: 99},
	}
	n3 := extractApiCacheName(New(pol3).swJS())
	if n3 == n1 {
		t.Errorf("reconfigurer /api/process_stream n'a pas invalidé son cache: %q", n3)
	}
}

// Le nom de cache API ne dépend plus du hash du SW : un commentaire
// ajouté au SW (sans changement de politique) conserve le nom de cache
// API => le replay offline survive aux déploiements anodins.
func TestApiCacheNameStableAcrossSWChanges(t *testing.T) {
	pol := emptyPolicy()
	pol.ApiCaches = []*core.PWAApiCache{{Path: "/api/process_stream"}}
	sw1 := New(pol).swJS()

	// changement sans rapport : stratégie assets explicite (modifie le
	// texte du SW, donc son hash global, mais pas la politique apiCache)
	pol.Assets = &core.PWAAssetsPolicy{Strategy: "networkFirst"}
	sw2 := New(pol).swJS()

	if extractCacheVersion(sw1) == extractCacheVersion(sw2) {
		t.Skip("le hash global n'a pas changé — test non discriminant")
	}
	if extractApiCacheName(sw1) != extractApiCacheName(sw2) {
		t.Errorf("cache API invalidé par un changement sans rapport:\n%q\nvs\n%q",
			extractApiCacheName(sw1), extractApiCacheName(sw2))
	}
}
