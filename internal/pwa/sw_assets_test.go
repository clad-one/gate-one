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
