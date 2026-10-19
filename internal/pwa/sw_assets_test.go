package pwa

import (
	"strings"
	"testing"

	"cladone/gateway/internal/core"
)

func TestSWAssetsStrategyDefault(t *testing.T) {
	sw := New(&core.PWAPolicy{Enabled: true}).swJS()
	if !strings.Contains(sw, "workbox.strategies.StaleWhileRevalidate") {
		t.Fatalf("expected default staleWhileRevalidate:\n%s", sw[:600])
	}
	if strings.Contains(sw, "networkTimeoutSeconds") {
		t.Fatal("no timeout expected by default")
	}
}

func TestSWAssetsStrategyNetworkFirst(t *testing.T) {
	pol := &core.PWAPolicy{Enabled: true, Assets: &core.PWAAssetsPolicy{
		Strategy: "networkFirst", NetworkTimeoutSeconds: 5,
	}}
	sw := New(pol).swJS()
	if !strings.Contains(sw, "workbox.strategies.NetworkFirst") {
		t.Fatalf("expected networkFirst:\n%s", sw[:600])
	}
	if !strings.Contains(sw, "networkTimeoutSeconds: 5") {
		t.Fatal("expected timeout 5")
	}
}

func TestSWAssetsStrategyUnknownFallsBack(t *testing.T) {
	pol := &core.PWAPolicy{Enabled: true, Assets: &core.PWAAssetsPolicy{Strategy: "zzz"}}
	sw := New(pol).swJS()
	if !strings.Contains(sw, "workbox.strategies.StaleWhileRevalidate") {
		t.Fatal("unknown strategy must fall back to staleWhileRevalidate")
	}
}

// emptyPolicyWithApiCache returns an active PWA policy with a
// default apiCache (the endpoint used in prod).
func emptyPolicyWithApiCache() *core.PWAPolicy {
	pol := emptyPolicy()
	pol.ApiCaches = []*core.PWAApiCache{{Path: "/api/process_stream"}}
	return pol
}

// The offline replay must not suffer the full TCP timeout of a
// dead network: navigator.onLine=false short-circuits the fetch, and
// online the fetch is aborted after networkTimeoutSeconds (default 3).
func TestSWApiCacheOfflineFastPath(t *testing.T) {
	sw := New(emptyPolicyWithApiCache()).swJS()

	for _, want := range []string{
		"const OFFLINE_FAST_api_process_stream = true;",                  // default fast-path
		"if (OFFLINE_FAST_api_process_stream && !self.navigator.onLine)", // offline short-circuit
		"replay offline (onLine=false)",                                  // distinct log
		"function fetchNetwork(req, timeoutSec)",                         // abort helper
		"AbortController()",
		"await fetchNetwork(req, 3)", // 3 s default rendered
	} {
		if !strings.Contains(sw, want) {
			t.Errorf("sw.js apiCache offline fast path missing %s", want)
		}
	}
}

// networkTimeoutSeconds declared: the generated timeout reflects it.
func TestSWApiCacheNetworkTimeoutDeclared(t *testing.T) {
	pol := emptyPolicyWithApiCache()
	pol.ApiCaches[0].NetworkTimeoutSeconds = 5
	sw := New(pol).swJS()
	if !strings.Contains(sw, "await fetchNetwork(req, 5)") {
		t.Error("networkTimeoutSeconds=5 not rendered in the SW")
	}
	if strings.Contains(sw, "await fetchNetwork(req, 3)") {
		t.Error("the 3 s default must not appear with a declared timeout")
	}
}

// offlineFastPath per endpoint: active by default, can be disabled.
func TestSWApiCacheOfflineFastPathConfig(t *testing.T) {
	// by default: active fast-path
	sw := New(emptyPolicyWithApiCache()).swJS()
	if !strings.Contains(sw, "const OFFLINE_FAST_api_process_stream = true;") {
		t.Error("offlineFastPath should be active by default")
	}

	// disabled: the onLine check must no longer short-circuit THIS
	// endpoint (const false), and the network logic stays unchanged
	falseVal := false
	pol := emptyPolicyWithApiCache()
	pol.ApiCaches[0].OfflineFastPath = &falseVal
	sw2 := New(pol).swJS()
	if !strings.Contains(sw2, "const OFFLINE_FAST_api_process_stream = false;") {
		t.Error("offlineFastPath=false not rendered in the SW")
	}

	// two endpoints: each its own flag
	pol2 := emptyPolicy()
	pol2.ApiCaches = []*core.PWAApiCache{
		{Path: "/api/process_stream", OfflineFastPath: &falseVal},
		{Path: "/api/other"},
	}
	sw3 := New(pol2).swJS()
	if !strings.Contains(sw3, "const OFFLINE_FAST_api_process_stream = false;") {
		t.Error("endpoint 1: disabled fast-path not rendered")
	}
	if !strings.Contains(sw3, "const OFFLINE_FAST_api_other = true;") {
		t.Error("endpoint 2: default active fast-path not rendered")
	}
}
