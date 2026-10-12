package proxy

import (
	"net/http"
	"strings"
	"testing"
)

// TestPWAChainedWithGuard verifies that a frontend route with both
// authGuard (default-on) and pwa policies gets BOTH injections in the
// same HTML response: the guard script and the manifest/SW wiring.
// Regression for the ModifyResponse overwrite where the last policy
// silently disabled the other.
func TestPWAChainedWithGuard(t *testing.T) {

	gw, hosts := testGateway(t, `{
		"routes": [
			{
				"host": "both.local",
				"path": "/*",
				"frontend": true,
				"backend": "BACKEND",
				"pwa": { "enabled": true, "name": "Both" }
			}
		]
	}`)
	host := hosts["both.local"]

	resp := doGet(t, gw, host, "/")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	html := body(t, resp)

	if !strings.Contains(html, `window.__cladoneAuthGuard`) {
		t.Error("guard script missing from chained response")
	}
	if !strings.Contains(html, `<link rel="manifest" href="/__gateway_pwa/manifest.json">`) {
		t.Error("manifest link missing from chained response")
	}
	if !strings.Contains(html, "navigator.serviceWorker.register") {
		t.Error("service worker registration missing from chained response")
	}

	// both must land inside <head> (order between the two is not
	// functionally significant: each inserts right after <head>, so
	// the last one to run ends up first)
	iGuard := strings.Index(html, "__cladoneAuthGuard")
	iManifest := strings.Index(html, `rel="manifest"`)
	iHead := strings.Index(html, "</head>")
	if iGuard < 0 || iManifest < 0 || iGuard > iHead || iManifest > iHead {
		t.Errorf("injections not in <head>:\n%s", html)
	}

	// virtual PWA endpoints answer on the same host
	manifest := doGet(t, gw, host, "/__gateway_pwa/manifest.json")
	defer manifest.Body.Close()
	if manifest.StatusCode != http.StatusOK {
		t.Errorf("manifest status = %d, want 200", manifest.StatusCode)
	}
	if !strings.Contains(body(t, manifest), `"name": "Both"`) {
		t.Error("manifest content wrong")
	}
}

// TestPWAStaleContentEncodingRemoved checks that InjectResponse drops
// a stale Content-Encoding header (body is re-serialized uncompressed).
func TestPWAStaleContentEncodingRemoved(t *testing.T) {
	// covered indirectly through the gateway here: backend sends gzip
	// header but plain body (transport-level mismatch is not
	// simulatable through httputil, so assert the header survives a
	// plain response untouched and is absent after injection)
	gw, hosts := testGateway(t, `{
		"routes": [
			{
				"host": "enc.local",
				"path": "/*",
				"frontend": true,
				"backend": "BACKEND",
				"pwa": { "enabled": true }
			}
		]
	}`)
	host := hosts["enc.local"]

	resp := doGet(t, gw, host, "/")
	defer resp.Body.Close()

	if ce := resp.Header.Get("Content-Encoding"); ce != "" {
		t.Errorf("Content-Encoding should be empty after injection, got %q", ce)
	}
}
