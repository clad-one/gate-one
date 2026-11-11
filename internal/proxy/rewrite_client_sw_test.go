package proxy

import (
	"io"
	"strings"
	"testing"

	"cladone/gate-one/internal/pwa"
)

// TestRewriteClientSideSW pins the client-side layer of
// upstream.rewriteBody:
//
//   - it is REGISTERED exactly when nothing else registers it (no
//     guard, no PWA policy) — the case of a proxified static site with
//     frontend:false, where dynamic JS URLs were previously left
//     unrewritten;
//   - clientSide:"off" disables every client layer (no registration,
//     no in-page patch) while keeping the server-side HTML rewriting;
//   - /__gate-one_pwa/sw.js always answers with the right script,
//     including the REMOVAL tombstone once the layer is off (an
//     installed worker survives a configuration change).
func TestRewriteClientSideSW(t *testing.T) {
	fragment := pwa.RewriteRegistrationHTML()

	route := func(extra string) string {
		return `{
			"oidc": {"loginUrl": "https://login.test/login"},
			"routes": [{
				"host": "app.test",
				"path": "/*",
				"backend": "BACKEND",
				"upstream": {"host": true, "rewriteBody": {"enabled": true` +
			extra + `}}
			}]
		}`
	}

	cases := []struct {
		name         string
		routes       string
		wantFragment bool   // our registration script in the HTML
		wantGuard    bool   // the guard script in the HTML
		wantSW       string // substring of /__gate-one_pwa/sw.js
		rejectSW     string // substring that must NOT appear
	}{
		{
			name:         "auto without guard or PWA registers the worker",
			routes:       route(""),
			wantFragment: true,
			wantSW:       "rwMatch",
			rejectSW:     "unregister",
		},
		{
			name:     "clientSide off serves the removal tombstone",
			routes:   route(`, "clientSide": "off"`),
			wantSW:   "self.registration.unregister()",
			rejectSW: "rwMatch",
		},
		{
			name:      "the guard registers the worker itself",
			routes:    strings.Replace(route(""), `"backend": "BACKEND",`, `"backend": "BACKEND", "frontend": true,`, 1),
			wantGuard: true,
			wantSW:    "rwMatch",
			rejectSW:  "unregister",
		},
		{
			name:      "clientSide off disables the guard registration too",
			routes:    strings.Replace(route(`, "clientSide": "off"`), `"backend": "BACKEND",`, `"backend": "BACKEND", "frontend": true,`, 1),
			wantGuard: true,
			wantSW:    "self.registration.unregister()",
			rejectSW:  "rwMatch",
		},
		{
			name:     "a PWA policy keeps its workbox worker",
			routes:   strings.Replace(route(""), `"backend": "BACKEND",`, `"backend": "BACKEND", "pwa": {"enabled": true},`, 1),
			wantSW:   "workbox",
			rejectSW: "self.registration.unregister()",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gw, hosts := testGateway(t, tc.routes)
			host := hosts["app.test"]

			resp := doGet(t, gw, host, "/")
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}
			page := string(body)

			if resp.StatusCode != 200 {
				t.Fatalf("page status = %d: %s", resp.StatusCode, page)
			}
			if got := strings.Contains(page, fragment); got != tc.wantFragment {
				t.Errorf("rewrite SW registration present = %t, want %t",
					got, tc.wantFragment)
			}
			if got := strings.Contains(page, "__cladoneAuthGuard"); got != tc.wantGuard {
				t.Errorf("guard script present = %t, want %t", got, tc.wantGuard)
			}

			// The endpoint must always answer: this is what reaches a
			// browser that still holds a registration.
			sw := doGet(t, gw, host, "/__gate-one_pwa/sw.js")
			defer sw.Body.Close()
			body, err = io.ReadAll(sw.Body)
			if err != nil {
				t.Fatal(err)
			}
			script := string(body)
			if sw.StatusCode != 200 {
				t.Fatalf("sw.js status = %d", sw.StatusCode)
			}
			if !strings.Contains(script, tc.wantSW) {
				t.Errorf("sw.js does not contain %q:\n%s", tc.wantSW, script)
			}
			if tc.rejectSW != "" && strings.Contains(script, tc.rejectSW) {
				t.Errorf("sw.js unexpectedly contains %q", tc.rejectSW)
			}
		})
	}
}

// TestRewriteSWShipsExceptionsArray: rwMatch reads RW.except.length,
// so the payload must ALWAYS carry the array — an omitted field threw a
// TypeError in the fetch handler and silently disabled the interception
// of every runtime call (found by a browser test on a route with no
// exception).
func TestRewriteSWShipsExceptionsArray(t *testing.T) {
	gw, hosts := testGateway(t, `{
		"oidc": {"loginUrl": "https://login.test/login"},
		"routes": [{"host": "app.test", "path": "/*", "backend": "BACKEND",
		 "upstream": {"host": true, "rewriteBody": {"enabled": true}}}]
	}`)

	resp := doGet(t, gw, hosts["app.test"], "/__gate-one_pwa/sw.js")
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	script := string(body)
	if !strings.Contains(script, `"except":[]`) {
		t.Fatalf("SW payload omits the exceptions array:\n%s", script)
	}
	// Defensive fallback for a worker already installed with the old
	// payload.
	if !strings.Contains(script, "RW.except || []") {
		t.Fatal("rwMatch does not tolerate a missing exceptions array")
	}
}

// TestRewriteClientSideGuardFlag: the guard script must carry the
// client-side flag, otherwise a clientSide:"off" route would still
// register the worker from its own guard.
func TestRewriteClientSideGuardFlag(t *testing.T) {
	on := `{
		"oidc": {"loginUrl": "https://login.test/login"},
		"routes": [{"host": "app.test", "path": "/*", "backend": "BACKEND",
		 "frontend": true,
		 "upstream": {"host": true, "rewriteBody": {"enabled": true}}}]
	}`
	off := strings.Replace(on, `"enabled": true}}`, `"enabled": true, "clientSide": "off"}}`, 1)

	for _, tc := range []struct {
		name string
		cfg  string
		want string
	}{
		{"auto", on, "var CLIENT_SW = true;"},
		{"off", off, "var CLIENT_SW = false;"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gw, hosts := testGateway(t, tc.cfg)
			resp := doGet(t, gw, hosts["app.test"], "/")
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			if !strings.Contains(string(body), tc.want) {
				t.Fatalf("guard script missing %q", tc.want)
			}
		})
	}
}
