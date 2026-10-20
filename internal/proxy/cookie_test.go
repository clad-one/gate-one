package proxy

// Tests of upstream.rewriteCookies (audit point 12): Set-Cookies set
// by the origin with Domain=<its own host> are rejected by the
// browser from the public host — the policy translates them (rewrite
// toward the public host, or strip). Unit tests on the (byte-exact)
// textual surgery + E2E through the gateway.

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cladone/gate-one/internal/core"
)

// Unit table of rewriteCookieDomain: input = raw Set-Cookie line
// from the origin, expected output (byte-exact).
func TestRewriteCookieDomainRules(t *testing.T) {
	const origin = "jacquelot.benoit-rolland.workers.dev"
	cases := []struct {
		name string
		mode string
		in   string
		want string
	}{
		{
			name: "exact Domain rewritten to public, other attributes untouched",
			mode: "rewrite",
			in:   "theme=dark; Domain=" + origin + "; Path=/; Secure; HttpOnly; SameSite=Lax",
			want: "theme=dark; Domain=public.test; Path=/; Secure; HttpOnly; SameSite=Lax",
		},
		{
			name: "Domain parent of the origin rewritten",
			mode: "rewrite",
			in:   "c=1; Domain=benoit-rolland.workers.dev",
			want: "c=1; Domain=public.test",
		},
		{
			name: "historical RFC dotted form (.host)",
			mode: "rewrite",
			in:   "c=1; Domain=." + origin,
			want: "c=1; Domain=public.test",
		},
		{
			name: "key and value case-insensitive (origin key preserved)",
			mode: "rewrite",
			in:   "c=1; DOMAIN=Jacquelot.Benoit-Rolland.Workers.Dev",
			want: "c=1; DOMAIN=public.test",
		},
		{
			name: "Domain as last attribute",
			mode: "rewrite",
			in:   "c=1; Domain=" + origin,
			want: "c=1; Domain=public.test",
		},
		{
			name: "unrelated Domain: untouched",
			mode: "rewrite",
			in:   "c=1; Domain=cloudflare.com; Path=/",
			want: "c=1; Domain=cloudflare.com; Path=/",
		},
		{
			name: "no Domain: untouched",
			mode: "rewrite",
			in:   "c=1; Path=/; Secure",
			want: "c=1; Path=/; Secure",
		},
		{
			name: "attribute-only cookie (no '='): untouched",
			mode: "rewrite",
			in:   "flag",
			want: "flag",
		},
		{
			name: "quoted value containing a ';': the attribute is still found",
			mode: "rewrite",
			in:   `c="a;b"; Domain=` + origin + `; Path=/`,
			want: `c="a;b"; Domain=public.test; Path=/`,
		},
		{
			name: "strip mode: attribute removed, separator cleaned",
			mode: "strip",
			in:   "c=1; Domain=" + origin + "; Path=/",
			want: "c=1; Path=/",
		},
		{
			name: "strip mode: Domain as last attribute",
			mode: "strip",
			in:   "c=1; Path=/; Domain=" + origin,
			want: "c=1; Path=/",
		},
		{
			name: "strip mode: unrelated Domain untouched",
			mode: "strip",
			in:   "c=1; Domain=cloudflare.com",
			want: "c=1; Domain=cloudflare.com",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := rewriteCookieDomain(tc.in, origin, "public.test", tc.mode)
			if got != tc.want {
				t.Errorf("\n in  %q\n got %q\nwant %q", tc.in, got, tc.want)
			}
		})
	}
}

// A Set-Cookie from the origin carrying a reserved name (gateway
// session) is dropped; the others pass (and are translated). Cookie
// names are case-sensitive: SESSION ≠ session, no drop.
func TestRewriteUpstreamCookiesDropsReservedNames(t *testing.T) {
	resp := &http.Response{Header: http.Header{}}
	for _, c := range []string{
		"access_token=abc; Path=/",
		"refresh_token=r; Path=/",
		"id_token=i; Path=/",
		"session=s; Path=/",
		"SESSION=not-reserved; Path=/",
		"theme=dark; Domain=127.0.0.1",
	} {
		resp.Header.Add("Set-Cookie", c)
	}

	backend, _ := url.Parse("http://127.0.0.1:9000")
	route := &core.Route{Host: "public.test"}
	rewriteUpstreamCookies(route, backend, "public.test",
		&core.RewriteCookiesPolicy{Domain: "rewrite"}, resp)

	got := resp.Header.Values("Set-Cookie")
	want := []string{"SESSION=not-reserved; Path=/", "theme=dark; Domain=public.test"}
	if len(got) != len(want) {
		t.Fatalf("Set-Cookie = %q, want %q", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("Set-Cookie[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

// E2E: the gateway translates the origin's Set-Cookies; without the
// policy, they pass through untouched (historical behavior).
func TestRewriteCookiesGatewayE2E(t *testing.T) {
	run := func(t *testing.T, upstreamJSON string) []string {
		t.Helper()
		gw, _ := upstreamGateway(t, fmt.Sprintf(`{
			"routes": [{
				"host": "public.test", "path": "/*",
				"backend": "BACKEND",
				"upstream": %s
			}]
		}`, upstreamJSON))

		// origin host = 127.0.0.1 (hostname of the backend URL)
		set := []string{
			"theme=dark; Domain=127.0.0.1; Path=/; Secure",
			"pref=big; Domain=cloudflare.com", // unrelated: untouched
			"noflag=1",                        // no Domain: untouched
			"session=pirate; Path=/",          // reserved name: dropped
		}
		q := url.Values{}
		for _, c := range set {
			q.Add("set", c)
		}
		resp := doGet(t, gw, "public.test", "/setcookie?"+q.Encode())
		if resp.StatusCode != http.StatusNoContent &&
			resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d", resp.StatusCode)
		}
		return resp.Header.Values("Set-Cookie")
	}

	t.Run("policy rewrite", func(t *testing.T) {
		got := run(t, `{"host": true, "rewriteCookies": {"domain": "rewrite"}}`)
		want := []string{
			"theme=dark; Domain=public.test; Path=/; Secure",
			"pref=big; Domain=cloudflare.com",
			"noflag=1",
		}
		if len(got) != len(want) {
			t.Fatalf("Set-Cookie = %q, want %q", got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("Set-Cookie[%d] =\n got  %q\n want %q", i, got[i], want[i])
			}
		}
	})

	t.Run("without policy: history untouched", func(t *testing.T) {
		got := run(t, `{"host": true}`)
		if len(got) != 4 {
			t.Fatalf("Set-Cookie = %q (4 expected)", got)
		}
		for i, c := range []string{
			"theme=dark; Domain=127.0.0.1; Path=/; Secure",
			"pref=big; Domain=cloudflare.com",
			"noflag=1",
			"session=pirate; Path=/",
		} {
			if got[i] != c {
				t.Errorf("Set-Cookie[%d] = %q, want %q", i, got[i], c)
			}
		}
	})
}

// The strict grammar rejects an unknown mode.
func TestRewriteCookiesRejectsUnknownMode(t *testing.T) {
	srv := upstreamTestServer(t)
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "routes.json")
	routesJSON := fmt.Sprintf(`{
		"routes": [{
			"host": "public.test", "path": "/*",
			"backend": %q,
			"upstream": {"rewriteCookies": {"domain": "frobnicate"}}
		}]
	}`, srv.URL)
	if err := os.WriteFile(cfgPath, []byte(routesJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := core.Load(cfgPath); err == nil {
		t.Fatal("config accepted: invalid rewriteCookies.domain should be rejected")
	} else if !strings.Contains(err.Error(), "rewriteCookies.domain") {
		t.Errorf("error without the expected context: %v", err)
	}
}
