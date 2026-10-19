package proxy

// Tests de upstream.rewriteCookies (point 12 de l'audit) : les
// Set-Cookie posés par l'origine avec Domain=<son propre host> sont
// rejetés par le navigateur depuis le host public — la policy les
// traduit (rewrite vers le host public, ou strip). Unitaires sur la
// chirurgie textuelle (byte-exact) + E2E via la gateway.

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cladone/gateway/internal/core"
)

// Table unitaire de rewriteCookieDomain : entrée = ligne Set-Cookie
// brute de l'origine, sortie attendue (byte-exact).
func TestRewriteCookieDomainRules(t *testing.T) {
	const origin = "jacquelot.benoit-rolland.workers.dev"
	cases := []struct {
		name string
		mode string
		in   string
		want string
	}{
		{
			name: "Domain exact réécrit vers public, autres attributs intacts",
			mode: "rewrite",
			in:   "theme=dark; Domain=" + origin + "; Path=/; Secure; HttpOnly; SameSite=Lax",
			want: "theme=dark; Domain=public.test; Path=/; Secure; HttpOnly; SameSite=Lax",
		},
		{
			name: "Domain parent de l'origine réécrit",
			mode: "rewrite",
			in:   "c=1; Domain=benoit-rolland.workers.dev",
			want: "c=1; Domain=public.test",
		},
		{
			name: "forme pointée RFC historique (.host)",
			mode: "rewrite",
			in:   "c=1; Domain=." + origin,
			want: "c=1; Domain=public.test",
		},
		{
			name: "casse de la clé et de la valeur indifférente (clé d'origine préservée)",
			mode: "rewrite",
			in:   "c=1; DOMAIN=Jacquelot.Benoit-Rolland.Workers.Dev",
			want: "c=1; DOMAIN=public.test",
		},
		{
			name: "Domain en dernier attribut",
			mode: "rewrite",
			in:   "c=1; Domain=" + origin,
			want: "c=1; Domain=public.test",
		},
		{
			name: "Domain sans rapport : intact",
			mode: "rewrite",
			in:   "c=1; Domain=cloudflare.com; Path=/",
			want: "c=1; Domain=cloudflare.com; Path=/",
		},
		{
			name: "pas de Domain : intact",
			mode: "rewrite",
			in:   "c=1; Path=/; Secure",
			want: "c=1; Path=/; Secure",
		},
		{
			name: "cookie attribut-seul (pas de '=') : intact",
			mode: "rewrite",
			in:   "flag",
			want: "flag",
		},
		{
			name: "valeur citée contenant un ';' : l'attribut reste trouvé",
			mode: "rewrite",
			in:   `c="a;b"; Domain=` + origin + `; Path=/`,
			want: `c="a;b"; Domain=public.test; Path=/`,
		},
		{
			name: "mode strip : attribut retiré, séparateur nettoyé",
			mode: "strip",
			in:   "c=1; Domain=" + origin + "; Path=/",
			want: "c=1; Path=/",
		},
		{
			name: "mode strip : Domain en dernier attribut",
			mode: "strip",
			in:   "c=1; Path=/; Domain=" + origin,
			want: "c=1; Path=/",
		},
		{
			name: "mode strip : Domain sans rapport intact",
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

// Un Set-Cookie de l'origine portant un nom réservé (session gateway)
// est retiré ; les autres passent (et sont traduits). Les noms de
// cookies sont sensibles à la casse : SESSION ≠ session, pas de drop.
func TestRewriteUpstreamCookiesDropsReservedNames(t *testing.T) {
	resp := &http.Response{Header: http.Header{}}
	for _, c := range []string{
		"access_token=abc; Path=/",
		"refresh_token=r; Path=/",
		"id_token=i; Path=/",
		"session=s; Path=/",
		"SESSION=pas-reserve; Path=/",
		"theme=dark; Domain=127.0.0.1",
	} {
		resp.Header.Add("Set-Cookie", c)
	}

	backend, _ := url.Parse("http://127.0.0.1:9000")
	route := &core.Route{Host: "public.test"}
	rewriteUpstreamCookies(route, backend, "public.test",
		&core.RewriteCookiesPolicy{Domain: "rewrite"}, resp)

	got := resp.Header.Values("Set-Cookie")
	want := []string{"SESSION=pas-reserve; Path=/", "theme=dark; Domain=public.test"}
	if len(got) != len(want) {
		t.Fatalf("Set-Cookie = %q, want %q", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("Set-Cookie[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

// E2E : la gateway traduit les Set-Cookie de l'origine ; sans la
// policy, ils traversent intacts (comportement historique).
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

		// host d'origine = 127.0.0.1 (hostname de l'URL backend)
		set := []string{
			"theme=dark; Domain=127.0.0.1; Path=/; Secure",
			"pref=big; Domain=cloudflare.com", // sans rapport : intact
			"noflag=1",                        // pas de Domain : intact
			"session=pirate; Path=/",          // nom réservé : droppé
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

	t.Run("sans policy : historique intact", func(t *testing.T) {
		got := run(t, `{"host": true}`)
		if len(got) != 4 {
			t.Fatalf("Set-Cookie = %q (4 attendus)", got)
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

// La grammaire stricte refuse un mode inconnu.
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
		t.Fatal("config acceptée : rewriteCookies.domain invalide devrait être refusé")
	} else if !strings.Contains(err.Error(), "rewriteCookies.domain") {
		t.Errorf("erreur sans le contexte attendu : %v", err)
	}
}
