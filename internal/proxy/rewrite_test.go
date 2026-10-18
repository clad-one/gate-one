package proxy

import (
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"cladone/gateway/internal/core"
	"cladone/gateway/internal/pwa"
)

// Politique de réécriture de test : origine "origin.example" réécrite
// vers "https://public.test", exceptions couvrant les trois verdicts :
// rester à l'origine (forme chaîne), host alternatif ({path,to}), et
// le préfixe le plus long gagne (/l1/detail règle longue contre /l1).
// Tri : préfixe le plus long d'abord (comme après compilation).
func rewriteTestPlan() *rewritePlan {
	except := []core.RewriteExcept{
		{Path: "/lecture/bonpapa"},
		{Path: "/l1/detail", To: "https://deep.example"},
		{Path: "/l1"},
		{Path: "/alt", To: "https://alt.example"},
	}
	maxExcept := 0
	for _, e := range except {
		if len(e.Path) > maxExcept {
			maxExcept = len(e.Path)
		}
	}
	return &rewritePlan{
		origins:   []string{"origin.example"},
		pub:       "https://public.test",
		except:    except,
		hold:      len("https://") + len("origin.example"),
		maxExcept: maxExcept,
	}
}

// rewriteTestSpec : la même politique côté SW client.
func rewriteTestSpec() *pwa.RewriteSpec {
	return rewriteTestPlan().clientSpec()
}

type rwCase struct {
	Name string
	// Input : entrée HTML/texte ; pour la parité SW : URL absolue pure.
	Input string
	// Expect = sortie EXACTE attendue ; vide = le texte original passe
	// sans modification (aucune interception/réécriture).
	Expect string
}

// rewriteTextCases : liste partagée des sémantiques — le moteur en
// flux (découpes 1..4096 octets), l'oracle bufferisé indépendant et le
// SW JS (harnais node, cf. rewrite_parity_harness.cjs) doivent
// produire EXACTEMENT la même sortie pour ces entrées.
func rewriteTextCases() []rwCase {
	return []rwCase{
		{
			Name:   "https simple",
			Input:  `<a href="https://origin.example/edit/page?x=1">edit</a>`,
			Expect: `<a href="https://public.test/edit/page?x=1">edit</a>`,
		},
		{
			Name:   "http simple réécrit en https",
			Input:  `<a href="http://origin.example/x">`,
			Expect: `<a href="https://public.test/x">`,
		},
		{
			Name:   "schéma relatif",
			Input:  `<img src="//origin.example/img.png">`,
			Expect: `<img src="https://public.test/img.png">`,
		},
		{
			Name:  "exception chaîne : reste à l'origine",
			Input: `<a href="https://origin.example/lecture/bonpapa/ch1">l</a>`,
		},
		{
			Name:  "exception chaîne avec query",
			Input: `<a href="https://origin.example/lecture/bonpapa/fin?y=2">l</a>`,
		},
		{
			Name:   "exception {path,to}",
			Input:  `<a href="https://origin.example/alt/chemin">a</a>`,
			Expect: `<a href="https://alt.example/alt/chemin">a</a>`,
		},
		{
			Name:   "préfixe le plus long gagne (to)",
			Input:  `<a href="https://origin.example/l1/detail/ou">d</a>`,
			Expect: `<a href="https://deep.example/l1/detail/ou">d</a>`,
		},
		{
			Name:  "préfixe le plus long gagne (resté à l'origine)",
			Input: `<a href="https://origin.example/l1/autre">k</a>`,
		},
		{
			Name:   "port explicite : réécrit, port perdu",
			Input:  `<a href="https://origin.example:4443/port">p</a>`,
			Expect: `<a href="https://public.test/port">p</a>`,
		},
		{
			Name:  "port + exception chaîne : texte tel quel",
			Input: `<a href="https://origin.example:9/lecture/bonpapa">p</a>`,
		},
		{
			Name:  "autre host : intact",
			Input: `<a href="https://autre.example/x">a</a>`,
		},
		{
			Name:  "host plus long (suffixe) : intact",
			Input: `<a href="https://origin.example.more/interieur">m</a>`,
		},
		{
			Name:  "wss : intact (frontière gauche)",
			Input: `<a href="wss://origin.example/ws">w</a>`,
		},
		{
			Name:  "mot collé avant le scheme : intact",
			Input: `<a href="xhttps://origin.example/x">g</a>`,
		},
		{
			Name:   "srcset double",
			Input:  `<img srcset="https://origin.example/a.jpg 2x, //origin.example/b.jpg 1x">`,
			Expect: `<img srcset="https://public.test/a.jpg 2x, https://public.test/b.jpg 1x">`,
		},
		{
			Name:   "CSS url()",
			Input:  `body{background:url(https://origin.example/fond.css)}`,
			Expect: `body{background:url(https://public.test/fond.css)}`,
		},
		{
			Name:   "texte brut",
			Input:  `<p>voir https://origin.example/txt/fin — suite</p>`,
			Expect: `<p>voir https://public.test/txt/fin — suite</p>`,
		},
		{
			Name:   "URL dans une query",
			Input:  `<a href="https://origin.example/api?u=https://origin.example/other">q</a>`,
			Expect: `<a href="https://public.test/api?u=https://public.test/other">q</a>`,
		},
		{
			Name:   "fragment",
			Input:  `<a href="https://origin.example/doc#ici">f</a>`,
			Expect: `<a href="https://public.test/doc#ici">f</a>`,
		},
		{
			Name:  "host nu sans scheme : intact",
			Input: `<p>voir origin.example/txt</p>`,
		},
	}
}

// rewriteReference : oracle bufferisé INDÉPENDANT du moteur en flux —
// contexte total (jamais de question de fenêtre), sémantique décrite
// dans rewrite.go, implémentation distincte.
func rewriteReference(body []byte, plan *rewritePlan) string {
	var sb bytes.Buffer
	i := 0
	for i < len(body) {
		// première occurrence d'un host d'origine ; à index égal, la
		// plus longue (miroir de findHost)
		h, hl := -1, 0
		for _, o := range plan.origins {
			j := bytes.Index(body[i:], []byte(o))
			if j < 0 {
				continue
			}
			j += i
			if h == -1 || j < h || (j == h && len(o) > hl) {
				h, hl = j, len(o)
			}
		}
		if h == -1 {
			sb.Write(body[i:])
			return sb.String()
		}

		// forme (scheme) entièrement présente dans body[i:h]
		formLen := 0
		switch {
		case h-8 >= i && string(body[h-8:h]) == "https://":
			formLen = 8
		case h-7 >= i && string(body[h-7:h]) == "http://":
			formLen = 7
		case h-2 >= i && string(body[h-2:h]) == "//":
			formLen = 2
		}
		if formLen == 0 {
			sb.Write(body[i : h+1])
			i = h + 1
			continue
		}
		formStart := h - formLen

		invalid := false
		if formLen == 2 {
			if formStart > 0 && !isRelBoundary(body[formStart-1]) {
				invalid = true
			}
		} else if formStart > 0 && isHostChar(body[formStart-1]) {
			invalid = true
		}

		// port optionnel :digits — inclus dans le préfixe réécrit,
		// absent des remplacements
		portEnd := h + hl
		if !invalid && portEnd < len(body) && body[portEnd] == ':' {
			k := portEnd + 1
			for k < len(body) && body[k] >= '0' && body[k] <= '9' {
				k++
			}
			if k == portEnd+1 {
				invalid = true // ':' sans chiffre (":/x")
			} else {
				portEnd = k
			}
		}
		if !invalid && portEnd < len(body) && isHostChar(body[portEnd]) {
			invalid = true // host qui se poursuit (a.b dans a.b.c)
		}
		if invalid {
			sb.Write(body[i : h+1])
			i = h + 1
			continue
		}

		// exceptions : préfixe le plus long gagne (trié en amont)
		keep, repl := false, plan.pub
		end := len(body)
		for j := portEnd; j < len(body); j++ {
			if isPathStop(body[j]) {
				end = j
				break
			}
		}
		for _, e := range plan.except {
			if len(e.Path) <= end-portEnd &&
				bytes.HasPrefix(body[portEnd:end], []byte(e.Path)) {
				if e.To != "" {
					repl = e.To
				} else {
					keep = true
				}
				break
			}
		}

		sb.Write(body[i:formStart])
		if keep {
			sb.Write(body[formStart:portEnd])
		} else {
			sb.WriteString(repl)
		}
		i = portEnd
	}
	return sb.String()
}

func rewriteStreamCase(t *testing.T, plan *rewritePlan, body []byte, chunk int) string {
	t.Helper()
	rs := newRewriteStream(
		io.NopCloser(&sizedReader{src: bytes.NewReader(body), n: chunk}),
		plan,
	)
	got, err := io.ReadAll(rs)
	if err != nil {
		t.Fatalf("flux (bloc %d) : %v", chunk, err)
	}
	return string(got)
}

// Le moteur en flux doit produire EXACTEMENT la sortie de l'oracle,
// quel que soit le découpage de lecture (1 octet = pire cas : la
// fenêtre glissante est sollicitée à chaque octet).
func TestRewriteStreamMatchesReference(t *testing.T) {
	plan := rewriteTestPlan()
	for _, c := range rewriteTextCases() {
		want := c.Expect
		if want == "" {
			want = c.Input
		}
		body := []byte(c.Input)
		if got := rewriteReference(body, plan); got != want {
			t.Errorf("oracle %q :\n got  %q\n want %q", c.Name, got, want)
			continue
		}
		for _, n := range []int{1, 2, 3, 5, 7, 8, 13, 33, 64, 4096} {
			if got := rewriteStreamCase(t, plan, body, n); got != want {
				t.Errorf(
					"flux %q (bloc %d) :\n got  %q\n want %q",
					c.Name, n, got, want,
				)
			}
		}
	}
}

// Assemblages chaotiques de cas : découpes 1 octet sur la page complète
// (toutes les sémantiques traversées dans UN flux, fenêtre toujours
// au bord).
func TestRewriteStreamWholePageChunkOfOne(t *testing.T) {
	plan := rewriteTestPlan()
	var body bytes.Buffer
	for _, c := range rewriteTextCases() {
		body.WriteString(c.Input)
		body.WriteString("\n")
	}
	want := rewriteReference(body.Bytes(), plan)
	if got := rewriteStreamCase(t, plan, body.Bytes(), 1); got != want {
		t.Fatalf("flux bloc 1 :\n got  %q\n want %q", got, want)
	}
}

// Page énorme parsemée d'URLs d'origine : livrée INTÉGRALE et
// réécrite (un octet manquant ou dupliqué casse la longueur exacte —
// comme guardStream, la troncature est structurellement impossible).
func TestRewriteStreamsHugePageWithoutTruncation(t *testing.T) {
	plan := rewriteTestPlan()
	var body bytes.Buffer
	body.WriteString("<html><head><title>huge</title></head><body>")
	for i := 0; i < 20000; i++ {
		fmt.Fprintf(&body,
			`<a href="https://origin.example/p/%d">x</a>`, i)
	}
	body.WriteString("</body></html>")

	want := rewriteReference(body.Bytes(), plan)
	got := rewriteStreamCase(t, plan, body.Bytes(), 4096)
	if got != want {
		t.Fatalf("page %d octets : reçu %d octets (troncature ?)",
			body.Len(), len(got))
	}
	if !strings.Contains(got, "https://public.test/p/19999") {
		t.Error("dernière URL non réécrite")
	}
}

// Erreur transport : propagée (jamais avalée), conformément à
// guardStream.
func TestRewriteStreamPropagatesTransportError(t *testing.T) {
	plan := rewriteTestPlan()
	boom := errors.New("boom transport")
	rs := newRewriteStream(io.NopCloser(&errorReader{boom}), plan)
	_, err := io.ReadAll(rs)
	if err != boom {
		t.Fatalf("err = %v, want %v", err, boom)
	}
}

// Données puis erreur transport AU MILIEU d'une URL : les octets déjà
// reçus partent BRUTS (un corps coupé ne doit pas être semi-réécrit),
// puis l'erreur sort (jamais avalée).
func TestRewriteStreamRawFlushThenError(t *testing.T) {
	plan := rewriteTestPlan()
	boom := errors.New("coupe")
	// URL valide… coupée en pleine host (< hold retenus ne changent
	// rien : l'erreur force l'émission brutale)
	src := io.MultiReader(
		strings.NewReader(`<a href="https://origin.exa`),
		&errorReader{boom},
	)
	rs := newRewriteStream(io.NopCloser(src), plan)
	out, err := io.ReadAll(rs)
	if err != boom {
		t.Fatalf("err = %v, want %v", err, boom)
	}
	if string(out) != `<a href="https://origin.exa` {
		t.Errorf("octets pré-erreur réécrits malgré la coupure : %q", string(out))
	}
}

// E2E via la gateway complète (config JSON réelle, grammaire stricte
// de core.Load) : la page HTML est réécrite (hors exceptions), le
// garde reste injecté, Content-Length/Content-Encoding retirés
// (chunked), et la page gzip est décompressée puis réécrite.
func TestRewriteBodyGatewayE2E(t *testing.T) {
	gw, backend := upstreamGateway(t, `{
		"routes": [{
			"host": "public.test", "path": "/*", "frontend": true,
			"backend": "BACKEND",
			"upstream": {
				"host": true,
				"rewriteBody": {
					"enabled": true,
					"except": [
						"/lecture/bonpapa",
						{"path": "/alt", "to": "https://alt.example"},
						"/l1",
						{"path": "/l1/detail", "to": "https://deep.example"}
					]
				}
			}
		}]
	}`)
	backendHost := backend.Host // host:port imposé au backend

	for _, path := range []string{"/rwpage", "/rwgz"} {
		resp := doGet(t, gw, "public.test", path)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s : status = %d", path, resp.StatusCode)
		}
		b, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		s := string(b)

		if resp.ContentLength != -1 ||
			resp.Header.Get("Content-Length") != "" ||
			resp.Header.Get("Content-Encoding") != "" {
			t.Errorf("%s : CL=%d CE=%q — réécrite = chunked clair",
				path, resp.ContentLength, resp.Header.Get("Content-Encoding"))
		}
		if !strings.Contains(s, "__cladoneAuthGuard") {
			t.Errorf("%s : garde absente", path)
		}

		origin := "https://" + backendHost
		for _, want := range []string{
			`https://public.test/edit/page?x=1`, // réécriture standard
			origin + `/lecture/bonpapa/`,        // exception : origine
			`https://alt.example/alt/chemin`,    // {path,to} : chemin suivi
			`https://deep.example/l1/detail/ou`, // /l1/detail (long)
			origin + `/l1/autre`,                // /l1 (court) : origine
			`https://public.test/img.png`,       // //origine
			`https://public.test/port`,          // port perdu
			`https://autre.example/x`,           // autre host intact
			origin + `.more/interieur`,          // suffixe intact
			`wss://` + backendHost + `/ws`,      // wss intact
			`https://public.test/a.jpg 2x, https://public.test/b.jpg 1x`,
			`url(https://public.test/fond.css)`,
			`https://public.test/txt/fin`,
		} {
			if !strings.Contains(s, want) {
				t.Errorf("%s : absence de %q", path, want)
			}
		}
		for _, not := range []string{
			origin + `/edit`,
			origin + `/alt/chemin`,
			origin + `/l1/detail`,
			backendHost + `/port`,
		} {
			if strings.Contains(s, not) {
				t.Errorf("%s : réécriture manquée %q", path, not)
			}
		}
	}
}

// Un asset JS n'est pas réécrit (le SW client couvre le runtime) ni
// décompressé (décompression HTML uniquement) : le corps zippe passe
// à l'identique, Content-Encoding compris.
func TestRewriteJSAssetUntouched(t *testing.T) {
	// octets gzip EXACTS servis par l'origine
	buf := &bytes.Buffer{}
	zw := gzip.NewWriter(buf)
	_, _ = zw.Write([]byte("console.log('gz');"))
	_ = zw.Close()
	zipped := buf.Bytes()

	gw, _ := upstreamGateway(t, `{
		"routes": [{
			"host": "public.test", "path": "/*", "frontend": true,
			"backend": "BACKEND",
			"upstream": {"host": true, "rewriteBody": {"enabled": true}}
		}]
	}`)

	resp := doGet(t, gw, "public.test", "/app.gz.js")
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(body, zipped) {
		t.Errorf("corps JS modifié : %d octets (want %d identiques)",
			len(body), len(zipped))
	}
	if resp.Header.Get("Content-Encoding") != "gzip" {
		t.Errorf("Content-Encoding = %q, want gzip (passthrough)", resp.Header.Get("Content-Encoding"))
	}
}

// Le SW de réécriture est servi PRE-AUTH (le SW doit s'enregistrer
// avant toute session) avec la policy embarquée et les en-têtes qui
// rendent l'enregistrement possible depuis la racine.
func TestRewriteServiceWorkerServed(t *testing.T) {
	gw, _ := upstreamGateway(t, `{
		"routes": [{
			"host": "public.test", "path": "/*", "frontend": true,
			"backend": "BACKEND",
			"upstream": {"host": true, "rewriteBody": {"enabled": true}}
		}]
	}`)

	resp := doGet(t, gw, "public.test", pwa.SwURL)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (SW servi pré-auth)", resp.StatusCode)
	}
	s := body(t, resp)
	if resp.Header.Get("Content-Type") != "text/javascript; charset=utf-8" {
		t.Errorf("Content-Type = %q", resp.Header.Get("Content-Type"))
	}
	if resp.Header.Get("Cache-Control") != "no-cache" {
		t.Errorf("Cache-Control = %q, want no-cache (le SW re-check)",
			resp.Header.Get("Cache-Control"))
	}
	if resp.Header.Get("Service-Worker-Allowed") != "/" {
		t.Errorf("Service-Worker-Allowed = %q, want /",
			resp.Header.Get("Service-Worker-Allowed"))
	}
	// la policy est embarquée : target + host d'origine NU (le payload
	// traverse son propreSW sans autoréécriture)
	if !strings.Contains(s, `"target":"https://public.test"`) ||
		!strings.Contains(s, `127.0.0.1`) {
		t.Error("policy rewrite absente du SW servi")
	}
}

// rewriteSWRequestCases : cas de parité SW — REQUÊTES (URL absolue
// pure, la matière d'un service worker). Hors périmètre volontaire :
// une URL d'origine IMBRIQUÉE dans la query (le SW réécrit l'URL
// demandée, pas le texte qu'elle porte — c'est la couche serveur qui
// réécrit le HTML) et l'origine nue sans chemin (une requête a
// toujours un chemin).
func rewriteSWRequestCases() []string {
	return []string{
		"https://origin.example/edit/page?x=1",
		"http://origin.example/x",
		"https://origin.example:4443/port",
		"https://origin.example/lecture/bonpapa/ch1",
		"https://origin.example/alt/chemin",
		"https://origin.example/l1/detail/ou",
		"https://origin.example/l1/autre",
		"https://autre.example/x",
		"https://origin.example.more/interieur",
		"https://origin.example/doc",
	}
}

// Parité Go↔JS : le SW généré (harnais node) applique la MÊME
// politique que la référence Go sur les mêmes requêtes absolues.
func TestRewriteParityWithServiceWorkerJS(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node absent : parité SW ignorée")
	}

	plan := rewriteTestPlan()
	cases := rewriteSWRequestCases()

	dir := t.TempDir()
	swPath := filepath.Join(dir, "sw.js")
	casesPath := filepath.Join(dir, "cases.txt")
	outPath := filepath.Join(dir, "results.txt")
	if err := os.WriteFile(swPath,
		[]byte(pwa.New(nil, rewriteTestSpec()).SwJS()), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(casesPath,
		[]byte(strings.Join(cases, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(node, "rewrite_parity_harness.cjs", swPath, casesPath, outPath)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if out, err := cmd.Output(); err != nil {
		t.Fatalf("harnais node : %v\n%s\n%s", err, out, stderr.String())
	}
	raw, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	results := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(results) != len(cases) {
		t.Fatalf("%d résultats pour %d cas :\n%s",
			len(results), len(cases), string(raw))
	}
	for i, u := range cases {
		got := results[i]
		if got == "NO-INTERCEPT" {
			got = u // non intercepté = la requête passe telle quelle
		}
		want := rewriteReference([]byte(u), plan)
		if got != want {
			t.Errorf("SW %q : got %q want %q", u, got, want)
		}
	}
}
