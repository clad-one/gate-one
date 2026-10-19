package proxy

// Tests des injections custom (bundle d'une route : "inject") —
// contenu inline/file, cibles nommées (head, body-end), ciblage par
// page, ordre dans le document, protection de l'auth (PATCH dans le
// script de garde).

import (
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cladone/gateway/internal/core"
)

// customGateway : comme upstreamGateway, mais écrit AUSSI le bundle
// d'injection dans le répertoire de config (la route le référence par
// son nom de fichier relatif).
func customGateway(
	t *testing.T,
	routesJSON, bundleJSON string,
	bundleFiles map[string]string,
) (*Gateway, *url.URL) {
	t.Helper()

	srv := upstreamTestServer(t)

	dir := t.TempDir()
	for name, content := range bundleFiles {
		full := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if bundleJSON != "" {
		if err := os.WriteFile(
			filepath.Join(dir, "bundle.json"), []byte(bundleJSON), 0o600,
		); err != nil {
			t.Fatal(err)
		}
	}

	routesJSON = strings.ReplaceAll(routesJSON, "BACKEND", srv.URL)
	cfg := loadForTestIn(t, dir, routesJSON)

	gw, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	return gw, u
}

const customRoutesJSON = `{
	"routes": [{
		"host": "public.test", "path": "/*", "frontend": true,
		"backend": "BACKEND",
		"upstream": {"host": true},
		"inject": "bundle.json"
	}]
}`

// E2E : les entrées du bundle arrivent dans le document — cible head
// (ordre Order croissant), body-end (contenu du file:), ciblage par
// page, et la PATCH embarquée dans le script de garde.
func TestCustomInjectE2E(t *testing.T) {
	gw, _ := customGateway(t, customRoutesJSON, `{
		"injects": [
			{
				"name": "meta-note",
				"target": "head",
				"order": 30,
				"html": "<meta name=\"custom\" content=\"1\">"
			},
			{
				"name": "stats-tail",
				"target": "body-end",
				"order": 40,
				"file": "./stats.html"
			},
			{
				"name": "late-head",
				"target": "head",
				"order": 50,
				"script": "console.log('late');"
			},
			{
				"name": "admin-only",
				"target": "head",
				"order": 60,
				"when": "/admin",
				"html": "<meta name=\"admin\" content=\"1\">"
			}
		],
		"patch": [
			{
				"selector": "#action",
				"attrs": {
					"data-gtw-logout": "",
					"data-gtw-auth-hidden": "after"
				}
			}
		]
	}`, map[string]string{
		"stats.html": "<script>stats();</script>",
	})

	resp := doGet(t, gw, "public.test", "/page")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	b := readBody(t, resp)

	// ordre head : meta-note (30) puis late-head (50), puis la garde
	iMeta := strings.Index(b, `<meta name="custom" content="1">`)
	iLate := strings.Index(b, `<script>console.log('late');</script>`)
	iGuard := strings.Index(b, "__cladoneAuthGuard")
	if iMeta < 0 || iLate < 0 || iGuard < 0 {
		t.Fatalf("injections head absentes : meta=%d late=%d guard=%d",
			iMeta, iLate, iGuard)
	}
	if !(iMeta < iLate && iLate < iGuard) {
		t.Errorf("ordre du head inattendu : meta=%d late=%d guard=%d",
			iMeta, iLate, iGuard)
	}

	// body-end : le contenu du file: est présent, avant </body>
	iStats := strings.Index(b, "<script>stats();</script>")
	iBodyClose := strings.LastIndex(b, "</body>")
	if iStats < 0 || iBodyClose < 0 || iStats > iBodyClose {
		t.Errorf("body-end mal placé : stats=%d </body>=%d", iStats, iBodyClose)
	}

	// ciblage par page : l'entrée /admin n'est pas sur /page
	if strings.Contains(b, `<meta name="admin"`) {
		t.Error("entrée /admin servie sur /page (when ignoré)")
	}

	// PATCH : embarquée dans le script de garde, ascii-safe
	if !strings.Contains(b,
		`var PATCH = [{"selector":"#action","attrs":{"data-gtw-auth-hidden":"after","data-gtw-logout":""}}];`) {
		t.Error("PATCH absente du script de garde")
	}
}

// Le ciblage when=/admin SERT l'entrée sur /admin/... (le endpoint du
// backend de test y répond en HTML ? non : 404 — on passe donc par un
// body-end sur une page réelle et un when qui ne matche pas, déjà
// couvert ci-dessus ; ici on vérifie le cas positif via /page quand
// when = "/page").
func TestCustomInjectWhenPathPositive(t *testing.T) {
	gw, _ := customGateway(t, customRoutesJSON, `{
		"injects": [
			{"name": "p", "target": "head", "when": "/page", "html": "<meta name=\"p\" content=\"1\">"}
		]
	}`, nil)

	b := readBody(t, doGet(t, gw, "public.test", "/page"))
	if !strings.Contains(b, `<meta name="p" content="1">`) {
		t.Error("entrée when=/page non servie sur /page")
	}
}

// body-end sur une page ÉNORME : insertion en flux, page entière + le
// contenu (aucun octet perdu — le filet de longueur).
func TestCustomInjectBodyEndHuge(t *testing.T) {
	gw, _ := customGateway(t, customRoutesJSON, `{
		"injects": [
			{"name": "tail", "target": "body-end", "order": 30,
			 "html": "<script>tail();</script>"}
		]
	}`, nil)

	resp := doGet(t, gw, "public.test", "/big")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	b := readBody(t, resp)
	want := bigPageLen + guardInjectedLen(t) +
		len("<script>tail();</script>")
	if len(b) != want {
		t.Errorf("longueur = %d, want %d (page + garde + injection)",
			len(b), want)
	}
	if !strings.HasSuffix(strings.TrimRight(b, "\n"), "</html>") &&
		!strings.Contains(b, "tail();") {
		t.Error("injection body-end absente sur la page énorme")
	}
	if !strings.Contains(b[:bigPageLen/2], "<script>tail();</script>") {
		// le contenu doit être près de la FIN, pas injecté au début
	} else {
		t.Error("injection body-end placée en tête de document")
	}
}

// Sans bundle : aucune injection custom, PATCH vide dans le garde
// (comportement historique inchangé).
func TestCustomInjectAbsentByDefault(t *testing.T) {
	gw, _ := customGateway(t, `{
		"routes": [{
			"host": "public.test", "path": "/*", "frontend": true,
			"backend": "BACKEND",
			"upstream": {"host": true}
		}]
	}`, "", nil)

	b := readBody(t, doGet(t, gw, "public.test", "/page"))
	if strings.Contains(b, "var PATCH = [{") {
		t.Error("PATCH non vide sans bundle")
	}
	if !strings.Contains(b, "var PATCH = [];") {
		t.Error("PATCH attendue vide (var PATCH = [])")
	}
}

// La grammaire stricte refuse les bundles fautifs.
func TestCustomInjectValidation(t *testing.T) {
	cases := []struct {
		name   string
		bundle string
		want   string
	}{
		{
			name:   "cible inconnue",
			bundle: `{"injects":[{"name":"x","target":"middle","html":"<b>"}]}`,
			want:   `target "middle"`,
		},
		{
			name:   "sans nom",
			bundle: `{"injects":[{"html":"<b>"}]}`,
			want:   "name vide",
		},
		{
			name: "nom dupliqué",
			bundle: `{"injects":[
				{"name":"x","html":"<b>"},
				{"name":"x","html":"<i>"}]}`,
			want: `nom dupliqué "x"`,
		},
		{
			name:   "order hors bornes",
			bundle: `{"injects":[{"name":"x","order":5,"html":"<b>"}]}`,
			want:   "order 5",
		},
		{
			name:   "sans contenu",
			bundle: `{"injects":[{"name":"x"}]}`,
			want:   "sans contenu",
		},
		{
			name:   "field inconnu",
			bundle: `{"injects":[{"name":"x","html":"<b>","extra":1}]}`,
			want:   "unknown field",
		},
		{
			name:   "patch sans selector",
			bundle: `{"patch":[{"attrs":{"a":"b"}}]}`,
			want:   "selector vide",
		},
		{
			name:   "patch sans attrs",
			bundle: `{"patch":[{"selector":"#x"}]}`,
			want:   "sans attrs",
		},
		{
			name:   "file qui remonte (..)",
			bundle: `{"injects":[{"name":"x","file":"../etc/passwd"}]}`,
			want:   "chemin relatif au bundle requis",
		},
		{
			name:   "file absent",
			bundle: `{"injects":[{"name":"x","file":"./n existepas.html"}]}`,
			want:   "no such file",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			cfgPath := filepath.Join(dir, "routes.json")
			cfg := `{"routes":[{"host":"public.test","path":"/*","frontend":true,
				"backend":"http://127.0.0.1:1","inject":"bundle.json"}]}`
			if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(
				filepath.Join(dir, "bundle.json"), []byte(tc.bundle), 0o600,
			); err != nil {
				t.Fatal(err)
			}
			if _, err := core.Load(cfgPath); err == nil {
				t.Errorf("bundle accepté : %s", tc.want)
			} else if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("erreur = %v, want contenant %q", err, tc.want)
			}
		})
	}
}

// file: le contenu est résolu relativement au BUNDLE (et relu au
// reload HUP, comme la config).
func TestCustomInjectFileResolved(t *testing.T) {
	gw, _ := customGateway(t, customRoutesJSON, `{
		"injects": [
			{"name": "from-file", "target": "head", "file": "./parts/head.html"}
		]
	}`, map[string]string{
		"parts/head.html": "<meta name=\"from-file\" content=\"1\">",
	})

	b := readBody(t, doGet(t, gw, "public.test", "/page"))
	if !strings.Contains(b, `<meta name="from-file" content="1">`) {
		t.Error("contenu du file: non injecté")
	}
}

func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
