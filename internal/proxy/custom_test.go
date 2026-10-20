package proxy

// Tests of custom injections (a route's bundle: "inject") —
// inline/file content, named targets (head, body-end), per-page
// targeting, document order, auth protection (PATCH in the guard
// script).

import (
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cladone/gate-one/internal/core"
)

// customGateway: like upstreamGateway, but ALSO writes the injection
// bundle into the config directory (the route references it by its
// relative file name).
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

// E2E: the bundle's entries land in the document — head target
// (ascending Order), body-end (file: content), per-page targeting,
// and the PATCH embedded in the guard script.
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

	// head order: meta-note (30) then late-head (50), then the guard
	iMeta := strings.Index(b, `<meta name="custom" content="1">`)
	iLate := strings.Index(b, `<script>console.log('late');</script>`)
	iGuard := strings.Index(b, "__cladoneAuthGuard")
	if iMeta < 0 || iLate < 0 || iGuard < 0 {
		t.Fatalf("head injections missing: meta=%d late=%d guard=%d",
			iMeta, iLate, iGuard)
	}
	if !(iMeta < iLate && iLate < iGuard) {
		t.Errorf("unexpected head order: meta=%d late=%d guard=%d",
			iMeta, iLate, iGuard)
	}

	// body-end: the file: content is present, before </body>
	iStats := strings.Index(b, "<script>stats();</script>")
	iBodyClose := strings.LastIndex(b, "</body>")
	if iStats < 0 || iBodyClose < 0 || iStats > iBodyClose {
		t.Errorf("body-end misplaced: stats=%d </body>=%d", iStats, iBodyClose)
	}

	// per-page targeting: the /admin entry is not served on /page
	if strings.Contains(b, `<meta name="admin"`) {
		t.Error("/admin entry served on /page (when ignored)")
	}

	// PATCH: embedded in the guard script, ascii-safe
	if !strings.Contains(b,
		`var PATCH = [{"selector":"#action","attrs":{"data-gtw-auth-hidden":"after","data-gtw-logout":""}}];`) {
		t.Error("PATCH missing from the guard script")
	}
}

// The when=/admin targeting SERVES the entry on /admin/... (does the
// test backend's endpoint answer HTML there? no: 404 — so we go
// through a body-end on a real page and a non-matching when, already
// covered above; here we check the positive case via /page when
// when = "/page").
func TestCustomInjectWhenPathPositive(t *testing.T) {
	gw, _ := customGateway(t, customRoutesJSON, `{
		"injects": [
			{"name": "p", "target": "head", "when": "/page", "html": "<meta name=\"p\" content=\"1\">"}
		]
	}`, nil)

	b := readBody(t, doGet(t, gw, "public.test", "/page"))
	if !strings.Contains(b, `<meta name="p" content="1">`) {
		t.Error("when=/page entry not served on /page")
	}
}

// body-end on a HUGE page: streaming insertion, whole page + the
// content (no byte lost — the length safety net).
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
		t.Errorf("length = %d, want %d (page + guard + injection)",
			len(b), want)
	}
	if !strings.HasSuffix(strings.TrimRight(b, "\n"), "</html>") &&
		!strings.Contains(b, "tail();") {
		t.Error("body-end injection missing on the huge page")
	}
	if !strings.Contains(b[:bigPageLen/2], "<script>tail();</script>") {
		// the content must be near the END, not injected at the start
	} else {
		t.Error("body-end injection placed at the top of the document")
	}
}

// Without a bundle: no custom injection, empty PATCH in the guard
// (unchanged historical behavior).
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
		t.Error("PATCH not empty without a bundle")
	}
	if !strings.Contains(b, "var PATCH = [];") {
		t.Error("PATCH expected empty (var PATCH = [])")
	}
}

// The strict grammar rejects faulty bundles.
func TestCustomInjectValidation(t *testing.T) {
	cases := []struct {
		name   string
		bundle string
		want   string
	}{
		{
			name:   "unknown target",
			bundle: `{"injects":[{"name":"x","target":"middle","html":"<b>"}]}`,
			want:   `target "middle"`,
		},
		{
			name:   "without name",
			bundle: `{"injects":[{"html":"<b>"}]}`,
			want:   "name empty",
		},
		{
			name: "duplicate name",
			bundle: `{"injects":[
				{"name":"x","html":"<b>"},
				{"name":"x","html":"<i>"}]}`,
			want: `duplicate name "x"`,
		},
		{
			name:   "order out of bounds",
			bundle: `{"injects":[{"name":"x","order":5,"html":"<b>"}]}`,
			want:   "order 5",
		},
		{
			name:   "without content",
			bundle: `{"injects":[{"name":"x"}]}`,
			want:   "without content",
		},
		{
			name:   "unknown field",
			bundle: `{"injects":[{"name":"x","html":"<b>","extra":1}]}`,
			want:   "unknown field",
		},
		{
			name:   "patch without selector",
			bundle: `{"patch":[{"attrs":{"a":"b"}}]}`,
			want:   "selector empty",
		},
		{
			name:   "patch without attrs",
			bundle: `{"patch":[{"selector":"#x"}]}`,
			want:   "without attrs",
		},
		{
			name:   "file escaping upward (..)",
			bundle: `{"injects":[{"name":"x","file":"../etc/passwd"}]}`,
			want:   "path relative to the bundle required",
		},
		{
			name:   "missing file",
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
				t.Errorf("bundle accepted: %s", tc.want)
			} else if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %v, want containing %q", err, tc.want)
			}
		})
	}
}

// file: content is resolved relative to the BUNDLE (and re-read on
// HUP reload, like the config).
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
		t.Error("file: content not injected")
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
