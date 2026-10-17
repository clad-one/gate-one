package proxy

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cladone/gateway/internal/core"
)

// upstreamTestServer : backend d'écho qui simule l'essentiel d'un
// worker Cloudflare protégé par basic auth — expose ce qu'il a reçu
// (Host, Authorization, en-têtes custom), sait rediriger (Location
// absolue/relative via ?loc=) et sert du HTML avec un CSP.
func upstreamTestServer(t *testing.T) *httptest.Server {
	t.Helper()

	mux := http.NewServeMux()

	mux.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"host":            r.Host,
			"authorization":   r.Header.Get("Authorization"),
			"custom":          r.Header.Get("X-Custom"),
			"strip_present":   len(r.Header.Values("X-Strip-Me")) > 0,
			"accept-encoding": r.Header.Get("Accept-Encoding"),
		})
	})

	mux.HandleFunc("/redirect", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, r.URL.Query().Get("loc"), http.StatusFound)
	})

	mux.HandleFunc("/page", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte("<html><head></head><body>x</body></html>"))
	})

	// HTML servi gzip (Content-Encoding: gzip) — simule une origine
	// qui compresse (Cloudflare le fait systématiquement).
	mux.HandleFunc("/gz", func(w http.ResponseWriter, r *http.Request) {
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		_, _ = zw.Write([]byte(
			"<html><head><title>gz</title></head><body>gzip-ok</body></html>"))
		zw.Close()
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(buf.Bytes())
	})

	// « brotli » (octets quelconques) : JAMAIS décodable en stdlib —
	// la réponse doit traverser intacte, sans injection.
	mux.HandleFunc("/br", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "br")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte{0x1b, 0x02, 0x00, 0x00, 0x00})
	})

	// Asset JS servi gzip : non-HTML, jamais touché par la
	// décompression (passthrough compressé jusqu'au navigateur).
	mux.HandleFunc("/app.gz.js", func(w http.ResponseWriter, r *http.Request) {
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		_, _ = zw.Write([]byte("console.log('gz');"))
		zw.Close()
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Type", "application/javascript")
		_, _ = w.Write(buf.Bytes())
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// upstreamGateway : gateway construite depuis un JSON de routes
// (BACKEND remplacé par l'URL du backend d'écho), chargée via la
// grammaire stricte de core.Load — comme en production.
func upstreamGateway(
	t *testing.T,
	routesJSON string,
) (*Gateway, *url.URL) {
	t.Helper()

	srv := upstreamTestServer(t)

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "routes.json")
	routesJSON = strings.ReplaceAll(routesJSON, "BACKEND", srv.URL)
	if err := os.WriteFile(cfgPath, []byte(routesJSON), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := core.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}

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

// doRequestWithHeaders : GET avec en-têtes du client simulé.
func doRequestWithHeaders(
	t *testing.T,
	gw http.Handler,
	host, path string,
	headers map[string]string,
) *http.Response {
	t.Helper()

	req := httptest.NewRequest(http.MethodGet, "http://"+host+path, nil)
	req.Host = host
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)
	return rec.Result()
}

func echoOf(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("echo non-JSON: %s", string(b))
	}
	return out
}

// Défaut historique : sans policy upstream, le Host public du
// navigateur est préservé vers le backend (réseau interne).
func TestUpstreamDefaultPreservesPublicHost(t *testing.T) {
	gw, _ := upstreamGateway(t, `{
		"routes": [{
			"host": "public.test", "path": "/*",
			"backend": "BACKEND"
		}]
	}`)

	resp := doGet(t, gw, "public.test", "/echo")
	if got := echoOf(t, resp)["host"]; got != "public.test" {
		t.Errorf("Host upstream = %v, want public.test", got)
	}
}

// upstream.host: true → le Host envoyé au backend est celui de son
// origine (requis pour un site externe qui route par Host).
func TestUpstreamHostRewrite(t *testing.T) {
	gw, backend := upstreamGateway(t, `{
		"routes": [{
			"host": "public.test", "path": "/*", "frontend": true,
			"backend": "BACKEND",
			"upstream": {"host": true}
		}]
	}`)

	resp := doGet(t, gw, "public.test", "/echo")
	if got := echoOf(t, resp)["host"]; got != backend.Host {
		t.Errorf("Host upstream = %v, want %q", got, backend.Host)
	}
}

// hostOverride : Host explicite différent du backend et du host
// public (précédence sur host).
func TestUpstreamHostOverride(t *testing.T) {
	gw, _ := upstreamGateway(t, `{
		"routes": [{
			"host": "public.test", "path": "/*",
			"backend": "BACKEND",
			"upstream": {"host": true, "hostOverride": "interne.svc:8000"}
		}]
	}`)

	resp := doGet(t, gw, "public.test", "/echo")
	if got := echoOf(t, resp)["host"]; got != "interne.svc:8000" {
		t.Errorf("Host upstream = %v, want interne.svc:8000", got)
	}
}

// En-têtes statiques : posés en Set (écrasent le client — mode
// machine-to-machine), interpolation ${VAR} résolue au load, valeur
// vide = en-tête retiré de la requête.
func TestUpstreamHeaders(t *testing.T) {
	t.Setenv("UPSTREAM_TEST_TOKEN", "c2VjcmV0")

	gw, _ := upstreamGateway(t, `{
		"routes": [{
			"host": "public.test", "path": "/*",
			"backend": "BACKEND",
			"upstream": {"headers": {
			  "Authorization": "Basic ${UPSTREAM_TEST_TOKEN}",
			  "X-Custom": "posé-par-gateway",
			  "X-Strip-Me": ""
			}}
		}]
	}`)

	resp := doRequestWithHeaders(t, gw, "public.test", "/echo", map[string]string{
		"Authorization": "Bearer token-du-client",
		"X-Strip-Me":    "valeur-client",
	})
	echo := echoOf(t, resp)

	if got := echo["authorization"]; got != "Basic c2VjcmV0" {
		t.Errorf("Authorization upstream = %v, want Basic c2VjcmV0 (écrase le client)", got)
	}
	if got := echo["custom"]; got != "posé-par-gateway" {
		t.Errorf("X-Custom upstream = %v", got)
	}
	if got := echo["strip_present"]; got != false {
		t.Errorf("X-Strip-Me transmis malgré valeur vide: %v", got)
	}
}

// Sans upstream.headers, l'Authorization du client traverse telle
// quelle (mode « forward de l'auth du site source »).
func TestUpstreamForwardsClientAuthorization(t *testing.T) {
	gw, _ := upstreamGateway(t, `{
		"routes": [{
			"host": "public.test", "path": "/*",
			"backend": "BACKEND",
			"upstream": {"host": true}
		}]
	}`)

	resp := doRequestWithHeaders(t, gw, "public.test", "/echo", map[string]string{
		"Authorization": "Basic base64-client",
	})
	if got := echoOf(t, resp)["authorization"]; got != "Basic base64-client" {
		t.Errorf("Authorization client non transmise: %v", got)
	}
}

// rewriteRedirects: les Location absolues visant l'ORIGINE du backend
// sont ramenées au host public (schéma https, chemin/query préservés).
func TestUpstreamRewriteRedirects(t *testing.T) {
	gw, backend := upstreamGateway(t, `{
		"routes": [{
			"host": "public.test", "path": "/*", "frontend": true,
			"backend": "BACKEND",
			"upstream": {"host": true, "rewriteRedirects": true}
		}]
	}`)

	absolu := backend.Scheme + "://" + backend.Host + "/Correspondances/?a=1"
	resp := doGet(t, gw, "public.test", "/redirect?loc="+url.QueryEscape(absolu))
	if got := resp.Header.Get("Location"); got != "https://public.test/Correspondances/?a=1" {
		t.Errorf("Location = %q, want https://public.test/Correspondances/?a=1", got)
	}

	// Location relative : traverse telle quelle.
	resp = doGet(t, gw, "public.test", "/redirect?loc="+url.QueryEscape("/relatif"))
	if got := resp.Header.Get("Location"); got != "/relatif" {
		t.Errorf("Location relative altérée: %q", got)
	}

	// Location d'une AUTRE origine (ex. domaine d'équipe Cloudflare
	// Access) : traverse intacte.
	resp = doGet(t, gw, "public.test", "/redirect?loc="+url.QueryEscape("https://equipe.cloudflareaccess.com/x"))
	if got := resp.Header.Get("Location"); got != "https://equipe.cloudflareaccess.com/x" {
		t.Errorf("Location d'une autre origine altérée: %q", got)
	}
}

// Sans rewriteRedirects (défaut) : Location absolue traverse telle
// quelle — comportement historique inchangé.
func TestUpstreamRedirectsUntouchedByDefault(t *testing.T) {
	gw, backend := upstreamGateway(t, `{
		"routes": [{
			"host": "public.test", "path": "/*", "frontend": true,
			"backend": "BACKEND",
			"upstream": {"host": true}
		}]
	}`)

	absolu := backend.Scheme + "://" + backend.Host + "/ailleurs"
	resp := doGet(t, gw, "public.test", "/redirect?loc="+url.QueryEscape(absolu))
	if got := resp.Header.Get("Location"); got != absolu {
		t.Errorf("Location = %q, want %q (non réécrite)", got, absolu)
	}
}

// responseHeaders: remove (CSP d'origine qui bloquerait les balises
// injectées) et set (en-tête ajouté/écrasé).
func TestUpstreamResponseHeaders(t *testing.T) {
	gw, _ := upstreamGateway(t, `{
		"routes": [{
			"host": "public.test", "path": "/*", "frontend": true,
			"backend": "BACKEND",
			"upstream": {"responseHeaders": {
			  "remove": ["Content-Security-Policy"],
			  "set": {"X-Gateway-Note": "instrumented"}
			}}
		}]
	}`)

	resp := doGet(t, gw, "public.test", "/page")
	if got := resp.Header.Get("Content-Security-Policy"); got != "" {
		t.Errorf("CSP non retiré: %q", got)
	}
	if got := resp.Header.Get("X-Gateway-Note"); got != "instrumented" {
		t.Errorf("X-Gateway-Note = %q", got)
	}
}

// Parité « site local » : l'injection du script de garde continue de
// s'appliquer aux HTML proxifiés d'un site externe (chaînage
// upstream → garde).
func TestUpstreamGuardStillInjected(t *testing.T) {
	gw, _ := upstreamGateway(t, `{
		"routes": [{
			"host": "public.test", "path": "/*", "frontend": true,
			"backend": "BACKEND",
			"upstream": {"host": true, "headers": {"Authorization": "Basic abc"}}
		}]
	}`)

	resp := doGet(t, gw, "public.test", "/page")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if b := body(t, resp); !strings.Contains(b, "__cladoneAuthGuard") {
		t.Error("script de garde absent du HTML proxifié")
	}
}

// L'auth gateway (auth: {}) reste orthogonal à l'upstream : sans
// identité, la requête est refusée AVANT d'atteindre le backend
// (route page → 302 login, backend jamais contacté).
func TestUpstreamAuthStillEnforced(t *testing.T) {
	gw, _ := upstreamGateway(t, `{
		"routes": [{
			"host": "public.test", "path": "/*", "frontend": true,
			"backend": "BACKEND",
			"auth": {},
			"upstream": {"host": true}
		}]
	}`)

	// auth-bridge stub injoignable → échec d'auth → la route page
	// (frontend) répond 302 vers le login.
	resp := doGet(t, gw, "public.test", "/echo")
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want 302 (redirection login)", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); !strings.HasPrefix(loc, LoginPageURL) {
		t.Errorf("Location = %q, want préfixe %q", loc, LoginPageURL)
	}
}

// --- Compression (incident 2026-10-17 : Cloudflare répondait brotli
// au navigateur, l'injecteur manipulait le corps compressé → page
// illisible malgré un 200). ---

// Route injectable + origine qui répond gzip : le navigateur reçoit
// du HTML EN CLAIR (décompressé), garde injectée, Content-Encoding
// retiré — quoi qu'offre le navigateur.
func TestInjectableRouteServesPlainHTMLFromGzip(t *testing.T) {
	gw, _ := upstreamGateway(t, `{
		"routes": [{
			"host": "public.test", "path": "/*", "frontend": true,
			"backend": "BACKEND",
			"upstream": {"host": true}
		}]
	}`)

	resp := doRequestWithHeaders(t, gw, "public.test", "/gz", map[string]string{
		"Accept-Encoding": "gzip, deflate, br, zstd",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Encoding"); got != "" {
		t.Errorf("Content-Encoding survit: %q (page illisible)", got)
	}
	b := body(t, resp)
	if !strings.Contains(b, "gzip-ok") {
		t.Errorf("HTML non décompressé: %.80q", b)
	}
	if !strings.Contains(b, "__cladoneAuthGuard") {
		t.Error("garde non injectée sur le HTML gzip décompressé")
	}
}

// Route injectable : l'Accept-Encoding sortant est FORCÉ à gzip
// (décodable en stdlib — brotli/zstd ne le sont pas), quel que soit
// l'offre du navigateur.
func TestInjectableRouteForcesAcceptEncodingGzip(t *testing.T) {
	gw, _ := upstreamGateway(t, `{
		"routes": [{
			"host": "public.test", "path": "/*", "frontend": true,
			"backend": "BACKEND",
			"upstream": {"host": true}
		}]
	}`)

	resp := doRequestWithHeaders(t, gw, "public.test", "/echo", map[string]string{
		"Accept-Encoding": "br, zstd",
	})
	if got := echoOf(t, resp)["accept-encoding"]; got != "gzip" {
		t.Errorf("Accept-Encoding upstream = %v, want gzip", got)
	}
}

// Route NON injectable (API sans garde/PWA) : l'Accept-Encoding du
// client traverse tel quel (passthrough optimal inchangé).
func TestNonInjectedRouteKeepsClientAcceptEncoding(t *testing.T) {
	gw, _ := upstreamGateway(t, `{
		"routes": [{
			"host": "public.test", "path": "/*",
			"backend": "BACKEND"
		}]
	}`)

	resp := doRequestWithHeaders(t, gw, "public.test", "/echo", map[string]string{
		"Accept-Encoding": "br, zstd",
	})
	if got := echoOf(t, resp)["accept-encoding"]; got != "br, zstd" {
		t.Errorf("Accept-Encoding upstream = %v, want br, zstd (intact)", got)
	}
}

// Contenu indécodable (brotli qui aurait franchi le forçage) : la
// réponse passe INTACTE — jamais d'octets compressés manipulés, pas
// de garde injectée dedans.
func TestIndecodableEncodingPassthrough(t *testing.T) {
	gw, _ := upstreamGateway(t, `{
		"routes": [{
			"host": "public.test", "path": "/*", "frontend": true,
			"backend": "BACKEND",
			"upstream": {"host": true}
		}]
	}`)

	resp := doRequestWithHeaders(t, gw, "public.test", "/br", nil)
	if got := resp.Header.Get("Content-Encoding"); got != "br" {
		t.Errorf("Content-Encoding = %q, want br (intact)", got)
	}
	b := body(t, resp)
	if !strings.Contains(b, "__cladoneAuthGuard") {
		t.Logf("corps brotli servi tel quel (garde absente, attendu)")
	}
}

// Asset non-HTML servi gzip : jamais décompressé — passthrough
// compressé jusqu'au navigateur (Content-Encoding préservé).
func TestGzippedAssetPassthrough(t *testing.T) {
	gw, _ := upstreamGateway(t, `{
		"routes": [{
			"host": "public.test", "path": "/*", "frontend": true,
			"backend": "BACKEND",
			"upstream": {"host": true}
		}]
	}`)

	resp := doRequestWithHeaders(t, gw, "public.test", "/app.gz.js", map[string]string{
		"Accept-Encoding": "gzip, br",
	})
	if got := resp.Header.Get("Content-Encoding"); got != "gzip" {
		t.Errorf("Content-Encoding = %q, want gzip (asset intact)", got)
	}

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	zr, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("corps asset n'est plus du gzip valide: %v", err)
	}
	dec, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(dec), "console.log('gz');") {
		t.Errorf("contenu asset corrompu: %.60q", dec)
	}
}
