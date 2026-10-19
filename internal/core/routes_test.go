package core

import (
	"os"
	"path/filepath"
	"testing"
)

// La config réelle utilise "autoHead" : le tag Go doit le lire. Régression
// pour le bug où le tag était "headFallback" et le flag était ignoré (HEAD
// partait natif au backend).
func TestAutoHeadDeserialization(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "routes.json")
	cfg := `{
		"routes": [
			{"host": "a.local", "path": "/*", "backend": "http://x", "autoHead": true},
			{"host": "b.local", "path": "/*", "backend": "http://x"}
		]
	}`
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !c.Routes[0].AutoHead {
		t.Error(`"autoHead": true not deserialized into Route.AutoHead`)
	}
	if c.Routes[1].AutoHead {
		t.Error("absent autoHead should default to false")
	}
}

// Le scope MCP exigé doit venir du champ "mcp.scope" de la config
// (valeur aussi déclarée dans le realm Keycloak : le client scope
// optionnel du même nom).
func TestMCPScopeDeserialization(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "routes.json")
	cfg := `{
		"oidc": {"issuer": "https://auth.plateforme.test/realms/test"},
		"routes": [
			{"host": "a.local", "path": "/mcp", "backend": "http://x",
			 "mcp": {"enabled": true, "scope": "custom-scope"}},
			{"host": "b.local", "path": "/*", "backend": "http://x",
			 "mcp": {"enabled": true}}
		]
	}`
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := c.OIDC.Issuer; got != "https://auth.plateforme.test/realms/test" {
		t.Errorf(`"oidc.issuer" désérialisé en %q`, got)
	}
	if got := c.Routes[0].MCP.Scope; got != "custom-scope" {
		t.Errorf(`"mcp": {"scope": "custom-scope"} deserialized as %q`, got)
	}
	if got := c.Routes[1].MCP.Scope; got != "" {
		t.Errorf("absent mcp.scope should default to empty, got %q", got)
	}
}

// La grammaire est STRICTE : tout champ inconnu (faute de frappe dans
// un nom de policy, champ prévu mais non implémenté) doit casser le
// load — jamais de policy ignorée en silence (régression du type
// autoHead/"headFallback"). NB : le décodage Go est insensible à la
// casse sur les tags ("autohead" matche "autoHead") — la stricte ne
// rejette que les noms réellement inconnus.
func TestLoadRejectsUnknownFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "routes.json")
	cfg := `{
		"routes": [
			{"host": "a.local", "path": "/*", "backend": "http://x",
			 "headFallback": true}
		]
	}`
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Error("headFallback (nom inconnu) doit être rejeté, load accepté")
	}
}

func TestLoadAllowsSchemaKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "routes.json")
	cfg := `{
		"$schema": "./api-routes.schema.json",
		"routes": [
			{"host": "a.local", "path": "/*", "backend": "http://x"}
		]
	}`
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatalf("$schema doit être accepté: %v", err)
	}
	if len(c.Routes) != 1 {
		t.Errorf("routes = %d, want 1", len(c.Routes))
	}
}

// La policy upstream (site externe proxifié — ex. Cloudflare) doit se
// désérialiser complètement depuis api-routes.json.
func TestUpstreamDeserialization(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "routes.json")
	cfg := `{
		"routes": [
			{"host": "a.local", "path": "/*", "backend": "https://ext.example",
			 "upstream": {
			   "host": true,
			   "hostOverride": "origin.example",
			   "headers": {"Authorization": "Basic abc", "X-Strip": ""},
			   "rewriteRedirects": true,
			   "responseHeaders": {
			     "set": {"X-Note": "instrumented"},
			     "remove": ["Content-Security-Policy"]
			   }
			 }}
		]
	}`
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}

	up := c.Routes[0].Upstream
	if up == nil {
		t.Fatal("upstream policy absent")
	}
	if up.Host == nil || !*up.Host {
		t.Error(`"host": true not deserialized`)
	}
	if up.HostOverride != "origin.example" {
		t.Errorf("hostOverride = %q", up.HostOverride)
	}
	if up.Headers["Authorization"] != "Basic abc" {
		t.Errorf("headers.Authorization = %q", up.Headers["Authorization"])
	}
	if v, ok := up.Headers["X-Strip"]; !ok || v != "" {
		t.Errorf("headers.X-Strip = %q (present=%v), want empty present", v, ok)
	}
	if up.RewriteRedirects == nil || !*up.RewriteRedirects {
		t.Error(`"rewriteRedirects": true not deserialized`)
	}
	if up.ResponseHeaders == nil ||
		up.ResponseHeaders.Set["X-Note"] != "instrumented" ||
		len(up.ResponseHeaders.Remove) != 1 ||
		up.ResponseHeaders.Remove[0] != "Content-Security-Policy" {
		t.Errorf("responseHeaders = %+v", up.ResponseHeaders)
	}
}

// Une route sans policy upstream ne doit pas en créer une vide.
func TestUpstreamAbsent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "routes.json")
	cfg := `{"routes": [
		{"host": "a.local", "path": "/*", "backend": "http://x"}
	]}`
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.Routes[0].Upstream != nil {
		t.Error("absent upstream should stay nil")
	}
}

// Les valeurs d'en-têtes upstream supportent l'interpolation ${VAR}
// depuis l'environnement du conteneur (les secrets vivent dans .env,
// jamais committés dans la config).
func TestUpstreamEnvExpansion(t *testing.T) {
	t.Setenv("UPSTREAM_TEST_TOKEN", "c2VjcmV0")

	dir := t.TempDir()
	path := filepath.Join(dir, "routes.json")
	cfg := `{"routes": [
		{"host": "a.local", "path": "/*", "backend": "https://ext.example",
		 "upstream": {"headers": {
		   "Authorization": "Basic ${UPSTREAM_TEST_TOKEN}",
		   "X-Plain": "sans-variable"
		 }}}
	]}`
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	h := c.Routes[0].Upstream.Headers
	if h["Authorization"] != "Basic c2VjcmV0" {
		t.Errorf("interpolation = %q, want %q", h["Authorization"], "Basic c2VjcmV0")
	}
	if h["X-Plain"] != "sans-variable" {
		t.Errorf("valeur sans variable altérée: %q", h["X-Plain"])
	}
}

// Variable d'environnement absente = refus de démarrer (jamais
// d'identifiant vide silencieux envoyé au backend).
func TestUpstreamEnvMissingVarFails(t *testing.T) {
	const name = "UPSTREAM_TEST_MISSING_VAR"
	old, had := os.LookupEnv(name)
	t.Cleanup(func() {
		if had {
			os.Setenv(name, old)
		} else {
			os.Unsetenv(name)
		}
	})
	os.Unsetenv(name)

	dir := t.TempDir()
	path := filepath.Join(dir, "routes.json")
	cfg := `{"routes": [
		{"host": "a.local", "path": "/*", "backend": "https://ext.example",
		 "upstream": {"headers": {"Authorization": "Basic ${UPSTREAM_TEST_MISSING_VAR}"}}}
	]}`
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Error("variable absente doit faire échouer le load")
	}
}

// Variable d'environnement présente mais VIDE (typiquement absente
// du .env serveur, injectée en "" par compose « ${VAR:-} ») : NON
// fatal — la valeur est vidée (l'en-tête sera retiré, l'upstream
// répondra 401) et un warning est journalisé. Incident 2026-10-17 :
// un deploy sans la variable faisait partir un parasite « Basic »
// tronqué au lieu d'un signal clair.
func TestUpstreamEnvEmptyVarDropsHeader(t *testing.T) {
	t.Setenv("UPSTREAM_TEST_EMPTY", "")

	dir := t.TempDir()
	path := filepath.Join(dir, "routes.json")
	cfg := `{"routes": [
		{"host": "a.local", "path": "/*", "backend": "https://ext.example",
		 "upstream": {"headers": {"Authorization": "Basic ${UPSTREAM_TEST_EMPTY}"}}}
	]}`
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	c, err := Load(path)
	if err != nil {
		t.Fatalf("variable vide ne doit pas être fatale: %v", err)
	}
	if got := c.Routes[0].Upstream.Headers["Authorization"]; got != "" {
		t.Errorf("valeur = %q, want vide (en-tête retiré par le proxy)", got)
	}
}

// Faute de frappe dans un sous-champ d'upstream = rejet (grammaire
// stricte, cf. TestLoadRejectsUnknownFields).
func TestUpstreamRejectsUnknownFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "routes.json")
	cfg := `{"routes": [
		{"host": "a.local", "path": "/*", "backend": "https://ext.example",
		 "upstream": {"headerz": {}}}
	]}`
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Error("upstream.headerz (nom inconnu) doit être rejeté")
	}
}

// Le badge userBadge.loginBadge : le champ se désérialise (défaut
// false — le badge n'apparaît en anonyme qu'après une mort de
// session détectée).
func TestUserBadgeLoginBadgeDeserialization(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "routes.json")
	cfg := `{
		"routes": [
			{"host": "a.local", "path": "/*", "backend": "http://x",
			 "userBadge": {"loginBadge": true, "claims": ["preferred_username"]}},
			{"host": "b.local", "path": "/*", "backend": "http://x",
			 "userBadge": {"claims": ["preferred_username"]}}
		]
	}`
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !c.Routes[0].UserBadge.LoginBadge {
		t.Error(`"loginBadge": true not deserialized`)
	}
	if c.Routes[1].UserBadge.LoginBadge {
		t.Error("absent loginBadge should default to false")
	}
}

// La config RÉELLE de production doit passer la grammaire stricte.
// Les secrets y sont référencés par interpolation ${VAR} (résolus
// depuis l'environnement du conteneur en production) : le test
// pré-positionne chaque variable référencée à une valeur factice —
// une variable réellement absente doit faire échouer le load (cf.
// TestUpstreamEnvMissingVarFails), pas ce test.
func TestLoadRealConfigStrict(t *testing.T) {

	data, err := os.ReadFile("../../api-routes.json")
	if err != nil {
		t.Fatal(err)
	}

	for _, m := range envVarPattern.FindAllStringSubmatch(string(data), -1) {
		t.Setenv(m[1], "test-"+m[1])
	}

	c, err := Load("../../api-routes.json")
	if err != nil {
		t.Fatalf("api-routes.json réel invalide: %v", err)
	}
	if len(c.Routes) == 0 {
		t.Error("aucune route chargée")
	}
}
