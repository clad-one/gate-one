package core

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The real config uses "autoHead": the Go tag must read it. Regression
// for the bug where the tag was "headFallback" and the flag was ignored
// (HEAD went raw to the backend).
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

// The required MCP scope must come from the config's "mcp.scope" field
// (value also declared in the Keycloak realm: the optional client
// scope of the same name).
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
		t.Errorf(`"oidc.issuer" deserialized as %q`, got)
	}
	if got := c.Routes[0].MCP.Scope; got != "custom-scope" {
		t.Errorf(`"mcp": {"scope": "custom-scope"} deserialized as %q`, got)
	}
	if got := c.Routes[1].MCP.Scope; got != "" {
		t.Errorf("absent mcp.scope should default to empty, got %q", got)
	}
}

// The grammar is STRICT: any unknown field (typo in a policy
// name, planned but unimplemented field) must break the
// load — never a silently ignored policy (regression of the
// autoHead/"headFallback" kind). NB: Go decoding is case-insensitive
// on tags ("autohead" matches "autoHead") — the strictness only
// rejects actually unknown names.
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
		t.Error("headFallback (unknown name) must be rejected, load accepted")
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
		t.Fatalf("$schema must be accepted: %v", err)
	}
	if len(c.Routes) != 1 {
		t.Errorf("routes = %d, want 1", len(c.Routes))
	}
}

func TestStripPrefixValidation(t *testing.T) {
	valid := `{
		"routes": [
			{"host": "a.local", "path": "/api/*", "backend": "http://x",
			 "stripPrefix": "/api/"}
		]
	}`
	dir := t.TempDir()
	path := filepath.Join(dir, "routes.json")
	if err := os.WriteFile(path, []byte(valid), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatalf("valid stripPrefix rejected: %v", err)
	}
	if got := c.Routes[0].StripPrefix; got != "/api" {
		t.Errorf("stripPrefix normalized to %q, want /api", got)
	}

	bad := []struct {
		name string
		path string
		pre  string
	}{
		{"no leading slash", "/api/*", "api"},
		{"root", "/*", "/"},
		{"query", "/api/*", "/api?x=1"},
		{"fragment", "/api/*", "/api#x"},
		{"wildcard", "/api/*", "/api/*"},
		{"empty segment", "/api/*", "/api//v1"},
		{"dot segment", "/api/*", "/api/../v1"},
		{"control character", "/api/*", "/api\nx"},
		{"outside route path", "/api/*", "/other"},
		{"segment boundary", "/apix", "/api"},
		{"too long", "/*", "/" + strings.Repeat("a", maxStripPrefixLen)},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			cfg := fmt.Sprintf(`{"routes":[{"host":"a.local","path":%q,"backend":"http://x","stripPrefix":%q}]}`,
				tc.path, tc.pre)
			if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(path); err == nil {
				t.Fatalf("stripPrefix %q with path %q accepted", tc.pre, tc.path)
			} else if !strings.Contains(err.Error(), "stripPrefix") {
				t.Errorf("error lacks stripPrefix context: %v", err)
			}
		})
	}
}

func TestInjectBundleAllowsSchemaKey(t *testing.T) {
	dir := t.TempDir()
	bundle := `{
		"$schema": "./inject-bundle.schema.json",
		"patch": [
			{"selector": "#action", "attrs": {"data-gtw-auth": ""}}
		]
	}`
	if err := os.WriteFile(
		filepath.Join(dir, "bundle.json"), []byte(bundle), 0o600,
	); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "routes.json")
	cfg := `{
		"routes": [
			{"host": "a.local", "path": "/*", "backend": "http://x",
			 "inject": "bundle.json"}
		]
	}`
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatalf("bundle $schema must be accepted: %v", err)
	}
	b := c.Routes[0].InjectionBundle()
	if b == nil || len(b.Patch) != 1 {
		t.Fatalf("bundle patch not loaded: %#v", b)
	}
}

// The upstream policy (proxified external site — e.g. Cloudflare) must
// fully deserialize from api-routes.json.
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
			   },
			   "browserCache": {"imagesMaxAgeSeconds": 604800}
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
	if up.BrowserCache == nil || up.BrowserCache.ImagesMaxAgeSeconds != 604800 {
		t.Errorf("browserCache = %+v", up.BrowserCache)
	}
}

// browserCache validation: a declared value must be a positive
// integer (in seconds) — declared-and-zero = configuration error,
// not a silent deactivation.
func TestBrowserCacheValidationForcesPositive(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "routes.json")
	for _, ma := range []int{0, -42} {
		cfg := fmt.Sprintf(`{
			"routes": [{
				"host": "a.local", "path": "/*", "backend": "https://ext.example",
				"upstream": {"browserCache": {"imagesMaxAgeSeconds": %d}}
			}]
		}`, ma)
		if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err == nil {
			t.Errorf("imagesMaxAgeSeconds = %d: acceptance expected to be refused", ma)
		}
	}
}

// A route without an upstream policy must not get an empty one created.
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

// Upstream header values support ${VAR} interpolation
// from the container environment (secrets live in .env,
// never committed to the config).
func TestUpstreamEnvExpansion(t *testing.T) {
	t.Setenv("UPSTREAM_TEST_TOKEN", "c2VjcmV0")

	dir := t.TempDir()
	path := filepath.Join(dir, "routes.json")
	cfg := `{"routes": [
		{"host": "a.local", "path": "/*", "backend": "https://ext.example",
		 "upstream": {"headers": {
		   "Authorization": "Basic ${UPSTREAM_TEST_TOKEN}",
		   "X-Plain": "no-variable"
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
	if h["X-Plain"] != "no-variable" {
		t.Errorf("variable-free value altered: %q", h["X-Plain"])
	}
}

// Missing environment variable = startup refused (never
// a silent empty credential sent to the backend).
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
		t.Error("missing variable must fail the load")
	}
}

// Environment variable present but EMPTY (typically missing
// from the server's .env, injected as "" by compose "${VAR:-}"): NOT
// fatal — the value is emptied (the header will be removed, the
// upstream will answer 401) and a warning is logged. Incident
// 2026-10-17: a deploy without the variable sent a truncated stray
// "Basic" instead of a clear signal.
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
		t.Fatalf("empty variable must not be fatal: %v", err)
	}
	if got := c.Routes[0].Upstream.Headers["Authorization"]; got != "" {
		t.Errorf("value = %q, want empty (header removed by the proxy)", got)
	}
}

// Typo in an upstream sub-field = rejection (strict
// grammar, see TestLoadRejectsUnknownFields).
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
		t.Error("upstream.headerz (unknown name) must be rejected")
	}
}

// The userBadge.loginBadge badge: the field deserializes (default
// false — when anonymous the badge only appears after a detected
// session death).
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

// The userBadge.roles / .scopes switches: bool AND list forms
// deserialize; absent = false (the expanded badge stays claims-only
// unless asked).
func TestUserBadgeRolesScopesDeserialization(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "routes.json")
	cfg := `{
		"routes": [
			{"host": "a.local", "path": "/*", "backend": "http://x",
			 "userBadge": {"claims": ["preferred_username"],
			               "roles": true, "scopes": true}},
			{"host": "b.local", "path": "/*", "backend": "http://x",
			 "userBadge": {"claims": ["preferred_username"]}},
			{"host": "c.local", "path": "/*", "backend": "http://x",
			 "userBadge": {"claims": true,
			               "roles": ["admin", "auditor"]}}
		]
	}`
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	ub := c.Routes[0].UserBadge
	if !ub.Roles.All || !ub.Scopes.All {
		t.Error(`"roles"/"scopes": true not deserialized (All)`)
	}
	if len(ub.Roles.Items) != 0 || len(ub.Scopes.Items) != 0 {
		t.Error("bool form must not carry items")
	}
	ub = c.Routes[1].UserBadge
	if ub.Roles.All || ub.Scopes.All ||
		len(ub.Roles.Items) != 0 || len(ub.Scopes.Items) != 0 {
		t.Error("absent roles/scopes should default to false")
	}
	ub = c.Routes[2].UserBadge
	if !ub.Claims.All {
		t.Error(`"claims": true not deserialized (All)`)
	}
	if ub.Roles.All || len(ub.Roles.Items) != 2 ||
		ub.Roles.Items[0] != "admin" || ub.Roles.Items[1] != "auditor" {
		t.Error("list form not deserialized (items, no All)")
	}
}

// The reference production config (testdata/api-routes.json, a copy
// of the live cladone-it-infra config) must pass the strict grammar.
// Secrets are referenced there by ${VAR} interpolation (resolved
// from the container environment in production): the test
// pre-sets each referenced variable to a dummy value —
// a genuinely missing variable must fail the load (see
// TestUpstreamEnvMissingVarFails), not this test.
func TestLoadRealConfigStrict(t *testing.T) {

	data, err := os.ReadFile("../../testdata/api-routes.json")
	if err != nil {
		t.Fatal(err)
	}

	for _, m := range envVarPattern.FindAllStringSubmatch(string(data), -1) {
		t.Setenv(m[1], "test-"+m[1])
	}

	// tokenBroker.secretEnv names the variable holding the broker
	// shared secret — a name, not a ${VAR} interpolation, so the loop
	// above misses it. Pre-set it too: a genuinely missing secret must
	// fail the load (resolveTokenBroker), not this test.
	var probe struct {
		TokenBroker *struct {
			SecretEnv string `json:"secretEnv"`
		} `json:"tokenBroker"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		t.Fatal(err)
	}
	if probe.TokenBroker != nil {
		name := probe.TokenBroker.SecretEnv
		if name == "" {
			name = "TOKEN_BROKER_SHARED_SECRET"
		}
		t.Setenv(name, "test-"+name)
	}

	c, err := Load("../../testdata/api-routes.json")
	if err != nil {
		t.Fatalf("real api-routes.json invalid: %v", err)
	}
	if len(c.Routes) == 0 {
		t.Error("no routes loaded")
	}
}

// Wildcard {name}: the route expands AT LOAD into one concrete route
// per allow-listed label — cross product in stable order, all the
// policies carried over, the expansion never visible to the request
// path.
func TestWildcardExpansion(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "routes.json")
	cfg := `{
		"oidc": {"loginUrl": "http://login.test/login"},
		"routes": [
			{"host": "{lang}.wikipedia.demo.localhost", "path": "/*",
			 "backend": "https://{lang}.wikipedia.org",
			 "wildcard": {"lang": ["fr", "en", "de"]},
			 "frontend": true,
			 "auth": {}}
		]
	}`
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Routes) != 3 {
		t.Fatalf("routes = %d, want 3 (one per allow-listed label)", len(c.Routes))
	}
	// stable order: sorted allow-list — de, en, fr
	want := []struct{ host, backend string }{
		{"de.wikipedia.demo.localhost", "https://de.wikipedia.org"},
		{"en.wikipedia.demo.localhost", "https://en.wikipedia.org"},
		{"fr.wikipedia.demo.localhost", "https://fr.wikipedia.org"},
	}
	for i, w := range want {
		r := &c.Routes[i]
		if r.Host != w.host || r.Backend != w.backend {
			t.Errorf("route %d = %s → %s, want %s → %s",
				i, r.Host, r.Backend, w.host, w.backend)
		}
		if r.Wildcard != nil {
			t.Error("expanded route must not carry the wildcard policy")
		}
		if !r.Frontend || r.Auth == nil {
			t.Error("policies must be carried over to the expansion")
		}
		if r.WildcardSource() != "{lang}.wikipedia.demo.localhost" {
			t.Errorf("WildcardSource = %q, want the pattern", r.WildcardSource())
		}
	}
}

// RewriteTargets: a wildcard expansion also compiles the
// cross-route mapping used by rewriteBody (backend origin → public
// host of the OTHER variants). This is what replaces a duplicated
// per-language host block in the plugin.
func TestWildcardRewriteTargets(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "routes.json")
	cfg := `{
		"oidc": {"loginUrl": "http://login.test/login"},
		"routes": [{
			"host": "{lang}.wikipedia.demo.localhost", "path": "/*",
			"backend": "https://{lang}.wikipedia.org",
			"wildcard": {"lang": ["fr", "en", "de"]},
			"frontend": true,
			"upstream": {"host": true, "rewriteBody": {"enabled": true}}
		}]
	}`
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Routes) != 3 {
		t.Fatalf("routes = %d, want 3", len(c.Routes))
	}

	want := map[string]map[string]string{
		"de.wikipedia.demo.localhost": {
			"en.wikipedia.org": "en.wikipedia.demo.localhost",
			"fr.wikipedia.org": "fr.wikipedia.demo.localhost",
		},
		"en.wikipedia.demo.localhost": {
			"de.wikipedia.org": "de.wikipedia.demo.localhost",
			"fr.wikipedia.org": "fr.wikipedia.demo.localhost",
		},
		"fr.wikipedia.demo.localhost": {
			"de.wikipedia.org": "de.wikipedia.demo.localhost",
			"en.wikipedia.org": "en.wikipedia.demo.localhost",
		},
	}
	for i := range c.Routes {
		r := &c.Routes[i]
		got := r.RewriteTargets()
		if len(got) != 2 {
			t.Errorf("%s: targets = %v, want 2", r.Host, got)
		}
		for origin, publicHost := range want[r.Host] {
			if got[origin] != publicHost {
				t.Errorf("%s: %s -> %q, want %q",
					r.Host, origin, got[origin], publicHost)
			}
		}
		if _, self := got[r.Host]; self {
			t.Errorf("%s: own backend must not be a target", r.Host)
		}
	}
}

// Alias form (capture absent from the backend): every public host
// points at the SAME origin, so a link to that origin cannot choose
// a variant — the mapping must stay empty rather than guess.
func TestWildcardRewriteTargetsAliasAmbiguous(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "routes.json")
	cfg := `{
		"oidc": {"loginUrl": "http://login.test/login"},
		"routes": [{
			"host": "{lang}.x.localhost", "path": "/*",
			"backend": "https://fixed.example",
			"wildcard": {"lang": ["fr", "en"]},
			"upstream": {"host": true, "rewriteBody": {"enabled": true}}
		}]
	}`
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := range c.Routes {
		if got := c.Routes[i].RewriteTargets(); len(got) != 0 {
			t.Errorf("%s: ambiguous alias mapping = %v, want none",
				c.Routes[i].Host, got)
		}
	}
}

// Explicit cross-route targets: origin host → public host, resolved
// against declared routes. This is the opt-in for routes that are not
// variants of one wildcard expansion.
func TestRewriteBodyExplicitTargets(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "routes.json")
	cfg := `{
		"oidc": {"loginUrl": "http://login.test/login"},
		"routes": [
			{
				"host": "a.public.localhost", "path": "/*", "frontend": true,
				"backend": "https://a.backend.example",
				"upstream": {"host": true, "rewriteBody": {
					"enabled": true,
					"targets": {"b.backend.example": "b.public.localhost"}
				}}
			},
			{
				"host": "b.public.localhost", "path": "/*", "frontend": true,
				"backend": "https://b.backend.example",
				"upstream": {"host": true}
			}
		]
	}`
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	var a *Route
	for i := range c.Routes {
		if c.Routes[i].Host == "a.public.localhost" {
			a = &c.Routes[i]
		}
	}
	if a == nil {
		t.Fatal("route a not found")
	}
	got := a.RewriteTargets()
	if got["b.backend.example"] != "b.public.localhost" {
		t.Errorf("targets = %v, want b.backend.example -> b.public.localhost", got)
	}
	if len(got) != 1 {
		t.Errorf("targets = %v, want exactly one entry", got)
	}
}

// followRoutes: select declared routes by PUBLIC host (exact or
// *.suffix), then derive origin → public host. Routes outside the
// selectors are never mapped; the current route is never mapped.
func TestRewriteBodyFollowRoutes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "routes.json")
	cfg := `{
		"oidc": {"loginUrl": "http://login.test/login"},
		"routes": [
			{
				"host": "hub.public.localhost", "path": "/*", "frontend": true,
				"backend": "https://hub.backend.example",
				"upstream": {"host": true, "rewriteBody": {
					"enabled": true,
					"followRoutes": ["es.public.localhost", "*.elsewhere.localhost"]
				}}
			},
			{"host": "es.public.localhost", "path": "/*", "backend": "https://es.backend.example"},
			{"host": "de.elsewhere.localhost", "path": "/*", "backend": "https://de.backend.example"},
			{"host": "fr.public.localhost", "path": "/*", "backend": "https://fr.backend.example"}
		]
	}`
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	var hub *Route
	for i := range c.Routes {
		if c.Routes[i].Host == "hub.public.localhost" {
			hub = &c.Routes[i]
		}
	}
	if hub == nil {
		t.Fatal("hub route not found")
	}
	want := map[string]string{
		"es.backend.example": "es.public.localhost",
		"de.backend.example": "de.elsewhere.localhost",
	}
	got := hub.RewriteTargets()
	if len(got) != len(want) {
		t.Errorf("targets = %v, want %v", got, want)
	}
	for origin, host := range want {
		if got[origin] != host {
			t.Errorf("%s -> %q, want %q", origin, got[origin], host)
		}
	}
	if _, mapped := got["fr.backend.example"]; mapped {
		t.Error("followRoutes must not map a route outside the selectors")
	}
	if _, self := got["hub.backend.example"]; self {
		t.Error("followRoutes must not map the current route's own origin")
	}
}

func TestRewriteBodyTargetsRejects(t *testing.T) {
	cases := []struct {
		name string
		cfg  string
		want string
	}{
		{
			name: "target value with scheme",
			cfg: `{"routes": [
				{"host": "a.public.localhost", "path": "/*", "backend": "https://a.backend.example",
				 "upstream": {"host": true, "rewriteBody": {"enabled": true,
				 "targets": {"b.backend.example": "https://b.public.localhost"}}}},
				{"host": "b.public.localhost", "path": "/*", "backend": "https://b.backend.example"}
			]}`,
			want: "bare host",
		},
		{
			name: "target key with scheme",
			cfg: `{"routes": [
				{"host": "a.public.localhost", "path": "/*", "backend": "https://a.backend.example",
				 "upstream": {"host": true, "rewriteBody": {"enabled": true,
				 "targets": {"https://b.backend.example": "b.public.localhost"}}}},
				{"host": "b.public.localhost", "path": "/*", "backend": "https://b.backend.example"}
			]}`,
			want: "bare host",
		},
		{
			name: "unknown origin",
			cfg: `{"routes": [
				{"host": "a.public.localhost", "path": "/*", "backend": "https://a.backend.example",
				 "upstream": {"host": true, "rewriteBody": {"enabled": true,
				 "targets": {"nope.backend.example": "b.public.localhost"}}}},
				{"host": "b.public.localhost", "path": "/*", "backend": "https://b.backend.example"}
			]}`,
			want: "not an origin of a declared route",
		},
		{
			name: "unknown target",
			cfg: `{"routes": [
				{"host": "a.public.localhost", "path": "/*", "backend": "https://a.backend.example",
				 "upstream": {"host": true, "rewriteBody": {"enabled": true,
				 "targets": {"b.backend.example": "nope.public.localhost"}}}},
				{"host": "b.public.localhost", "path": "/*", "backend": "https://b.backend.example"}
			]}`,
			want: "not the public host of a declared route",
		},
		{
			name: "self origin",
			cfg: `{"routes": [
				{"host": "a.public.localhost", "path": "/*", "backend": "https://a.backend.example",
				 "upstream": {"host": true, "rewriteBody": {"enabled": true,
				 "targets": {"a.backend.example": "b.public.localhost"}}}},
				{"host": "b.public.localhost", "path": "/*", "backend": "https://b.backend.example"}
			]}`,
			want: "own origin",
		},
		{
			name: "self public host",
			cfg: `{"routes": [
				{"host": "a.public.localhost", "path": "/*", "backend": "https://a.backend.example",
				 "upstream": {"host": true, "rewriteBody": {"enabled": true,
				 "targets": {"b.backend.example": "a.public.localhost"}}}},
				{"host": "b.public.localhost", "path": "/*", "backend": "https://b.backend.example"}
			]}`,
			want: "own public host",
		},
		{
			name: "targets without enabled",
			cfg: `{"routes": [
				{"host": "a.public.localhost", "path": "/*", "backend": "https://a.backend.example",
				 "upstream": {"host": true, "rewriteBody": {"enabled": false,
				 "targets": {"b.backend.example": "b.public.localhost"}}}},
				{"host": "b.public.localhost", "path": "/*", "backend": "https://b.backend.example"}
			]}`,
			want: "require enabled: true",
		},
		{
			name: "followRoutes bare star",
			cfg: `{"routes": [
				{"host": "a.public.localhost", "path": "/*", "backend": "https://a.backend.example",
				 "upstream": {"host": true, "rewriteBody": {"enabled": true,
				 "followRoutes": ["*"]}}},
				{"host": "b.public.localhost", "path": "/*", "backend": "https://b.backend.example"}
			]}`,
			want: "bare * is refused",
		},
		{
			name: "followRoutes no match",
			cfg: `{"routes": [
				{"host": "a.public.localhost", "path": "/*", "backend": "https://a.backend.example",
				 "upstream": {"host": true, "rewriteBody": {"enabled": true,
				 "followRoutes": ["*.nowhere.localhost"]}}},
				{"host": "b.public.localhost", "path": "/*", "backend": "https://b.backend.example"}
			]}`,
			want: "matches no declared route",
		},
		{
			name: "followRoutes only self",
			cfg: `{"routes": [
				{"host": "a.public.localhost", "path": "/*", "backend": "https://a.backend.example",
				 "upstream": {"host": true, "rewriteBody": {"enabled": true,
				 "followRoutes": ["a.public.localhost"]}}},
				{"host": "b.public.localhost", "path": "/*", "backend": "https://b.backend.example"}
			]}`,
			want: "matches only this route",
		},
		{
			name: "followRoutes ambiguity",
			cfg: `{"routes": [
				{"host": "a.public.localhost", "path": "/*", "backend": "https://a.backend.example",
				 "upstream": {"host": true, "rewriteBody": {"enabled": true,
				 "followRoutes": ["x.public.localhost", "y.public.localhost"]}}},
				{"host": "x.public.localhost", "path": "/*", "backend": "https://shared.backend.example"},
				{"host": "y.public.localhost", "path": "/*", "backend": "https://shared.backend.example"}
			]}`,
			want: "already targets",
		},
		{
			name: "explicit/follow conflict",
			cfg: `{"routes": [
				{"host": "a.public.localhost", "path": "/*", "backend": "https://a.backend.example",
				 "upstream": {"host": true, "rewriteBody": {"enabled": true,
				 "targets": {"x.backend.example": "y.public.localhost"},
				 "followRoutes": ["x.public.localhost"]}}},
				{"host": "x.public.localhost", "path": "/*", "backend": "https://x.backend.example"},
				{"host": "y.public.localhost", "path": "/*", "backend": "https://y.backend.example"}
			]}`,
			want: "already targets",
		},
		{
			name: "explicit/wildcard conflict",
			cfg: `{"routes": [
				{"host": "{lang}.wiki.demo.localhost", "path": "/*",
				 "backend": "https://{lang}.wikipedia.org",
				 "wildcard": {"lang": ["en", "fr"]},
				 "upstream": {"host": true, "rewriteBody": {"enabled": true,
				 "targets": {"fr.wikipedia.org": "other.public.localhost"}}}},
				{"host": "other.public.localhost", "path": "/*", "backend": "https://other.backend.example"}
			]}`,
			want: "already targets",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "routes.json")
			if err := os.WriteFile(path, []byte(c.cfg), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := Load(path)
			if err == nil {
				t.Fatal("Load succeeded, want an error")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("error = %v, want substring %q", err, c.want)
			}
		})
	}
}

func TestWildcardRejects(t *testing.T) {
	cases := []struct{ name, cfg string }{
		{
			"label outside the allow-list is not a config issue (no route) — but a BAD label is",
			`{"routes": [{"host": "{lang}.x.localhost", "path": "/*",
			  "backend": "https://{lang}.x.org", "wildcard": {"lang": ["FR"]}}]}`,
		},
		{
			"label with a dot (domain jump)",
			`{"routes": [{"host": "{lang}.x.localhost", "path": "/*",
			  "backend": "https://{lang}.x.org", "wildcard": {"lang": ["fr.eu"]}}]}`,
		},
		{
			"capture without allow-list",
			`{"routes": [{"host": "{lang}.x.localhost", "path": "/*",
			  "backend": "https://{lang}.x.org", "wildcard": {"other": ["a"]}}]}`,
		},
		{
			"allow-list entry never referenced in the host",
			`{"routes": [{"host": "{lang}.x.localhost", "path": "/*",
			  "backend": "https://{lang}.x.org", "wildcard": {"lang": ["fr"], "tld": ["org"]}}]}`,
		},
		{
			"malformed capture",
			`{"routes": [{"host": "*.x.localhost", "path": "/*",
			  "backend": "https://x.org", "wildcard": {"lang": ["fr"]}}]}`,
		},
		{
			"collision with an exact route",
			`{"routes": [
			  {"host": "fr.wikipedia.demo.localhost", "path": "/*", "backend": "https://other.example"},
			  {"host": "{lang}.wikipedia.demo.localhost", "path": "/*",
			   "backend": "https://{lang}.wikipedia.org", "wildcard": {"lang": ["fr", "en"]}}]}`,
		},
	}
	for _, c := range cases {
		dir := t.TempDir()
		path := filepath.Join(dir, "routes.json")
		if err := os.WriteFile(path, []byte(c.cfg), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err == nil {
			t.Errorf("%s: load must be REFUSED", c.name)
		}
	}
}

// Alias form: the capture MAY be absent from the backend — N host
// aliases on one fixed backend (no SSRF surface at all).
func TestWildcardAliasForm(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "routes.json")
	cfg := `{
		"routes": [
			{"host": "{lang}.x.localhost", "path": "/*",
			 "backend": "https://fixed.example", "wildcard": {"lang": ["fr", "en"]}}
		]
	}`
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Routes) != 2 {
		t.Fatalf("routes = %d, want 2", len(c.Routes))
	}
	for _, r := range c.Routes {
		if r.Backend != "https://fixed.example" {
			t.Errorf("alias expansion must keep the fixed backend, got %s", r.Backend)
		}
	}
}

// TestAuthWhenIdentitySplit: auth.when holds technical conditions only
// (object = AND of its conditions, array = OR of ANDs), auth.identity
// holds identity conditions (checked after authentication). Mixing the
// two families is refused at load rather than silently reinterpreted.
func TestAuthWhenIdentitySplit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "routes.json")

	load := func(cfg string) (*Config, error) {
		if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
			t.Fatal(err)
		}
		return Load(path)
	}

	t.Run("object when + identity", func(t *testing.T) {
		c, err := load(`{"routes":[{"host":"a.local","path":"/x","backend":"http://x",
			"auth":{"when":{"method":"POST","body":{"k":true}},
			        "identity":{"roles":["r"],"claims":{"email":"*"}}}}]}`)
		if err != nil {
			t.Fatalf("valid auth rejected: %v", err)
		}
		a := c.Routes[0].Auth
		if a == nil || len(a.When) != 1 || a.When[0].Method != "POST" {
			t.Fatalf("when not deserialized: %+v", a)
		}
		if a.Identity == nil || len(a.Identity.Roles) != 1 ||
			a.Identity.Claims["email"] != "*" {
			t.Fatalf("identity not deserialized: %+v", a.Identity)
		}
	})

	t.Run("array when (OR of ANDs)", func(t *testing.T) {
		c, err := load(`{"routes":[{"host":"a.local","path":"/x","backend":"http://x",
			"auth":{"when":[{"method":"POST"},{"method":"DELETE","body":{"k":true}}]}}]}`)
		if err != nil {
			t.Fatalf("valid when array rejected: %v", err)
		}
		if got := len(c.Routes[0].Auth.When); got != 2 {
			t.Fatalf("when elements = %d, want 2", got)
		}
	})

	t.Run("identity-only (always required)", func(t *testing.T) {
		c, err := load(`{"routes":[{"host":"a.local","path":"/x","backend":"http://x",
			"auth":{"identity":{"user":"alice"}}}]}`)
		if err != nil {
			t.Fatalf("identity-only rejected: %v", err)
		}
		a := c.Routes[0].Auth
		if len(a.When) != 0 || a.Identity == nil || a.Identity.User != "alice" {
			t.Fatalf("identity-only not deserialized: %+v", a)
		}
	})

	t.Run("empty auth stays always-required", func(t *testing.T) {
		c, err := load(`{"routes":[{"host":"a.local","path":"/x","backend":"http://x",
			"auth":{}}]}`)
		if err != nil {
			t.Fatalf("empty auth rejected: %v", err)
		}
		a := c.Routes[0].Auth
		if a == nil || len(a.When) != 0 || a.Identity != nil {
			t.Fatalf("empty auth not deserialized: %+v", a)
		}
	})

	t.Run("identity in when refused", func(t *testing.T) {
		_, err := load(`{"routes":[{"host":"a.local","path":"/x","backend":"http://x",
			"auth":{"when":{"method":"GET","roles":["r"]}}}]}`)
		if err == nil || !strings.Contains(err.Error(), "auth.identity") {
			t.Fatalf("identity in when accepted or wrong error: %v", err)
		}
	})

	t.Run("identity in when array element refused", func(t *testing.T) {
		_, err := load(`{"routes":[{"host":"a.local","path":"/x","backend":"http://x",
			"auth":{"when":[{"method":"GET"},{"scopes":["s"]}]}}]}`)
		if err == nil || !strings.Contains(err.Error(), "auth.when[1]") {
			t.Fatalf("identity in when array accepted or wrong error: %v", err)
		}
	})

	t.Run("technical in identity refused", func(t *testing.T) {
		_, err := load(`{"routes":[{"host":"a.local","path":"/x","backend":"http://x",
			"auth":{"when":{"method":"GET"},"identity":{"method":"POST"}}}]}`)
		if err == nil || !strings.Contains(err.Error(), "auth.when") {
			t.Fatalf("technical in identity accepted or wrong error: %v", err)
		}
	})

	t.Run("unknown field in when element refused", func(t *testing.T) {
		_, err := load(`{"routes":[{"host":"a.local","path":"/x","backend":"http://x",
			"auth":{"when":[{"mothod":"GET"}]}}]}`)
		if err == nil || !strings.Contains(err.Error(), "unknown field") {
			t.Fatalf("unknown field in when accepted or wrong error: %v", err)
		}
	})
}
