//go:build e2e

// Package e2e runs the full authentication chain in-process: fake
// Google, two brokers (one per tenant), two Gate One instances sharing
// Redis, and a test backend. Hosts are rewritten by a transport so the
// cookie jar sees real domains (mycompany.test, contoso.test) while the
// servers listen on 127.0.0.1.
package e2e

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"cladone/gate-one/internal/broker"
	"cladone/gate-one/internal/core"
	"cladone/gate-one/internal/proxy"
	"cladone/gate-one/internal/testutil/fakegoogle"
	"cladone/gate-one/internal/testutil/netchaos"

	"github.com/alicebob/miniredis/v2"
)

const (
	mycompanyDomain = "mycompany.test"
	contosoDomain   = "contoso.test"

	sessionKeyEnv   = "E2E_SESSION_KEY"
	clientSecretEnv = "E2E_OIDC_SECRET"
	sessionKey      = "e2e-session-key-0123456789"
	clientSecret    = "e2e-client-secret"
	authPrefix      = "e2e:auth:v1:"

	subjectSecretEnv = "E2E_SUBJECT_SECRET"
	pluginSecretEnv  = "E2E_PLUGIN_SECRET"
	e2ePluginName    = "e2e"
	e2ePluginSecret  = "e2e-plugin-secret-0123456789abcdef"
)

type stackOptions struct {
	mycompanyBrokerDown bool
	// mycompanyBrokerDelay injects a per-request delay into the mycompany broker
	// handler (0 = none). Adjustable at runtime via s.mycompanyDelay.
	mycompanyBrokerDelay time.Duration
	// redisDelay injects a per-direction TCP delay in front of the
	// shared Redis (0 = direct connection).
	redisDelay time.Duration
	// mycompanyBrokerProxy puts a stable, swappable HTTP proxy in front of
	// the mycompany broker so a key rotation can replace the broker
	// instance behind the same public URL.
	mycompanyBrokerProxy bool
	// redisHA replaces the miniredis URL with a real Sentinel cluster
	// (TLS + ACL). Used by the e2e_ha build tag against the local
	// Redis HA stack.
	redisHA *redisHAConfig

	// usagePluginURL, when set, enables the usage bus on BOTH replicas,
	// each with its own WAL dir and nodeId (gw-1/gw-2), delivering to
	// this plugin.
	usagePluginURL string
}

// redisHAConfig is the Sentinel-mode store used by the HA E2E test.
// The password fields are read from the environment by the driver.
type redisHAConfig struct {
	SentinelAddrs    []string
	MasterName       string
	SentinelUsername string
	SentinelPassword string
	Username         string
	Password         string
	TLSCaFile        string
	TLSServerName    string
	// AuthPrefix is shared by Gate One's sessionStore and the broker's
	// revocation keys. It must be allowed by the Redis ACL.
	AuthPrefix string
}

// sessionStoreJSON renders the Gate One sessionStore block.
func (r *redisHAConfig) sessionStoreJSON(prefix string) string {
	return fmt.Sprintf(`{
		"type": "redis",
		"masterName": %q,
		"sentinelAddrs": %s,
		"sentinelUsername": %q,
		"sentinelPasswordEnv": "E2E_HA_SENTINEL_PASSWORD",
		"username": %q,
		"passwordEnv": "E2E_HA_APP_PASSWORD",
		"tls": true,
		"tlsCaFile": %q,
		"tlsServerName": %q,
		"prefix": %q
	}`, r.MasterName, jsonStrings(r.SentinelAddrs), r.SentinelUsername,
		r.Username, r.TLSCaFile, r.TLSServerName, prefix)
}

// brokerRedis renders the broker redis block (same cluster).
func (r *redisHAConfig) brokerRedis(dataPrefix string) *broker.RedisConfig {
	return &broker.RedisConfig{
		MasterName:          r.MasterName,
		SentinelAddrs:       r.SentinelAddrs,
		SentinelUsername:    r.SentinelUsername,
		SentinelPasswordEnv: "E2E_HA_SENTINEL_PASSWORD",
		Username:            r.Username,
		PasswordEnv:         "E2E_HA_APP_PASSWORD",
		Prefix:              "cladone:broker:canari:e2e:" + dataPrefix + ":",
		AuthPrefix:          r.AuthPrefix,
		TLS:                 true,
		TLSCaFile:           r.TLSCaFile,
		TLSServerName:       r.TLSServerName,
	}
}

func jsonStrings(items []string) string {
	raw, _ := json.Marshal(items)
	return string(raw)
}

// Stack is one isolated E2E environment.
type Stack struct {
	t *testing.T

	fake    *fakegoogle.Server
	fakeSrv *httptest.Server
	redis   *miniredis.Miniredis

	mycompanyBroker *broker.Broker
	mycompanySrv    *httptest.Server
	mycompanyCfg    *broker.Config
	mycompanyDelay  *netchaos.HTTPDelay

	// Set when the mycompany broker sits behind a stable proxy (key
	// rotation test).
	brokerProxy      *netchaos.HTTPProxy
	mycompanyKeyFile string

	redisProxy *netchaos.DelayProxy

	contosoBroker *broker.Broker
	contosoSrv    *httptest.Server
	contosoCfg    *broker.Config

	gw1    *proxy.Gateway
	gw1Srv *httptest.Server
	gw2    *proxy.Gateway
	gw2Srv *httptest.Server

	backend *backend

	jar        http.CookieJar
	follow     *http.Client
	noRedirect *http.Client
}

func newStack(t *testing.T, opts stackOptions) *Stack {
	t.Helper()
	t.Setenv(sessionKeyEnv, sessionKey)
	t.Setenv(clientSecretEnv, clientSecret)

	s := &Stack{t: t}

	if opts.usagePluginURL != "" {
		t.Setenv(subjectSecretEnv, "e2e-subject-secret")
		t.Setenv(pluginSecretEnv, e2ePluginSecret)
	}

	s.redis = miniredis.RunT(t)

	fake, err := fakegoogle.New(fakegoogle.Config{
		ClientID: "google-client",
		Users: []fakegoogle.User{
			{
				Sub: "google-mycompany-alice", Email: "alice@mycompany.test",
				EmailVerified: true, HostedDomain: mycompanyDomain,
				PreferredUsername: "alice", Name: "Alice",
				Groups: []string{"admins"},
			},
			{
				Sub: "google-mycompany-carol", Email: "carol@mycompany.test",
				EmailVerified: true, HostedDomain: mycompanyDomain,
				PreferredUsername: "carol", Name: "Carol",
				Groups: []string{"superusers"},
			},
			{
				Sub: "google-contoso-bob", Email: "bob@contoso.test",
				EmailVerified: true, HostedDomain: contosoDomain,
				PreferredUsername: "bob", Name: "Bob",
				Groups: []string{"users"},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	s.fake = fake
	s.fakeSrv = httptest.NewServer(fake)
	t.Cleanup(s.fakeSrv.Close)
	fake.SetIssuer(s.fakeSrv.URL)

	s.backend = newBackend(t)

	redisAddr := s.redis.Addr()
	if opts.redisDelay > 0 {
		dp, err := netchaos.NewDelayProxy(redisAddr, opts.redisDelay)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(dp.Close)
		s.redisProxy = dp
		redisAddr = dp.Addr()
	}

	// Default: miniredis URL. The e2e_ha test swaps in a real Sentinel
	// cluster (TLS + ACL) with the same config shape.
	sessionStore := fmt.Sprintf(
		`{"type":"redis","url":"redis://%s/0","prefix":%q}`,
		redisAddr, authPrefix)
	brokerRedis := func(id string) *broker.RedisConfig {
		return &broker.RedisConfig{
			URL:        "redis://" + redisAddr + "/0",
			Prefix:     "e2e:broker:" + id + ":",
			AuthPrefix: authPrefix,
		}
	}
	if opts.redisHA != nil {
		sessionStore = opts.redisHA.sessionStoreJSON(opts.redisHA.AuthPrefix)
		brokerRedis = opts.redisHA.brokerRedis
	}

	s.mycompanyCfg = newBrokerConfig(
		"mycompany", s.fakeSrv.URL, brokerRedis("mycompany"), mycompanyDomain)
	if opts.mycompanyBrokerProxy {
		// A stable key file so the rotated config can keep the old
		// key in keyFiles (overlap window).
		kf := filepath.Join(t.TempDir(), "mycompany.key")
		if err := writeTestKey(kf); err != nil {
			t.Fatal(err)
		}
		s.mycompanyKeyFile = kf
		s.mycompanyCfg.Tenants[0].KeyFiles = []string{kf}
	}
	s.mycompanyBroker, s.mycompanySrv, s.mycompanyDelay = newBroker(t, s.mycompanyCfg)
	if opts.mycompanyBrokerDelay > 0 {
		s.mycompanyDelay.SetDelay(opts.mycompanyBrokerDelay)
	}
	if opts.mycompanyBrokerDown {
		// Close only the HTTP surface: the broker object (and its
		// Redis client) stays alive so t.Cleanup closes it once.
		s.mycompanySrv.Close()
	}
	if opts.mycompanyBrokerProxy {
		bp, err := netchaos.NewHTTPProxy(s.mycompanySrv.URL)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(bp.Close)
		s.brokerProxy = bp
		s.mycompanyBroker.SetPublicURL(bp.URL())
	}

	s.contosoCfg = newBrokerConfig(
		"contoso", s.fakeSrv.URL, brokerRedis("contoso"), contosoDomain)
	s.contosoBroker, s.contosoSrv, _ = newBroker(t, s.contosoCfg)

	mycompanyIssuer := s.mycompanySrv.URL
	if s.brokerProxy != nil {
		mycompanyIssuer = s.brokerProxy.URL()
	}

	// usageJSON renders the per-node usage block (its own WAL dir and
	// nodeId) or "" when the bus is disabled.
	usageJSON := func(nodeID, dir string) string {
		if opts.usagePluginURL == "" {
			return ""
		}
		return fmt.Sprintf(`
		"usage": {
			"dir": %q,
			"nodeId": %q,
			"subjectSecretEnv": %q,
			"pluginSecretEnv": %q,
			"budgetBytes": 1048576,
			"types": {
				"request": {"shareBytes": 524288, "fsync": "none"},
				"error":   {"shareBytes": 524288, "fsync": "none"}
			},
			"plugins": [{
				"name": %q, "url": %q, "types": ["request", "error"]
			}]
		},`, dir, nodeID, subjectSecretEnv, pluginSecretEnv,
			e2ePluginName, opts.usagePluginURL)
	}
	buildCfg := func(nodeID string) *core.Config {
		dir := filepath.Join(t.TempDir(), "usage")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		return loadConfig(t, fmt.Sprintf(`{%s
		"authProviders": [
			{
				"id": "mycompany", "type": "oidc",
				"issuer": %q,
				"clientId": "gate-one",
				"clientSecretEnv": %q,
				"loginBaseUrl": "https://login.mycompany.test",
				"cookieDomain": %q,
				"cookieName": "gate_one_mycompany",
				"roleClaims": ["roles", "groups"],
				"sessionStore": %s,
				"sessionKeyEnv": %q,
				"sessionTtlSeconds": 3600,
				"revocationTtlSeconds": 2592000,
				"backchannelLogout": true
			},
			{
				"id": "contoso", "type": "oidc",
				"issuer": %q,
				"clientId": "gate-one",
				"clientSecretEnv": %q,
				"loginBaseUrl": "https://login.contoso.test",
				"cookieDomain": %q,
				"cookieName": "gate_one_contoso",
				"roleClaims": ["roles", "groups"],
				"sessionStore": %s,
				"sessionKeyEnv": %q,
				"sessionTtlSeconds": 3600,
				"revocationTtlSeconds": 2592000,
				"backchannelLogout": true
			}
		],
		"defaultAuthProvider": "mycompany",
		"defaultAppUrl": "https://app.mycompany.test/",
		"routes": [
			{"host": "app.mycompany.test", "path": "/*", "frontend": true,
			 "backend": %q, "auth": {"provider": "mycompany"}},
			{"host": "app2.mycompany.test", "path": "/*", "frontend": true,
			 "backend": %q, "auth": {"provider": "mycompany"}},
			{"host": "api.mycompany.test", "path": "/*",
			 "backend": %q, "auth": {"provider": "mycompany"}},
			{"host": "public.mycompany.test", "path": "/*", "frontend": true,
			 "backend": %q},
			{"host": "denied.mycompany.test", "path": "/*", "frontend": true,
			 "backend": %q, "auth": {"provider": "mycompany",
			  "identity": {"roles": ["superusers"]}}},
			{"host": "quiet.mycompany.test", "path": "/*", "frontend": true,
			 "backend": %q, "auth": {"provider": "mycompany"}, "usage": false},
			{"host": "app.contoso.test", "path": "/*", "frontend": true,
			 "backend": %q, "auth": {"provider": "contoso"}}
		]
	}`,
			usageJSON(nodeID, dir),
			mycompanyIssuer+"/t/mycompany", clientSecretEnv, mycompanyDomain,
			sessionStore, sessionKeyEnv,
			s.contosoSrv.URL+"/t/contoso", clientSecretEnv, contosoDomain,
			sessionStore, sessionKeyEnv,
			s.backend.URL(), s.backend.URL(), s.backend.URL(),
			s.backend.URL(), s.backend.URL(), s.backend.URL(),
			s.backend.URL(),
		))
	}
	cfg1 := buildCfg("gw-1")
	cfg2 := buildCfg("gw-2")

	gw1, err := proxy.New(cfg1)
	if err != nil {
		t.Fatal(err)
	}
	s.gw1 = gw1
	s.gw1Srv = httptest.NewTLSServer(gw1)
	t.Cleanup(func() {
		s.gw1Srv.Close()
		_ = gw1.Close()
	})

	gw2, err := proxy.New(cfg2)
	if err != nil {
		t.Fatal(err)
	}
	s.gw2 = gw2
	s.gw2Srv = httptest.NewTLSServer(gw2)
	t.Cleanup(func() {
		s.gw2Srv.Close()
		_ = gw2.Close()
	})

	hosts := map[string]*httptest.Server{
		"app.mycompany.test":    s.gw1Srv,
		"app2.mycompany.test":   s.gw2Srv,
		"login.mycompany.test":  s.gw1Srv,
		"api.mycompany.test":    s.gw1Srv,
		"public.mycompany.test": s.gw1Srv,
		"denied.mycompany.test": s.gw1Srv,
		"quiet.mycompany.test":  s.gw1Srv,
		"app.contoso.test":      s.gw1Srv,
		"login.contoso.test":    s.gw1Srv,
	}

	base := http.DefaultTransport.(*http.Transport).Clone()
	base.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	tr := &mapTransport{base: base, hosts: hosts}

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	s.jar = jar
	s.follow = &http.Client{Jar: jar, Transport: tr}
	s.noRedirect = &http.Client{
		Jar:       jar,
		Transport: tr,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return s
}

func NewStack(t *testing.T) *Stack {
	return newStack(t, stackOptions{})
}

func newBrokerConfig(
	id, fakeURL string, redis *broker.RedisConfig, domain string,
) *broker.Config {
	return &broker.Config{
		PublicURL: "http://placeholder.invalid",
		Tenants: []broker.Tenant{{
			ID:           id,
			ClientID:     "gate-one",
			ClientSecret: clientSecret,
			RedirectURIs: []string{
				"https://login." + domain + "/auth/callback",
			},
			PostLogoutRedirectURIs: []string{
				"https://login." + domain + "/*",
				"https://app." + domain + "/*",
				"https://app2." + domain + "/*",
				"https://denied." + domain + "/*",
			},
			Audiences: []string{"https://api." + domain},
			Google: broker.GoogleConfig{
				Issuer:       fakeURL,
				ClientID:     "google-client",
				ClientSecret: "google-secret",
				HostedDomain: domain,
				Scopes:       []string{"openid", "profile", "email"},
			},
			DefaultRoles:   []string{"user"},
			AllowedDomains: []string{domain},
			// The broker is the policy point: a Google group becomes
			// a role in the emitted ID token. Gate One only reads
			// roles (it does not need the upstream groups claim).
			GroupRoles: map[string][]string{
				"superusers": {"superusers"},
			},
		}},
		Redis: redis,
	}
}

func newBroker(
	t *testing.T, cfg *broker.Config,
) (*broker.Broker, *httptest.Server, *netchaos.HTTPDelay) {
	t.Helper()
	b, err := broker.New(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	delayer := netchaos.NewHTTPDelay(b.Handler())
	srv := httptest.NewServer(delayer)
	t.Cleanup(func() {
		srv.Close()
		_ = b.Close()
	})
	b.SetPublicURL(srv.URL)
	return b, srv, delayer
}

// writeTestKey writes a fresh Ed25519 signing key (base64 raw seed),
// the same format as `cladone-auth keygen`.
func writeTestKey(path string) error {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	body := base64.RawURLEncoding.EncodeToString(priv.Seed()) + "\n"
	return os.WriteFile(path, []byte(body), 0o600)
}

func loadConfig(t *testing.T, raw string) *core.Config {
	t.Helper()
	path := filepath.Join(t.TempDir(), "routes.json")
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := core.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

// mapTransport sends fake hosts to their httptest server while keeping
// the original URL host for the cookie jar and the Host header.
type mapTransport struct {
	base  http.RoundTripper
	hosts map[string]*httptest.Server
}

func (m *mapTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	srv, ok := m.hosts[req.URL.Hostname()]
	if !ok {
		return m.base.RoundTrip(req)
	}
	target, err := url.Parse(srv.URL)
	if err != nil {
		return nil, err
	}
	clone := req.Clone(req.Context())
	u := *req.URL
	u.Scheme = target.Scheme
	u.Host = target.Host
	clone.URL = &u
	clone.Host = req.URL.Host
	return m.base.RoundTrip(clone)
}

// CloseIdleConnections forwards to the wrapped transport: without it
// http.Client.CloseIdleConnections is a silent no-op through the
// mapping layer (goroutine-leak tests would see idle conns forever).
func (m *mapTransport) CloseIdleConnections() {
	if c, ok := m.base.(interface{ CloseIdleConnections() }); ok {
		c.CloseIdleConnections()
	}
}

// backend records the identity headers Gate One forwards.
type backend struct {
	mu   sync.Mutex
	seen map[string]http.Header
	srv  *httptest.Server
}

func newBackend(t *testing.T) *backend {
	t.Helper()
	b := &backend{seen: map[string]http.Header{}}
	b.srv = httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			host := r.Header.Get("X-Forwarded-Host")
			if host == "" {
				host = r.Host
			}
			b.mu.Lock()
			b.seen[host] = r.Header.Clone()
			b.mu.Unlock()
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = io.WriteString(w,
				"<!doctype html><html><body>ok</body></html>")
		}))
	t.Cleanup(b.srv.Close)
	return b
}

func (b *backend) URL() string { return b.srv.URL }

func (b *backend) headers(host string) http.Header {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.seen[host]
}

// login follows the whole browser flow and returns the final page.
func (s *Stack) login(appURL string) string {
	s.t.Helper()
	resp, err := s.follow.Get(appURL)
	if err != nil {
		s.t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		s.t.Fatalf("login %s = %d: %s", appURL, resp.StatusCode, body)
	}
	return string(body)
}

func (s *Stack) setUser(email string) {
	s.t.Helper()
	if err := s.fake.SetDefaultUser(email); err != nil {
		s.t.Fatal(err)
	}
}

func (s *Stack) rpCookie(host, name string) *http.Cookie {
	s.t.Helper()
	for _, c := range s.jar.Cookies(&url.URL{
		Scheme: "https", Host: host,
	}) {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func (s *Stack) rpPayload(c *http.Cookie) map[string]any {
	s.t.Helper()
	body, _, ok := strings.Cut(c.Value, ".")
	if !ok {
		s.t.Fatalf("malformed RP cookie")
	}
	raw, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		s.t.Fatal(err)
	}
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		s.t.Fatal(err)
	}
	return payload
}
