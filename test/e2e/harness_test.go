//go:build e2e

// Package e2e runs the full authentication chain in-process: fake
// Google, two brokers (one per tenant), two Gate One instances sharing
// Redis, and a test backend. Hosts are rewritten by a transport so the
// cookie jar sees real domains (acme.test, contoso.test) while the
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
	acmeDomain    = "acme.test"
	contosoDomain = "contoso.test"

	sessionKeyEnv   = "E2E_SESSION_KEY"
	clientSecretEnv = "E2E_OIDC_SECRET"
	sessionKey      = "e2e-session-key-0123456789"
	clientSecret    = "e2e-client-secret"
	authPrefix      = "e2e:auth:v1:"
)

type stackOptions struct {
	acmeBrokerDown bool
	// acmeBrokerDelay injects a per-request delay into the acme broker
	// handler (0 = none). Adjustable at runtime via s.acmeDelay.
	acmeBrokerDelay time.Duration
	// redisDelay injects a per-direction TCP delay in front of the
	// shared Redis (0 = direct connection).
	redisDelay time.Duration
	// acmeBrokerProxy puts a stable, swappable HTTP proxy in front of
	// the acme broker so a key rotation can replace the broker
	// instance behind the same public URL.
	acmeBrokerProxy bool
}

// Stack is one isolated E2E environment.
type Stack struct {
	t *testing.T

	fake    *fakegoogle.Server
	fakeSrv *httptest.Server
	redis   *miniredis.Miniredis

	acmeBroker *broker.Broker
	acmeSrv    *httptest.Server
	acmeCfg    *broker.Config
	acmeDelay  *netchaos.HTTPDelay

	// Set when the acme broker sits behind a stable proxy (key
	// rotation test).
	brokerProxy *netchaos.HTTPProxy
	acmeKeyFile string

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

	s.redis = miniredis.RunT(t)

	fake, err := fakegoogle.New(fakegoogle.Config{
		ClientID: "google-client",
		Users: []fakegoogle.User{
			{
				Sub: "google-acme-alice", Email: "alice@acme.test",
				EmailVerified: true, HostedDomain: acmeDomain,
				PreferredUsername: "alice", Name: "Alice",
				Groups: []string{"admins"},
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

	s.acmeCfg = newBrokerConfig("acme", s.fakeSrv.URL, redisAddr, acmeDomain)
	if opts.acmeBrokerProxy {
		// A stable key file so the rotated config can keep the old
		// key in keyFiles (overlap window).
		kf := filepath.Join(t.TempDir(), "acme.key")
		if err := writeTestKey(kf); err != nil {
			t.Fatal(err)
		}
		s.acmeKeyFile = kf
		s.acmeCfg.Tenants[0].KeyFiles = []string{kf}
	}
	s.acmeBroker, s.acmeSrv, s.acmeDelay = newBroker(t, s.acmeCfg)
	if opts.acmeBrokerDelay > 0 {
		s.acmeDelay.SetDelay(opts.acmeBrokerDelay)
	}
	if opts.acmeBrokerDown {
		// Close only the HTTP surface: the broker object (and its
		// Redis client) stays alive so t.Cleanup closes it once.
		s.acmeSrv.Close()
	}
	if opts.acmeBrokerProxy {
		bp, err := netchaos.NewHTTPProxy(s.acmeSrv.URL)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(bp.Close)
		s.brokerProxy = bp
		s.acmeBroker.SetPublicURL(bp.URL())
	}

	s.contosoCfg = newBrokerConfig(
		"contoso", s.fakeSrv.URL, redisAddr, contosoDomain)
	s.contosoBroker, s.contosoSrv, _ = newBroker(t, s.contosoCfg)

	acmeIssuer := s.acmeSrv.URL
	if s.brokerProxy != nil {
		acmeIssuer = s.brokerProxy.URL()
	}

	cfg := loadConfig(t, fmt.Sprintf(`{
		"authProviders": [
			{
				"id": "acme", "type": "oidc",
				"issuer": %q,
				"clientId": "gate-one",
				"clientSecretEnv": %q,
				"loginBaseUrl": "https://login.acme.test",
				"cookieDomain": %q,
				"cookieName": "gate_one_acme",
				"roleClaims": ["roles", "groups"],
				"sessionStore": {
					"type": "redis",
					"url": "redis://%s/0",
					"prefix": %q
				},
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
				"sessionStore": {
					"type": "redis",
					"url": "redis://%s/0",
					"prefix": %q
				},
				"sessionKeyEnv": %q,
				"sessionTtlSeconds": 3600,
				"revocationTtlSeconds": 2592000,
				"backchannelLogout": true
			}
		],
		"defaultAuthProvider": "acme",
		"routes": [
			{"host": "app.acme.test", "path": "/*", "frontend": true,
			 "backend": %q, "auth": {"provider": "acme"}},
			{"host": "app2.acme.test", "path": "/*", "frontend": true,
			 "backend": %q, "auth": {"provider": "acme"}},
			{"host": "api.acme.test", "path": "/*",
			 "backend": %q, "auth": {"provider": "acme"}},
			{"host": "public.acme.test", "path": "/*", "frontend": true,
			 "backend": %q},
			{"host": "app.contoso.test", "path": "/*", "frontend": true,
			 "backend": %q, "auth": {"provider": "contoso"}}
		]
	}`,
		acmeIssuer+"/t/acme", clientSecretEnv, acmeDomain,
		redisAddr, authPrefix, sessionKeyEnv,
		s.contosoSrv.URL+"/t/contoso", clientSecretEnv, contosoDomain,
		redisAddr, authPrefix, sessionKeyEnv,
		s.backend.URL(), s.backend.URL(), s.backend.URL(),
		s.backend.URL(), s.backend.URL(),
	))

	gw1, err := proxy.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	s.gw1 = gw1
	s.gw1Srv = httptest.NewTLSServer(gw1)
	t.Cleanup(func() {
		s.gw1Srv.Close()
		_ = gw1.Close()
	})

	gw2, err := proxy.New(cfg)
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
		"app.acme.test":      s.gw1Srv,
		"app2.acme.test":     s.gw2Srv,
		"login.acme.test":    s.gw1Srv,
		"api.acme.test":      s.gw1Srv,
		"public.acme.test":   s.gw1Srv,
		"app.contoso.test":   s.gw1Srv,
		"login.contoso.test": s.gw1Srv,
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
	id, fakeURL, redisAddr, domain string,
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
		}},
		Redis: &broker.RedisConfig{
			URL:        "redis://" + redisAddr + "/0",
			Prefix:     "e2e:broker:" + id + ":",
			AuthPrefix: authPrefix,
		},
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
