//go:build e2e && e2e_ha

// HA end-to-end test: a real Sentinel cluster (TLS + ACL) backs the
// same in-process chain as the e2e suite. The driver
// (compose/redis-ha/ha-e2e.sh) stops the current master once the test
// signals that a session is established. The test then proves:
//
//  1. the session survives the failover (same cookie, identity kept);
//  2. a revocation issued after the failover (fresh Sentinel
//     connection, the CLI path) is seen on the next request;
//  3. a new login after the failover is allowed.
//
// Run with: make ha-e2e (from cladone-it-infra).
package e2e

import (
	"context"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"cladone/gate-one/internal/iam"
	"cladone/gate-one/internal/proxy"
)

func haConfigFromEnv(t *testing.T) *redisHAConfig {
	t.Helper()
	raw := os.Getenv("E2E_HA_SENTINELS")
	if raw == "" {
		t.Skip("E2E_HA_SENTINELS not set: run `make ha-e2e`")
	}
	for _, name := range []string{
		"E2E_HA_SENTINEL_PASSWORD", "E2E_HA_APP_PASSWORD",
	} {
		if os.Getenv(name) == "" {
			t.Fatalf("%s is empty", name)
		}
	}
	ha := &redisHAConfig{
		SentinelAddrs: strings.Split(raw, ","),
		MasterName:    envOr("E2E_HA_MASTER", "authmaster"),
		Username:      envOr("E2E_HA_USER", "app"),
		TLSCaFile:     envOr("E2E_HA_CA", "/tls/ca.crt"),
		TLSServerName: envOr("E2E_HA_SERVER_NAME", "redis.cladone.internal"),
		AuthPrefix:    envOr("E2E_HA_PREFIX", "cladone:auth:v1:e2e:"),
	}
	ha.SentinelUsername = os.Getenv("E2E_HA_SENTINEL_USER")
	return ha
}

func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

// appCode performs an authenticated request without following the
// redirect. 200 = session accepted, 302/401 = login required,
// 502 = fail-closed (Redis unavailable). A transport error is reported
// as 0 so the poll loop treats it as a failure.
func (s *Stack) appCode() int {
	resp, err := s.noRedirect.Get("https://app.mycompany.test/")
	if err != nil {
		return 0
	}
	resp.Body.Close()
	return resp.StatusCode
}

func TestE2E_HA_SessionSurvivesFailover(t *testing.T) {
	ha := haConfigFromEnv(t)
	s := newStack(t, stackOptions{redisHA: ha})
	s.setUser("alice@mycompany.test")

	s.login("https://app.mycompany.test/")
	c := s.rpCookie("app.mycompany.test", "gate_one_mycompany")
	if c == nil {
		t.Fatal("no RP cookie after login")
	}
	payload := s.rpPayload(c)
	sid, _ := payload["sid"].(string)
	uid, _ := payload["uid"].(string)
	if sid == "" || uid == "" {
		t.Fatalf("RP payload missing sid/uid: %v", payload)
	}
	if code := s.appCode(); code != http.StatusOK {
		t.Fatalf("before failover = %d, want 200", code)
	}

	// Tell the driver it may stop the master now.
	ready := os.Getenv("E2E_HA_READY_FILE")
	if ready == "" {
		t.Fatal("E2E_HA_READY_FILE is required")
	}
	if err := os.WriteFile(ready, []byte("ready"), 0o600); err != nil {
		t.Fatal(err)
	}

	// The fail-closed window is expected, then the same session must be
	// accepted again without re-login.
	deadline := time.Now().Add(120 * time.Second)
	sawFailure := false
	recovered := false
	var lastCode int
	for time.Now().Before(deadline) {
		code := s.appCode()
		lastCode = code
		if code != http.StatusOK {
			sawFailure = true
		}
		if sawFailure && code == http.StatusOK {
			recovered = true
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if !sawFailure {
		t.Fatalf("failover not observed (last status %d): was the master stopped?", lastCode)
	}
	if !recovered {
		t.Fatalf("session did not recover after failover (last status %d)", lastCode)
	}

	// Same cookie, same identity: the session survived, not a re-login.
	c2 := s.rpCookie("app.mycompany.test", "gate_one_mycompany")
	if c2 == nil || c2.Value != c.Value {
		t.Fatal("RP cookie changed across the failover (unexpected re-login)")
	}
	h := s.backend.headers("app.mycompany.test")
	if h == nil {
		t.Fatal("backend did not receive the request after failover")
	}
	if got := h.Get("X-Email"); got != "alice@mycompany.test" {
		t.Errorf("X-Email after failover = %q", got)
	}

	// Revocation after the failover: a fresh Sentinel connection (the
	// `cladone-auth revoke` path) must be seen by Gate One.
	if err := iam.RevokeWithConfig(
		context.Background(), s.mycompanyCfg, "mycompany", sid, uid, time.Hour,
	); err != nil {
		t.Fatal(err)
	}
	proxy.ResetAuthCache()
	if code := s.appCode(); code != http.StatusFound &&
		code != http.StatusUnauthorized {
		t.Fatalf("after revoke = %d, want 302/401", code)
	}

	// A new login after the failover is allowed and gets a new sid.
	time.Sleep(1100 * time.Millisecond)
	s.setUser("alice@mycompany.test")
	s.login("https://app.mycompany.test/")
	c3 := s.rpCookie("app.mycompany.test", "gate_one_mycompany")
	if c3 == nil {
		t.Fatal("no RP cookie after second login")
	}
	if p3 := s.rpPayload(c3); p3["sid"] == sid {
		t.Fatal("sid did not change after logout/login")
	}
	if code := s.appCode(); code != http.StatusOK {
		t.Fatalf("after new login = %d, want 200", code)
	}
}
