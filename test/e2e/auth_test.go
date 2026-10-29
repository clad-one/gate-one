//go:build e2e

package e2e

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"cladone/gate-one/internal/broker"
	"cladone/gate-one/internal/proxy"
)

// TestE2E_Login_SSO_Logout_NewLogin covers the browser path end to end:
// login through fake Google and the broker, SSO across two apps and two
// Gate One instances, logout, then a new login with a new sid.
func TestE2E_Login_SSO_Logout_NewLogin(t *testing.T) {
	s := NewStack(t)
	s.setUser("alice@acme.test")

	body := s.login("https://app.acme.test/")
	if !strings.Contains(body, "__cladoneAuthGuard") {
		t.Fatal("guard script not injected on app.acme.test")
	}

	c1 := s.rpCookie("app.acme.test", "gate_one_acme")
	if c1 == nil {
		t.Fatal("no RP cookie after login")
	}
	p1 := s.rpPayload(c1)
	sid1, _ := p1["sid"].(string)
	uid1, _ := p1["uid"].(string)
	if sid1 == "" || uid1 == "" {
		t.Fatalf("RP payload missing sid/uid: %v", p1)
	}

	h := s.backend.headers("app.acme.test")
	if h == nil {
		t.Fatal("backend did not receive app.acme.test")
	}
	if got := h.Get("X-User-Id"); got != uid1 {
		t.Errorf("X-User-Id = %q, want %q", got, uid1)
	}
	if got := h.Get("X-Email"); got != "alice@acme.test" {
		t.Errorf("X-Email = %q", got)
	}
	if got := h.Get("X-Roles"); !strings.Contains(got, "user") {
		t.Errorf("X-Roles = %q", got)
	}

	// app2 is served by the second Gate One instance; the RP cookie is
	// shared on acme.test and the Redis store is shared.
	body2 := s.login("https://app2.acme.test/")
	if !strings.Contains(body2, "__cladoneAuthGuard") {
		t.Fatal("guard script not injected on app2.acme.test")
	}
	c2 := s.rpCookie("app2.acme.test", "gate_one_acme")
	if c2 == nil || c2.Value != c1.Value {
		t.Fatalf("RP cookie not shared with app2: %+v", c2)
	}

	// Logout from app A: the logout surface is the login host, not the
	// proxied app host.
	resp, err := s.follow.Get("https://login.acme.test/logout")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	// app B must require a new login.
	resp2, err := s.noRedirect.Get("https://app2.acme.test/")
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusFound {
		t.Fatalf("app2 after logout = %d, want 302", resp2.StatusCode)
	}

	// A new login is allowed and gets a new sid. The sub revocation is
	// stored with second granularity: a login in the same second as the
	// logout is deliberately still rejected, so wait one second.
	time.Sleep(1100 * time.Millisecond)
	s.setUser("alice@acme.test")
	s.login("https://app.acme.test/")
	c3 := s.rpCookie("app.acme.test", "gate_one_acme")
	if c3 == nil {
		t.Fatal("no RP cookie after second login")
	}
	p3 := s.rpPayload(c3)
	sid3, _ := p3["sid"].(string)
	if sid3 == "" {
		t.Fatal("new RP payload missing sid")
	}
	if sid3 == sid1 {
		t.Fatalf("sid did not change after logout/login: %s", sid1)
	}
}

// TestE2E_RedisFailClosed_PublicOK proves the fail-closed policy: an
// authenticated route returns 502 when Redis is unavailable, public
// routes keep working, and the route recovers when Redis returns.
func TestE2E_RedisFailClosed_PublicOK(t *testing.T) {
	s := NewStack(t)
	s.setUser("alice@acme.test")
	s.login("https://app.acme.test/")

	proxy.ResetAuthCache()
	s.redis.SetError("ERR simulated outage")

	resp, err := s.noRedirect.Get("https://app.acme.test/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("redis down authenticated route = %d, want 502",
			resp.StatusCode)
	}

	pub, err := s.noRedirect.Get("https://public.acme.test/")
	if err != nil {
		t.Fatal(err)
	}
	pub.Body.Close()
	if pub.StatusCode != http.StatusOK {
		t.Fatalf("public route during redis outage = %d, want 200",
			pub.StatusCode)
	}

	s.redis.SetError("")
	proxy.ResetAuthCache()
	again, err := s.noRedirect.Get("https://app.acme.test/")
	if err != nil {
		t.Fatal(err)
	}
	again.Body.Close()
	if again.StatusCode != http.StatusOK {
		t.Fatalf("after redis recovery = %d, want 200", again.StatusCode)
	}
}

// TestE2E_Revoke_SID_SUB revokes the shared sid/sub through the broker
// API (the same path as the CLI) and checks Gate One rejects the
// existing session on the next request.
func TestE2E_Revoke_SID_SUB(t *testing.T) {
	s := NewStack(t)
	s.setUser("alice@acme.test")
	s.login("https://app.acme.test/")

	c := s.rpCookie("app.acme.test", "gate_one_acme")
	if c == nil {
		t.Fatal("no RP cookie after login")
	}
	payload := s.rpPayload(c)
	sid, _ := payload["sid"].(string)
	uid, _ := payload["uid"].(string)
	if sid == "" || uid == "" {
		t.Fatalf("RP payload missing sid/uid: %v", payload)
	}

	if err := broker.RevokeWithConfig(
		context.Background(), s.acmeCfg, "acme", sid, uid, time.Hour,
	); err != nil {
		t.Fatal(err)
	}
	proxy.ResetAuthCache()

	resp, err := s.noRedirect.Get("https://app.acme.test/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound &&
		resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("after revoke = %d, want 302/401", resp.StatusCode)
	}
}

// TestE2E_BrokerDown_PerTenant starts with the acme broker unreachable:
// acme routes are degraded (502) while contoso still logs in.
func TestE2E_BrokerDown_PerTenant(t *testing.T) {
	s := newStack(t, stackOptions{acmeBrokerDown: true})

	resp, err := s.noRedirect.Get("https://app.acme.test/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("acme with broker down = %d, want 502", resp.StatusCode)
	}

	s.setUser("bob@contoso.test")
	body := s.login("https://app.contoso.test/")
	if !strings.Contains(body, "__cladoneAuthGuard") {
		t.Fatal("contoso login failed while acme is degraded")
	}
}
