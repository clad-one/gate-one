//go:build e2e

package e2e

import (
	"context"
	"html"
	"io"
	"net/http"
	"net/url"
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
	s.setUser("alice@mycompany.test")

	body := s.login("https://app.mycompany.test/")
	if !strings.Contains(body, "__cladoneAuthGuard") {
		t.Fatal("guard script not injected on app.mycompany.test")
	}

	c1 := s.rpCookie("app.mycompany.test", "gate_one_mycompany")
	if c1 == nil {
		t.Fatal("no RP cookie after login")
	}
	p1 := s.rpPayload(c1)
	sid1, _ := p1["sid"].(string)
	uid1, _ := p1["uid"].(string)
	if sid1 == "" || uid1 == "" {
		t.Fatalf("RP payload missing sid/uid: %v", p1)
	}

	h := s.backend.headers("app.mycompany.test")
	if h == nil {
		t.Fatal("backend did not receive app.mycompany.test")
	}
	if got := h.Get("X-User-Id"); got != uid1 {
		t.Errorf("X-User-Id = %q, want %q", got, uid1)
	}
	if got := h.Get("X-Email"); got != "alice@mycompany.test" {
		t.Errorf("X-Email = %q", got)
	}
	if got := h.Get("X-Roles"); !strings.Contains(got, "user") {
		t.Errorf("X-Roles = %q", got)
	}

	// app2 is served by the second Gate One instance; the RP cookie is
	// shared on mycompany.test and the Redis store is shared.
	body2 := s.login("https://app2.mycompany.test/")
	if !strings.Contains(body2, "__cladoneAuthGuard") {
		t.Fatal("guard script not injected on app2.mycompany.test")
	}
	c2 := s.rpCookie("app2.mycompany.test", "gate_one_mycompany")
	if c2 == nil || c2.Value != c1.Value {
		t.Fatalf("RP cookie not shared with app2: %+v", c2)
	}

	// Logout from app A: the logout surface is the login host, not the
	// proxied app host.
	resp, err := s.follow.Get("https://login.mycompany.test/logout")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	// app B must require a new login.
	resp2, err := s.noRedirect.Get("https://app2.mycompany.test/")
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
	s.setUser("alice@mycompany.test")
	s.login("https://app.mycompany.test/")
	c3 := s.rpCookie("app.mycompany.test", "gate_one_mycompany")
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
	s.setUser("alice@mycompany.test")
	s.login("https://app.mycompany.test/")

	proxy.ResetAuthCache()
	s.redis.SetError("ERR simulated outage")

	resp, err := s.noRedirect.Get("https://app.mycompany.test/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("redis down authenticated route = %d, want 502",
			resp.StatusCode)
	}

	pub, err := s.noRedirect.Get("https://public.mycompany.test/")
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
	again, err := s.noRedirect.Get("https://app.mycompany.test/")
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

	if err := broker.RevokeWithConfig(
		context.Background(), s.mycompanyCfg, "mycompany", sid, uid, time.Hour,
	); err != nil {
		t.Fatal(err)
	}
	proxy.ResetAuthCache()

	resp, err := s.noRedirect.Get("https://app.mycompany.test/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound &&
		resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("after revoke = %d, want 302/401", resp.StatusCode)
	}
}

// TestE2E_BrokerDown_PerTenant starts with the mycompany broker unreachable:
// mycompany routes are degraded (502) while contoso still logs in.
func TestE2E_BrokerDown_PerTenant(t *testing.T) {
	s := newStack(t, stackOptions{mycompanyBrokerDown: true})

	resp, err := s.noRedirect.Get("https://app.mycompany.test/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("mycompany with broker down = %d, want 502", resp.StatusCode)
	}

	s.setUser("bob@contoso.test")
	body := s.login("https://app.contoso.test/")
	if !strings.Contains(body, "__cladoneAuthGuard") {
		t.Fatal("contoso login failed while mycompany is degraded")
	}
}

// TestE2E_Forbidden_SwitchAccount covers the blocked-user path: an
// authenticated user missing a route role gets a readable 403 with an
// explicit sign-out action, and can come back as another account with
// the required role. Without the action the user is trapped (a new tab
// reuses the same session).
func TestE2E_Forbidden_SwitchAccount(t *testing.T) {
	s := NewStack(t)
	s.setUser("alice@mycompany.test") // roles: user, admins — not superusers
	s.login("https://app.mycompany.test/")

	// A real browser navigation (Accept: text/html); an API client
	// still gets the JSON 403 unchanged.
	browserGet := func(target string) *http.Response {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, target, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Accept", "text/html,application/xhtml+xml")
		resp, err := s.noRedirect.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}

	resp := browserGet("https://denied.mycompany.test/")
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("denied route = %d, want 403", resp.StatusCode)
	}
	page := string(body)
	if !strings.Contains(page, "Signed in as") ||
		!strings.Contains(page, "alice@mycompany.test") {
		t.Fatalf("403 page does not name the refused account:\n%s", page)
	}
	if !strings.Contains(page, "Sign out and use another account") {
		t.Fatalf("403 page has no sign-out action:\n%s", page)
	}

	start := strings.Index(page, `href="`)
	if start < 0 {
		t.Fatal("no href on the 403 page")
	}
	rest := page[start+len(`href="`):]
	end := strings.Index(rest, `"`)
	if end < 0 {
		t.Fatal("unterminated href on the 403 page")
	}
	link := html.UnescapeString(rest[:end])
	if !strings.HasPrefix(link, "https://login.mycompany.test/logout?returnTo=") {
		t.Fatalf("sign-out link = %q", link)
	}
	if !strings.Contains(link, "denied.mycompany.test") {
		t.Fatalf("sign-out does not return to the refused URL: %q", link)
	}

	// Gate One clears its cookie, then redirects to the broker's
	// end-session (which revokes the shared session).
	logout, err := s.noRedirect.Get(link)
	if err != nil {
		t.Fatal(err)
	}
	logout.Body.Close()
	if logout.StatusCode != http.StatusFound {
		t.Fatalf("logout = %d, want 302", logout.StatusCode)
	}
	brokerLogout := logout.Header.Get("Location")
	if !strings.Contains(brokerLogout, "/t/mycompany/logout") {
		t.Fatalf("logout did not reach the broker: %q", brokerLogout)
	}
	bl, err := s.noRedirect.Get(brokerLogout)
	if err != nil {
		t.Fatal(err)
	}
	bl.Body.Close()
	if bl.StatusCode != http.StatusFound {
		t.Fatalf("broker logout = %d, want 302", bl.StatusCode)
	}

	// The RP session is gone: the route starts a fresh login instead of
	// showing the 403 again.
	after := browserGet("https://denied.mycompany.test/")
	after.Body.Close()
	if after.StatusCode != http.StatusFound {
		t.Fatalf("after sign-out = %d, want 302 to login", after.StatusCode)
	}

	// Another account, this time with the role, gets in.
	s.setUser("carol@mycompany.test")
	body2 := s.login("https://denied.mycompany.test/")
	if !strings.Contains(body2, "ok") {
		t.Fatalf("carol login did not reach the backend: %s", body2)
	}
	if roles := s.backend.headers("denied.mycompany.test").Get("X-Roles"); !strings.Contains(roles, "superusers") {
		t.Fatalf("X-Roles = %q, want superusers", roles)
	}
}

// TestE2E_ReadyzOnLoginHost: operational endpoints are served on every
// gateway host, including the dedicated login host (a load balancer
// may probe /readyz there instead of the app host).
func TestE2E_ReadyzOnLoginHost(t *testing.T) {
	s := NewStack(t)
	for _, base := range []string{
		"https://login.mycompany.test",
		"https://app.mycompany.test",
	} {
		resp, err := s.noRedirect.Get(base + "/readyz")
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s/readyz = %d: %s", base, resp.StatusCode, body)
		}
		if !strings.Contains(string(body), `"status":"ready"`) {
			t.Fatalf("%s/readyz body = %s", base, body)
		}
	}
}

// TestE2E_LoginHostLanding covers the generic, IdP-blind landing point
// of the login host root: a link-carried return target wins, an
// incomplete action link gets a readable diagnostic page (not a silent
// fallback), and a bare visit uses defaultAppUrl.
func TestE2E_LoginHostLanding(t *testing.T) {
	s := NewStack(t)

	browserGet := func(raw string) *http.Response {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, raw, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Accept", "text/html")
		resp, err := s.noRedirect.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}

	// 1. returnTo + action payload: redirect to the app, payload
	// preserved, routing params stripped.
	resp := browserGet("https://login.mycompany.test/?returnTo=" +
		"https%3A%2F%2Fapp.mycompany.test%2F&mode=verifyEmail&oobCode=abc123&lang=fr")
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("returnTo landing = %d, want 302", resp.StatusCode)
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if loc.Scheme != "https" || loc.Host != "app.mycompany.test" || loc.Path != "/" {
		t.Fatalf("redirect target = %s", loc)
	}
	q := loc.Query()
	if q.Get("mode") != "verifyEmail" || q.Get("oobCode") != "abc123" ||
		q.Get("lang") != "fr" {
		t.Fatalf("action payload lost: %v", q)
	}
	if q.Has("returnTo") || q.Has("continueUrl") {
		t.Fatalf("routing parameter forwarded: %v", q)
	}

	// 2. continueUrl (Firebase style) is accepted too.
	resp = browserGet("https://login.mycompany.test/?continueUrl=" +
		"https%3A%2F%2Fapp.mycompany.test%2F&mode=verifyEmail&oobCode=def456")
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("continueUrl landing = %d, want 302", resp.StatusCode)
	}
	if got := resp.Header.Get("Location"); !strings.HasPrefix(
		got, "https://app.mycompany.test/?") {
		t.Fatalf("continueUrl redirect = %q", got)
	}

	// 3. Action payload without any return target: readable 400 page
	// naming the missing adapter configuration.
	resp = browserGet("https://login.mycompany.test/?mode=verifyEmail&oobCode=abc123")
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("incomplete landing = %d, want 400", resp.StatusCode)
	}
	page := string(body)
	for _, want := range []string{
		"Incomplete link", "return application missing",
		"continueUrl", "returnTo", "Reference",
	} {
		if !strings.Contains(page, want) {
			t.Fatalf("fallback page missing %q:\n%s", want, page)
		}
	}
	if strings.Contains(page, "abc123") {
		t.Fatal("fallback page leaked the oobCode value")
	}

	// 4. returnTo outside the allowed hosts is refused.
	resp = browserGet("https://login.mycompany.test/?returnTo=" +
		"https%3A%2F%2Fevil.example%2F&mode=verifyEmail")
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("open redirect accepted: %d", resp.StatusCode)
	}
	if !strings.Contains(string(body), "host not allowed") {
		t.Fatalf("unexpected page: %s", body)
	}

	// 5. A subdomain of the cookie domain is an allowed app host.
	resp = browserGet("https://login.mycompany.test/?returnTo=" +
		"https%3A%2F%2Fsub.app.mycompany.test%2F")
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("subdomain landing = %d, want 302", resp.StatusCode)
	}

	// 6. Bare root: operational fallback to defaultAppUrl.
	resp = browserGet("https://login.mycompany.test/")
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("bare root = %d, want 302", resp.StatusCode)
	}
	if got := resp.Header.Get("Location"); got != "https://app.mycompany.test/" {
		t.Fatalf("bare root redirect = %q", got)
	}

	// 7. A real login path is untouched.
	login, err := s.noRedirect.Get(
		"https://login.mycompany.test/login?returnTo=https%3A%2F%2Fapp.mycompany.test%2F")
	if err != nil {
		t.Fatal(err)
	}
	login.Body.Close()
	if login.StatusCode != http.StatusFound {
		t.Fatalf("/login = %d, want 302 to the IdP", login.StatusCode)
	}
}

// TestE2E_LoginForwardsIdpHint: Gate One forwards the optional `idp`
// hint from its /login URL to the upstream authorize endpoint (e.g.
// the broker's local password login).
func TestE2E_LoginForwardsIdpHint(t *testing.T) {
	s := NewStack(t)
	resp, err := s.noRedirect.Get(
		"https://login.mycompany.test/login?idp=local&returnTo=" +
			"https%3A%2F%2Fapp.mycompany.test%2F")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("login = %d, want 302", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if !strings.Contains(loc, "idp=local") {
		t.Fatalf("idp hint not forwarded: %q", loc)
	}
}
