//go:build e2e && load

// Phase 4.5 — load and chaos. These tests are opt-in: they are slow
// and statistical, so they run with `-tags "e2e load"` and never in
// the default unit-test loop.
//
//	go test -count=1 -tags "e2e load" ./test/e2e/ -run TestLoad -v
//	go test -count=1 -tags "e2e load" ./test/e2e/ -run TestChaos -v
package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"cladone/gate-one/internal/iam"
	"cladone/gate-one/internal/proxy"
)

// samples is a latency distribution.
type samples []time.Duration

func (s samples) quantile(q float64) time.Duration {
	if len(s) == 0 {
		return 0
	}
	idx := int(q * float64(len(s)-1))
	if idx < 0 {
		idx = 0
	}
	if idx >= len(s) {
		idx = len(s) - 1
	}
	return s[idx]
}

func (s samples) summary() string {
	return fmt.Sprintf(
		"p50=%s p95=%s p99=%s max=%s",
		s.quantile(0.50).Round(time.Microsecond),
		s.quantile(0.95).Round(time.Microsecond),
		s.quantile(0.99).Round(time.Microsecond),
		s.quantile(1.00).Round(time.Microsecond),
	)
}

type loadResult struct {
	lat    samples
	status map[int]int
	errs   []string
}

func (r loadResult) total() int {
	n := 0
	for _, v := range r.status {
		n += v
	}
	return n
}

// runLoad fires workers×perWorker GETs at target and records the
// latency and final status of each one.
func runLoad(
	t *testing.T,
	client *http.Client,
	target string,
	workers, perWorker int,
) loadResult {
	t.Helper()

	var (
		mu  sync.Mutex
		res = loadResult{status: map[int]int{}}
		wg  sync.WaitGroup
	)
	start := make(chan struct{})

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			lat := make(samples, 0, perWorker)
			status := map[int]int{}
			var errs []string
			<-start
			for i := 0; i < perWorker; i++ {
				t0 := time.Now()
				resp, err := client.Get(target)
				d := time.Since(t0)
				if err != nil {
					errs = append(errs, err.Error())
					continue
				}
				_, _ = io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				lat = append(lat, d)
				status[resp.StatusCode]++
			}
			mu.Lock()
			res.lat = append(res.lat, lat...)
			for k, v := range status {
				res.status[k] += v
			}
			res.errs = append(res.errs, errs...)
			mu.Unlock()
		}()
	}
	close(start)
	wg.Wait()

	sort.Slice(res.lat, func(i, j int) bool {
		return res.lat[i] < res.lat[j]
	})
	return res
}

func (r loadResult) requireAll(t *testing.T, want int) {
	t.Helper()
	if len(r.errs) > 0 {
		t.Fatalf("%d transport errors, first: %s",
			len(r.errs), r.errs[0])
	}
	if got := r.status[want]; got != r.total() {
		t.Fatalf("status distribution = %v, want all %d", r.status, want)
	}
}

func getStatus(t *testing.T, client *http.Client, target string) int {
	t.Helper()
	resp, err := client.Get(target)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp.StatusCode
}

type statsSnapshot struct {
	CacheHits     int64 `json:"authCacheHits"`
	ProviderCalls int64 `json:"authBridgeCalls"`
}

func readStats(t *testing.T, client *http.Client) statsSnapshot {
	t.Helper()
	resp, err := client.Get("https://app.mycompany.test/__gate-one/stats")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("stats = %d", resp.StatusCode)
	}
	var snap statsSnapshot
	if err := json.NewDecoder(resp.Body).Decode(&snap); err != nil {
		t.Fatal(err)
	}
	return snap
}

// TestLoad_AuthenticatedLatency measures the steady-state cost of an
// authenticated request (identity cache hit + shared-store revocation
// check) and proves the cache is actually serving.
func TestLoad_AuthenticatedLatency(t *testing.T) {
	s := NewStack(t)
	s.setUser("alice@mycompany.test")
	s.login("https://app.mycompany.test/")

	// Warm up: TLS session, Redis pool, identity cache.
	for i := 0; i < 20; i++ {
		if got := getStatus(t, s.noRedirect, "https://app.mycompany.test/"); got != 200 {
			t.Fatalf("warmup = %d", got)
		}
	}

	before := readStats(t, s.noRedirect)
	res := runLoad(t, s.noRedirect, "https://app.mycompany.test/", 8, 150)
	after := readStats(t, s.noRedirect)

	res.requireAll(t, 200)
	t.Logf("authenticated requests=%d %s", len(res.lat), res.lat.summary())
	t.Logf("auth cache hits +%d, fresh provider calls +%d",
		after.CacheHits-before.CacheHits,
		after.ProviderCalls-before.ProviderCalls)

	if after.CacheHits-before.CacheHits < int64(len(res.lat)) {
		t.Fatalf("identity cache did not serve the load: hits +%d for %d requests",
			after.CacheHits-before.CacheHits, len(res.lat))
	}
	if p99 := res.lat.quantile(0.99); p99 > 250*time.Millisecond {
		t.Fatalf("p99 = %s, want <= 250ms", p99)
	}
}

// TestChaos_RedisSlowDown proves the per-request Redis revocation
// check is on the hot path and degrades proportionally, without
// failing requests.
func TestChaos_RedisSlowDown(t *testing.T) {
	s := newStack(t, stackOptions{redisDelay: 20 * time.Millisecond})
	s.setUser("alice@mycompany.test")
	s.login("https://app.mycompany.test/")
	for i := 0; i < 10; i++ {
		getStatus(t, s.noRedirect, "https://app.mycompany.test/")
	}

	s.redisProxy.SetDelay(0)
	fast := runLoad(t, s.noRedirect, "https://app.mycompany.test/", 4, 60)
	fast.requireAll(t, 200)

	s.redisProxy.SetDelay(20 * time.Millisecond)
	slow := runLoad(t, s.noRedirect, "https://app.mycompany.test/", 4, 60)
	slow.requireAll(t, 200)

	f50, s50 := fast.lat.quantile(0.50), slow.lat.quantile(0.50)
	t.Logf("redis delay=0     %s", fast.lat.summary())
	t.Logf("redis delay=20ms  %s", slow.lat.summary())
	if s50 < f50+15*time.Millisecond {
		t.Fatalf("Redis delay not visible: p50 fast=%s slow=%s", f50, s50)
	}
}

// TestChaos_RedisOutageUnderLoad checks fail-closed under load: every
// authenticated request is refused with 502, public routes keep
// working, and traffic recovers when Redis returns.
func TestChaos_RedisOutageUnderLoad(t *testing.T) {
	s := NewStack(t)
	s.setUser("alice@mycompany.test")
	s.login("https://app.mycompany.test/")
	proxy.ResetAuthCache()

	s.redis.SetError("ERR simulated outage")

	down := runLoad(t, s.noRedirect, "https://app.mycompany.test/", 4, 50)
	down.requireAll(t, http.StatusBadGateway)

	pub := runLoad(t, s.noRedirect, "https://public.mycompany.test/", 4, 50)
	pub.requireAll(t, 200)

	s.redis.SetError("")
	proxy.ResetAuthCache()

	up := runLoad(t, s.noRedirect, "https://app.mycompany.test/", 4, 50)
	up.requireAll(t, 200)

	t.Logf("outage: authenticated 502, public 200, recovery 200")
}

// TestChaos_IAMSlow checks the steady-state path does not depend on
// the IAM: a slow IAM makes login slow but leaves established
// sessions fast.
func TestChaos_IAMSlow(t *testing.T) {
	s := newStack(t, stackOptions{mycompanyIAMDelay: 200 * time.Millisecond})
	s.setUser("alice@mycompany.test")

	t0 := time.Now()
	s.login("https://app.mycompany.test/")
	loginDur := time.Since(t0)
	if loginDur < 200*time.Millisecond {
		t.Fatalf("login = %s, IAM delay not applied", loginDur)
	}

	proxy.ResetAuthCache()
	res := runLoad(t, s.noRedirect, "https://app.mycompany.test/", 4, 100)
	res.requireAll(t, 200)

	t.Logf("login (IAM delayed 200ms) = %s", loginDur.Round(time.Millisecond))
	t.Logf("steady state %s", res.lat.summary())
	if p99 := res.lat.quantile(0.99); p99 > 100*time.Millisecond {
		t.Fatalf("steady-state p99 = %s: IAM latency leaked into the request path", p99)
	}
}

// TestLoad_RevocationUnderLoad revokes a live session while traffic is
// flowing: in-flight requests may succeed, later ones must be refused,
// and the gateway must not fail with 5xx.
func TestLoad_RevocationUnderLoad(t *testing.T) {
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

	stop := make(chan struct{})
	var (
		wg       sync.WaitGroup
		ok       atomic.Int64
		refused  atomic.Int64
		upstream atomic.Int64
	)
	record := func(status int) {
		switch status {
		case 200:
			ok.Add(1)
		case http.StatusFound, http.StatusUnauthorized:
			refused.Add(1)
		default:
			upstream.Add(1)
		}
	}
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				resp, err := s.noRedirect.Get("https://app.mycompany.test/")
				if err != nil {
					return
				}
				_, _ = io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				record(resp.StatusCode)
			}
		}()
	}

	time.Sleep(250 * time.Millisecond)
	if err := iam.RevokeWithConfig(
		context.Background(), s.mycompanyCfg, "mycompany", sid, uid, time.Hour,
	); err != nil {
		close(stop)
		wg.Wait()
		t.Fatal(err)
	}
	time.Sleep(250 * time.Millisecond)
	close(stop)
	wg.Wait()

	t.Logf("under load: ok=%d refused=%d unexpected=%d",
		ok.Load(), refused.Load(), upstream.Load())
	if ok.Load() == 0 {
		t.Fatal("no request succeeded before revocation")
	}
	if refused.Load() == 0 {
		t.Fatal("revocation not observed under load")
	}
	if upstream.Load() != 0 {
		t.Fatalf("%d unexpected statuses under revocation", upstream.Load())
	}

	// After the load, the session is definitively refused.
	if got := getStatus(t, s.noRedirect, "https://app.mycompany.test/"); got != http.StatusFound &&
		got != http.StatusUnauthorized {
		t.Fatalf("after revocation = %d, want 302/401", got)
	}
}

// TestLoad_KeyRotationOverlap replaces the IAM behind a stable
// public URL with an instance that keeps the old key and adds a new
// one. The old session must stay valid (overlap) and a new login must
// succeed with the new key (JWKS refresh on unknown kid).
func TestLoad_KeyRotationOverlap(t *testing.T) {
	s := newStack(t, stackOptions{mycompanyIAMProxy: true})
	s.setUser("alice@mycompany.test")
	s.login("https://app.mycompany.test/")

	old := s.rpCookie("app.mycompany.test", "gate_one_mycompany")
	if old == nil {
		t.Fatal("no RP cookie after login")
	}
	oldSid, _ := s.rpPayload(old)["sid"].(string)
	if oldSid == "" {
		t.Fatal("old RP payload missing sid")
	}

	// Rotated IAM: keyFiles = [old, new], last key active.
	key2 := filepath.Join(t.TempDir(), "mycompany-2.key")
	if err := writeTestKey(key2); err != nil {
		t.Fatal(err)
	}
	cfg := *s.mycompanyCfg
	cfg.PublicURL = s.iamProxy.URL()
	tenant := cfg.Tenants[0]
	tenant.KeyFiles = []string{s.mycompanyKeyFile, key2}
	cfg.Tenants = []iam.Tenant{tenant}

	b2, srv2, _ := newIAM(t, &cfg)
	b2.SetPublicURL(s.iamProxy.URL())
	s.iamProxy.SetTarget(srv2.URL)

	// Overlap: the old token was signed by key1, which the new JWKS
	// still publishes. Force a full verification (bypass the identity
	// cache).
	proxy.ResetAuthCache()
	if got := getStatus(t, s.noRedirect, "https://app.mycompany.test/"); got != 200 {
		t.Fatalf("old session after rotation = %d, want 200", got)
	}

	// New login goes through the rotated IAM and is signed by key2:
	// Gate One must refresh JWKS (unknown kid) and accept it.
	if _, err := s.follow.Get("https://login.mycompany.test/logout"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond) // sub revocation is per-second
	s.setUser("alice@mycompany.test")
	s.login("https://app.mycompany.test/")

	fresh := s.rpCookie("app.mycompany.test", "gate_one_mycompany")
	if fresh == nil {
		t.Fatal("no RP cookie after rotation login")
	}
	newSid, _ := s.rpPayload(fresh)["sid"].(string)
	if newSid == "" || newSid == oldSid {
		t.Fatalf("sid after rotation = %q (old %q)", newSid, oldSid)
	}

	// Both keys are published during the overlap window.
	resp, err := http.Get(s.iamProxy.URL() + "/t/mycompany/jwks.json")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var jwks struct {
		Keys []struct {
			Kid string `json:"kid"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		t.Fatal(err)
	}
	if len(jwks.Keys) != 2 {
		t.Fatalf("jwks after rotation has %d keys, want 2", len(jwks.Keys))
	}
	t.Logf("rotation OK: overlap accepted, new login sid=%s, %d keys published",
		newSid, len(jwks.Keys))
}

// TestLoad_NoGoroutineLeak runs repeated bursts and checks the gateway
// does not accumulate goroutines (connection/leak regression).
func TestLoad_NoGoroutineLeak(t *testing.T) {
	s := NewStack(t)
	s.setUser("alice@mycompany.test")
	s.login("https://app.mycompany.test/")
	getStatus(t, s.noRedirect, "https://app.mycompany.test/")

	settle := func() int {
		s.noRedirect.CloseIdleConnections()
		s.follow.CloseIdleConnections()
		time.Sleep(500 * time.Millisecond)
		runtime.GC()
		return runtime.NumGoroutine()
	}

	// Warm up once so pools and server loops reach steady state, then
	// measure growth caused by the bursts alone.
	runLoad(t, s.noRedirect, "https://app.mycompany.test/", 8, 20).
		requireAll(t, 200)
	base := settle()

	for i := 0; i < 4; i++ {
		res := runLoad(t, s.noRedirect, "https://app.mycompany.test/", 8, 50)
		res.requireAll(t, 200)
	}
	after := settle()

	t.Logf("goroutines before=%d after=%d", base, after)
	if after > base+25 {
		buf := make([]byte, 1<<16)
		n := runtime.Stack(buf, true)
		t.Fatalf("goroutine leak: %d -> %d\n%s", base, after, buf[:n])
	}
}
