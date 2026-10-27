package proxy

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"cladone/gate-one/internal/authn"
)

// fakeRevokeProvider lets us exercise the cache/revocation ordering
// without a real IdP.
type fakeRevokeProvider struct {
	revoked bool
	err     error
	verify  int
	checks  int
}

func (p *fakeRevokeProvider) Name() string   { return "fake" }
func (p *fakeRevokeProvider) Issuer() string { return "" }
func (p *fakeRevokeProvider) LoginURL() string {
	return "https://login.test/login"
}
func (p *fakeRevokeProvider) Health(context.Context) error { return nil }
func (p *fakeRevokeProvider) Verify(
	context.Context, *http.Request,
) (*authn.Result, error) {
	p.verify++
	return &authn.Result{Identity: authn.Identity{
		UserID: "user-1", Username: "alice",
	}}, nil
}
func (p *fakeRevokeProvider) VerifyMCP(
	context.Context, *http.Request, string, string,
) (*authn.Result, error) {
	return nil, authn.ErrUnauthenticated
}
func (p *fakeRevokeProvider) CheckRevoked(
	context.Context, authn.Identity,
) (bool, error) {
	p.checks++
	return p.revoked, p.err
}

func TestAuthCacheChecksRevocationBeforeHit(t *testing.T) {
	clearAuthCache()
	t.Cleanup(clearAuthCache)

	gw := &Gateway{}
	p := &fakeRevokeProvider{}
	gw.auth = p

	req := httptest.NewRequest(http.MethodGet, "http://app.test/", nil)
	req.Header.Set("Cookie", "session=abc")
	rec := httptest.NewRecorder()

	if _, err := gw.checkAuth(
		rec, req, &RequestContext{Host: "app.test", Path: "/"},
	); err != nil {
		t.Fatalf("first auth: %v", err)
	}
	if p.verify != 1 {
		t.Fatalf("Verify calls = %d, want 1", p.verify)
	}

	// Cached identity, but the session is now revoked: the cache must
	// not be trusted.
	p.revoked = true
	_, err := gw.checkAuth(
		rec, req, &RequestContext{Host: "app.test", Path: "/"},
	)
	if !errors.Is(err, authn.ErrUnauthenticated) {
		t.Fatalf("cached revoked auth = %v, want ErrUnauthenticated", err)
	}
	if p.verify != 1 {
		t.Errorf("Verify calls = %d, want 1 (cache hit)", p.verify)
	}
	if p.checks != 1 {
		t.Errorf("CheckRevoked calls = %d, want 1", p.checks)
	}
}

func TestAuthCacheRevocationStoreErrorIsFailClosed(t *testing.T) {
	clearAuthCache()
	t.Cleanup(clearAuthCache)

	gw := &Gateway{}
	p := &fakeRevokeProvider{}
	gw.auth = p

	req := httptest.NewRequest(http.MethodGet, "http://app.test/", nil)
	req.Header.Set("Cookie", "session=abc")
	rec := httptest.NewRecorder()
	if _, err := gw.checkAuth(
		rec, req, &RequestContext{Host: "app.test", Path: "/"},
	); err != nil {
		t.Fatal(err)
	}

	p.err = errors.New("store down")
	_, err := gw.checkAuth(
		rec, req, &RequestContext{Host: "app.test", Path: "/"},
	)
	if !errors.Is(err, authn.ErrProviderUnavailable) {
		t.Fatalf("store error = %v, want ErrProviderUnavailable", err)
	}
}
