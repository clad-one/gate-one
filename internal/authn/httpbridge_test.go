package authn

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHTTPBridgeStatusClassification(t *testing.T) {
	status := http.StatusOK
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/auth/mcp" {
				w.WriteHeader(status)
				return
			}
			if status == http.StatusOK {
				w.Header().Set("X-User-Id", "u-1")
				w.Header().Set("X-Username", "alice")
				w.Header().Set("X-Roles", "user,admin")
				w.Header().Set("X-Scopes", "profile,mcp-tools")
				w.Header().Add("Set-Cookie", "access_token=abc; Path=/")
			}
			w.WriteHeader(status)
		},
	))
	t.Cleanup(srv.Close)

	p, err := NewHTTP(HTTPConfig{
		BaseURL:       srv.URL,
		LoginURLValue: srv.URL + "/login",
	})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "http://app.test/", nil)

	// 200: identity + Set-Cookie propagation.
	status = http.StatusOK
	res, err := p.Verify(context.Background(), req)
	if err != nil {
		t.Fatalf("200: %v", err)
	}
	if res.UserID != "u-1" || res.Username != "alice" {
		t.Errorf("identity = %+v", res.Identity)
	}
	if len(res.SetCookies) != 1 ||
		res.SetCookies[0] != "access_token=abc; Path=/" {
		t.Errorf("cookies = %v", res.SetCookies)
	}

	// 302 from auth-bridge = no session, NOT an outage.
	status = http.StatusFound
	if _, err := p.Verify(
		context.Background(), req,
	); !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("302 = %v, want ErrUnauthenticated", err)
	}

	// 401/403 = unauthenticated.
	for _, code := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		status = code
		if _, err := p.Verify(
			context.Background(), req,
		); !errors.Is(err, ErrUnauthenticated) {
			t.Errorf("%d = %v, want ErrUnauthenticated", code, err)
		}
	}

	// 5xx = outage.
	status = http.StatusInternalServerError
	if _, err := p.Verify(
		context.Background(), req,
	); !errors.Is(err, ErrProviderUnavailable) {
		t.Errorf("500 = %v, want ErrProviderUnavailable", err)
	}
}

func TestHTTPBridgeMCPStatus(t *testing.T) {
	status := http.StatusOK
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if status == http.StatusOK {
				w.Header().Set("X-User-Id", "u-1")
				w.Header().Set("X-Roles", "admin")
			}
			w.WriteHeader(status)
		},
	))
	t.Cleanup(srv.Close)

	p, err := NewHTTP(HTTPConfig{BaseURL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "http://mcp.test/mcp", nil)

	status = http.StatusOK
	if _, err := p.VerifyMCP(
		context.Background(), req, "mcp-tools", "",
	); err != nil {
		t.Fatalf("200: %v", err)
	}

	status = http.StatusUnauthorized
	if _, err := p.VerifyMCP(
		context.Background(), req, "mcp-tools", "",
	); !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("401 = %v", err)
	}

	status = http.StatusForbidden
	if _, err := p.VerifyMCP(
		context.Background(), req, "mcp-tools", "",
	); !errors.Is(err, ErrInsufficientScope) {
		t.Errorf("403 = %v", err)
	}

	status = http.StatusBadGateway
	if _, err := p.VerifyMCP(
		context.Background(), req, "mcp-tools", "",
	); !errors.Is(err, ErrProviderUnavailable) {
		t.Errorf("502 = %v", err)
	}
}
