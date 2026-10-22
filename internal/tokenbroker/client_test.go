package tokenbroker

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestTokenSuccess(t *testing.T) {
	var gotSecret, gotUser, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			gotSecret = r.Header.Get("X-Broker-Secret")
			gotUser = r.Header.Get("X-User-Id")
			gotPath = r.URL.Path
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{
				"provider":"github",
				"access_token":"gh-token",
				"token_type":"bearer",
				"expires_at":1234,
				"scopes":["repo:read"]
			}`))
		},
	))
	defer srv.Close()

	c, err := New(srv.URL, "broker-secret")
	if err != nil {
		t.Fatal(err)
	}

	tok, err := c.Token(context.Background(), "user-1", "github")
	if err != nil {
		t.Fatal(err)
	}
	if gotSecret != "broker-secret" || gotUser != "user-1" {
		t.Fatalf("headers: secret=%q user=%q", gotSecret, gotUser)
	}
	if gotPath != "/token/github" {
		t.Fatalf("path = %q", gotPath)
	}
	if tok.AccessToken != "gh-token" || tok.Provider != "github" {
		t.Fatalf("token = %+v", tok)
	}
	if tok.ExpiresAt == nil || *tok.ExpiresAt != 1234 {
		t.Fatalf("expires_at = %v", tok.ExpiresAt)
	}
}

func TestTokenErrors(t *testing.T) {
	cases := []struct {
		name       string
		status     int
		body       string
		wantKind   ErrorKind
		wantStatus int
		connect    string
	}{
		{
			name:       "not connected",
			status:     http.StatusNotFound,
			body:       `{"error":"not_connected","provider":"github","connect_url":"https://login.test/connect/github"}`,
			wantKind:   KindNotConnected,
			wantStatus: http.StatusNotFound,
			connect:    "https://login.test/connect/github",
		},
		{
			name:       "reauth",
			status:     http.StatusConflict,
			body:       `{"error":"reauthorization_required","connect_url":"https://login.test/connect/github"}`,
			wantKind:   KindReauthorizationRequired,
			wantStatus: http.StatusConflict,
			connect:    "https://login.test/connect/github",
		},
		{
			name:       "unknown provider",
			status:     http.StatusNotFound,
			body:       `{"error":"unknown_provider"}`,
			wantKind:   KindUnknownProvider,
			wantStatus: http.StatusNotFound,
		},
		{
			name:       "upstream",
			status:     http.StatusBadGateway,
			body:       `{"error":"upstream_unavailable"}`,
			wantKind:   KindUpstreamUnavailable,
			wantStatus: http.StatusBadGateway,
		},
		{
			name:       "broker secret",
			status:     http.StatusUnauthorized,
			body:       `{"error":"unauthorized"}`,
			wantKind:   KindUnauthorized,
			wantStatus: http.StatusUnauthorized,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(
				func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(tc.status)
					_, _ = w.Write([]byte(tc.body))
				},
			))
			defer srv.Close()

			c, err := New(srv.URL, "secret")
			if err != nil {
				t.Fatal(err)
			}
			_, err = c.Token(context.Background(), "u", "github")
			if err == nil {
				t.Fatal("expected error")
			}
			if got := KindOf(err); got != tc.wantKind {
				t.Fatalf("kind = %q, want %q (err=%v)", got, tc.wantKind, err)
			}
			e, ok := err.(*Error)
			if !ok {
				t.Fatalf("error type = %T", err)
			}
			if e.Status != tc.wantStatus {
				t.Fatalf("status = %d, want %d", e.Status, tc.wantStatus)
			}
			if e.ConnectURL != tc.connect {
				t.Fatalf("connect = %q, want %q", e.ConnectURL, tc.connect)
			}
		})
	}
}

func TestTokenInvalidResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"access_token":""}`))
		},
	))
	defer srv.Close()

	c, _ := New(srv.URL, "secret")
	_, err := c.Token(context.Background(), "u", "github")
	if got := KindOf(err); got != KindInvalidResponse {
		t.Fatalf("kind = %q, err=%v", got, err)
	}
}

func TestProviders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/providers" {
				t.Errorf("path = %q", r.URL.Path)
			}
			if r.Header.Get("X-Broker-Secret") != "secret" {
				t.Errorf("missing broker secret")
			}
			if r.Header.Get("X-User-Id") != "" {
				t.Errorf("provider list must not carry a user")
			}
			_, _ = w.Write([]byte(`{"providers":[
				{"name":"github","display_name":"GitHub","connected":false}
			]}`))
		},
	))
	defer srv.Close()

	c, _ := New(srv.URL, "secret")
	providers, err := c.Providers(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(providers) != 1 || providers[0].Name != "github" {
		t.Fatalf("providers = %+v", providers)
	}
}

func TestProvidersRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
		},
	))
	defer srv.Close()

	c, _ := New(srv.URL, "wrong")
	_, err := c.Providers(context.Background())
	if got := KindOf(err); got != KindUnauthorized {
		t.Fatalf("kind = %q, err=%v", got, err)
	}
}

func TestNewValidation(t *testing.T) {
	if _, err := New("", "secret"); err == nil {
		t.Fatal("empty URL accepted")
	}
	if _, err := New("ftp://broker", "secret"); err == nil {
		t.Fatal("bad scheme accepted")
	}
	if _, err := New("http://broker", ""); err == nil {
		t.Fatal("empty secret accepted")
	}
}

func TestTokenPathEscaped(t *testing.T) {
	var path string
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			path = r.URL.EscapedPath()
			_, _ = w.Write([]byte(`{"access_token":"x"}`))
		},
	))
	defer srv.Close()

	c, _ := New(srv.URL, "secret")
	_, err := c.Token(context.Background(), "u", "git hub")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(path, "/token/git%20hub") {
		t.Fatalf("path = %q", path)
	}
}
