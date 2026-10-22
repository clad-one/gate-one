package proxy

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// stripPrefixBackend echoes what the backend actually received.
func stripPrefixBackend(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"path":  r.URL.Path,
				"query": r.URL.RawQuery,
				"xfp":   r.Header.Get("X-Forwarded-Prefix"),
			})
		}))
	t.Cleanup(srv.Close)
	return srv
}

func TestStripPrefixRequestPath(t *testing.T) {
	srv := stripPrefixBackend(t)
	gw := mustStripPrefixGateway(t, fmt.Sprintf(`{
		"routes": [{
			"host": "public.test", "path": "/api/*",
			"backend": %q, "stripPrefix": "/api"
		}]
	}`, srv.URL))

	cases := []struct {
		path      string
		wantPath  string
		wantQuery string
	}{
		{"/api/foo?x=1", "/foo", "x=1"},
		{"/api/foo/bar", "/foo/bar", ""},
		{"/api", "/", ""},
		{"/api/", "/", ""},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			resp := doGet(t, gw, "public.test", tc.path)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status = %d", resp.StatusCode)
			}
			got := echoOf(t, resp)
			if got["path"] != tc.wantPath {
				t.Errorf("backend path = %q, want %q", got["path"], tc.wantPath)
			}
			if got["query"] != tc.wantQuery {
				t.Errorf("backend query = %q, want %q", got["query"], tc.wantQuery)
			}
			if got["xfp"] != "/api" {
				t.Errorf("X-Forwarded-Prefix = %q, want /api", got["xfp"])
			}
		})
	}

	// Segment boundary and route-path selection: /apix must not be
	// silently stripped to /x.
	for _, path := range []string{"/apix", "/other"} {
		resp := doGet(t, gw, "public.test", path)
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s: status = %d, want 404", path, resp.StatusCode)
		}
	}
}

func TestStripPrefixWithBackendBasePath(t *testing.T) {
	srv := stripPrefixBackend(t)
	backend := srv.URL + "/v1"
	gw := mustStripPrefixGateway(t, fmt.Sprintf(`{
		"routes": [{
			"host": "public.test", "path": "/api/*",
			"backend": %q, "stripPrefix": "/api"
		}]
	}`, backend))

	resp := doGet(t, gw, "public.test", "/api/foo")
	got := echoOf(t, resp)
	if got["path"] != "/v1/foo" {
		t.Errorf("backend path = %q, want /v1/foo", got["path"])
	}

	resp = doGet(t, gw, "public.test", "/api")
	got = echoOf(t, resp)
	if got["path"] != "/v1/" {
		t.Errorf("bare prefix: backend path = %q, want /v1/", got["path"])
	}
}

func TestStripPrefixDoesNotOverwriteIngressPrefix(t *testing.T) {
	srv := stripPrefixBackend(t)
	gw := mustStripPrefixGateway(t, fmt.Sprintf(`{
		"routes": [{
			"host": "public.test", "path": "/api/*",
			"backend": %q, "stripPrefix": "/api"
		}]
	}`, srv.URL))

	resp := doRequestWithHeaders(
		t, gw, "public.test", "/api/foo",
		map[string]string{"X-Forwarded-Prefix": "/edge"})
	got := echoOf(t, resp)
	if got["xfp"] != "/edge" {
		t.Errorf("X-Forwarded-Prefix = %q, want /edge", got["xfp"])
	}
}

func mustStripPrefixGateway(t *testing.T, routesJSON string) *Gateway {
	t.Helper()
	cfg := loadForTest(t, routesJSON)
	gw, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return gw
}
