package authn

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// HeaderNames maps the Gate One auth contract to the actual response
// headers of an external provider. Defaults are the auth-bridge /
// Keycloak names; another forward-auth service can override them
// without a code change.
type HeaderNames struct {
	UserID   string
	Username string
	Email    string
	Roles    string
	Scopes   string
	Claims   string
}

func (h HeaderNames) withDefaults() HeaderNames {
	if h.UserID == "" {
		h.UserID = "X-User-Id"
	}
	if h.Username == "" {
		h.Username = "X-Username"
	}
	if h.Email == "" {
		h.Email = "X-Email"
	}
	if h.Roles == "" {
		h.Roles = "X-Roles"
	}
	if h.Scopes == "" {
		h.Scopes = "X-Scopes"
	}
	if h.Claims == "" {
		h.Claims = "X-Claims"
	}
	return h
}

// HTTPConfig configures the external-provider adapter.
type HTTPConfig struct {
	// BaseURL is the service root; endpoints are derived from it.
	BaseURL string

	// Explicit endpoint overrides (default: BaseURL + /auth,
	// /auth/mcp, /health).
	VerifyURL    string
	MCPVerifyURL string
	HealthURL    string

	// LoginURLValue is the browser login page (auth-bridge: /login).
	// Empty = no browser login (MCP-only provider).
	LoginURLValue string

	// Issuer is advertised in MCP metadata.
	IssuerValue string

	// Headers maps the identity response headers.
	Headers HeaderNames

	// Client overrides the HTTP client (tests, custom transport).
	Client *http.Client
}

// HTTP is the adapter for any service speaking the Gate One auth
// contract over HTTP (auth-bridge is the reference implementation;
// a non-conforming service needs an adapter).
type HTTP struct {
	baseURL      string
	verifyURL    string
	mcpVerifyURL string
	healthURL    string
	loginURL     string
	issuer       string
	headers      HeaderNames
	client       *http.Client
}

// NewHTTP validates and builds the adapter.
func NewHTTP(cfg HTTPConfig) (*HTTP, error) {
	base := strings.TrimRight(strings.TrimSpace(cfg.BaseURL), "/")
	if base == "" {
		return nil, fmt.Errorf("authProvider: baseUrl is required for type http")
	}
	u, err := url.Parse(base)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("authProvider.baseUrl %q: invalid URL", cfg.BaseURL)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf(
			"authProvider.baseUrl %q: scheme must be http or https", cfg.BaseURL)
	}

	h := &HTTP{
		baseURL:      base,
		verifyURL:    strings.TrimSpace(cfg.VerifyURL),
		mcpVerifyURL: strings.TrimSpace(cfg.MCPVerifyURL),
		healthURL:    strings.TrimSpace(cfg.HealthURL),
		loginURL:     strings.TrimSpace(cfg.LoginURLValue),
		issuer:       strings.TrimSpace(cfg.IssuerValue),
		headers:      cfg.Headers.withDefaults(),
		client:       cfg.Client,
	}
	if h.verifyURL == "" {
		h.verifyURL = base + "/auth"
	}
	if h.mcpVerifyURL == "" {
		h.mcpVerifyURL = base + "/auth/mcp"
	}
	if h.healthURL == "" {
		h.healthURL = base + "/health"
	}
	if h.client == nil {
		h.client = &http.Client{Timeout: 5 * time.Second}
	}
	return h, nil
}

func (h *HTTP) Name() string   { return "http" }
func (h *HTTP) Issuer() string { return h.issuer }
func (h *HTTP) LoginURL() string {
	return h.loginURL
}

// CheckRevoked implements Provider. Auth-bridge owns its revocation
// state; the gateway cannot see it (its 30s identity cache is the
// documented window).
func (h *HTTP) CheckRevoked(context.Context, Identity) (bool, error) {
	return false, nil
}

// Verify implements Provider.
func (h *HTTP) Verify(
	ctx context.Context,
	r *http.Request,
) (*Result, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.verifyURL, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrProviderUnavailable, err)
	}
	if auth := r.Header.Get("Authorization"); auth != "" {
		req.Header.Set("Authorization", auth)
	}
	for _, c := range r.Cookies() {
		req.AddCookie(c)
	}
	req.Header.Set("X-Forwarded-Host", r.Host)
	req.Header.Set("X-Forwarded-Uri", r.RequestURI)
	req.Header.Set("X-Forwarded-Method", r.Method)

	resp, err := h.client.Do(req)
	if err != nil {
		log.Printf("AUTH PROVIDER %s unreachable: %v", h.verifyURL, err)
		return nil, fmt.Errorf("%w: %v", ErrProviderUnavailable, err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))

	res := &Result{
		Identity:   h.identity(resp.Header),
		SetCookies: append([]string(nil), resp.Header["Set-Cookie"]...),
	}

	switch resp.StatusCode {
	case http.StatusOK:
		return res, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		// The provider may still have refreshed cookies on a 401;
		// hand them back so the browser can retry.
		return res, ErrUnauthenticated
	}
	// auth-bridge redirects to /login when there is no session: a
	// 3xx on /auth is an authentication failure, NOT an outage. The
	// client has CheckRedirect=ErrUseLastResponse, so the 302 is
	// visible here instead of being followed.
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return res, ErrUnauthenticated
	}
	log.Printf(
		"AUTH PROVIDER %s: unexpected status %d",
		h.verifyURL, resp.StatusCode)
	return nil, fmt.Errorf(
		"%w: status %d", ErrProviderUnavailable, resp.StatusCode)
}

// VerifyMCP implements Provider.
func (h *HTTP) VerifyMCP(
	ctx context.Context,
	r *http.Request,
	scope, resource string,
) (*Result, error) {
	req, err := http.NewRequestWithContext(
		ctx, http.MethodGet, h.mcpVerifyURL, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrProviderUnavailable, err)
	}
	if auth := r.Header.Get("Authorization"); auth != "" {
		req.Header.Set("Authorization", auth)
	}
	// Internal headers: built here, never copied from the client.
	req.Header.Set("X-MCP-Scope", scope)
	if resource != "" {
		req.Header.Set("X-MCP-Resource", resource)
	}

	resp, err := h.client.Do(req)
	if err != nil {
		log.Printf("MCP AUTH PROVIDER %s unreachable: %v", h.mcpVerifyURL, err)
		return nil, fmt.Errorf("%w: %v", ErrProviderUnavailable, err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))

	switch resp.StatusCode {
	case http.StatusOK:
		return &Result{Identity: h.identity(resp.Header)}, nil
	case http.StatusUnauthorized:
		return nil, ErrUnauthenticated
	case http.StatusForbidden:
		return nil, ErrInsufficientScope
	default:
		log.Printf(
			"MCP AUTH PROVIDER %s: unexpected status %d",
			h.mcpVerifyURL, resp.StatusCode)
		return nil, fmt.Errorf(
			"%w: status %d", ErrProviderUnavailable, resp.StatusCode)
	}
}

// Health implements Provider.
func (h *HTTP) Health(ctx context.Context) error {
	req, err := http.NewRequestWithContext(
		ctx, http.MethodGet, h.healthURL, nil)
	if err != nil {
		return err
	}
	resp, err := h.client.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrProviderUnavailable, err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf(
			"%w: health status %d", ErrProviderUnavailable, resp.StatusCode)
	}
	return nil
}

func (h *HTTP) identity(header http.Header) Identity {
	id := Identity{
		UserID:   header.Get(h.headers.UserID),
		Username: header.Get(h.headers.Username),
		Email:    header.Get(h.headers.Email),
		Roles:    splitList(header.Get(h.headers.Roles)),
		Scopes:   splitList(header.Get(h.headers.Scopes)),
	}
	if raw := header.Get(h.headers.Claims); raw != "" {
		if decoded, err := base64.StdEncoding.DecodeString(raw); err == nil {
			var claims map[string]any
			if json.Unmarshal(decoded, &claims) == nil {
				id.Claims = claims
			} else {
				log.Printf("AUTH PROVIDER: unreadable claims header")
			}
		} else {
			log.Printf("AUTH PROVIDER: non-base64 claims header")
		}
	}
	return id
}

func splitList(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
