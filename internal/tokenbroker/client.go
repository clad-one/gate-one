// Package tokenbroker is a small client for the per-user token
// broker. Gate One never sees provider client secrets: it only asks
// the broker, for one authenticated user, the access token of a
// provider declared in the route configuration.
//
// The broker is an internal service (no public route): the shared
// secret and the user id travel in headers, the response only
// contains the short-lived access token. Tokens are deliberately
// never logged here.
package tokenbroker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	// maxResponse bounds a broker response: a broken service must
	// not exhaust the gateway's memory.
	maxResponse = 1 << 20

	// defaultTimeout bounds one broker call. Token refreshes happen
	// in the broker (single-flight); the gateway must not freeze a
	// request for longer than a browser will wait.
	defaultTimeout = 5 * time.Second
)

// ErrorKind classifies a broker failure so callers can choose the
// right HTTP answer (connect invitation, reauthorization, 502…).
type ErrorKind string

const (
	KindNotConnected            ErrorKind = "not_connected"
	KindReauthorizationRequired ErrorKind = "reauthorization_required"
	KindUnknownProvider         ErrorKind = "unknown_provider"
	KindUnauthorized            ErrorKind = "unauthorized"
	KindUpstreamUnavailable     ErrorKind = "upstream_unavailable"
	KindUnavailable             ErrorKind = "unavailable"
	KindInvalidResponse         ErrorKind = "invalid_response"
)

// Error is a classified broker failure. The token itself is never
// carried in an error.
type Error struct {
	Kind       ErrorKind
	Status     int
	Provider   string
	ConnectURL string
	Message    string
}

func (e *Error) Error() string {
	if e == nil {
		return "<nil>"
	}
	if e.Status != 0 {
		return fmt.Sprintf("token broker: %s (HTTP %d): %s",
			e.Kind, e.Status, e.Message)
	}
	return fmt.Sprintf("token broker: %s: %s", e.Kind, e.Message)
}

// KindOf extracts the classification of a broker error.
func KindOf(err error) ErrorKind {
	var e *Error
	if errors.As(err, &e) {
		return e.Kind
	}
	return ""
}

// Token is the broker's /token answer.
type Token struct {
	Provider    string   `json:"provider"`
	AccessToken string   `json:"access_token"`
	TokenType   string   `json:"token_type"`
	ExpiresAt   *int64   `json:"expires_at"`
	Scopes      []string `json:"scopes"`
}

// Provider is one entry of the broker's /providers answer. Used at
// load time to reject a route referencing an unknown (or disabled)
// provider.
type Provider struct {
	Name             string   `json:"name"`
	DisplayName      string   `json:"display_name"`
	Scopes           []string `json:"scopes"`
	Connected        bool     `json:"connected"`
	ExpiresAt        *int64   `json:"expires_at"`
	RefreshExpiresAt *int64   `json:"refresh_expires_at"`
	HasRefreshToken  bool     `json:"has_refresh_token"`
	ReauthRequired   bool     `json:"reauth_required"`
	ConnectURL       string   `json:"connect_url"`
}

// Client calls the broker's internal API.
type Client struct {
	baseURL string
	secret  string
	http    *http.Client
}

// Option customizes a Client (tests).
type Option func(*Client)

// WithHTTPClient replaces the HTTP client (tests, custom transport).
func WithHTTPClient(h *http.Client) Option {
	return func(c *Client) {
		if h != nil {
			c.http = h
		}
	}
}

// New builds a client for baseURL. secret is the shared secret
// configured on both sides (X-Broker-Secret).
func New(baseURL, secret string, opts ...Option) (*Client, error) {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if baseURL == "" {
		return nil, fmt.Errorf("token broker: empty URL")
	}
	u, err := url.Parse(baseURL)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("token broker: invalid URL %q", baseURL)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("token broker: URL scheme %q (expected http or https)", u.Scheme)
	}
	if secret == "" {
		return nil, fmt.Errorf("token broker: empty shared secret")
	}

	c := &Client{
		baseURL: baseURL,
		secret:  secret,
		http: &http.Client{
			Timeout: defaultTimeout,
		},
	}
	for _, opt := range opts {
		opt(c)
	}
	return c, nil
}

// Token fetches the current access token of provider for userID.
// A missing/expired connection is returned as a classified *Error
// carrying the broker's connect URL.
func (c *Client) Token(
	ctx context.Context,
	userID, provider string,
) (*Token, error) {
	if strings.TrimSpace(userID) == "" {
		return nil, &Error{
			Kind:    KindUnauthorized,
			Message: "empty user id",
		}
	}
	if strings.TrimSpace(provider) == "" {
		return nil, &Error{
			Kind:     KindUnknownProvider,
			Provider: provider,
			Message:  "empty provider",
		}
	}

	u := c.baseURL + "/token/" + url.PathEscape(provider)
	status, body, err := c.get(ctx, u, userID)
	if err != nil {
		return nil, err
	}

	if status == http.StatusOK {
		var tok Token
		if err := json.Unmarshal(body, &tok); err != nil {
			return nil, &Error{
				Kind:     KindInvalidResponse,
				Status:   status,
				Provider: provider,
				Message:  "invalid JSON",
			}
		}
		if tok.AccessToken == "" {
			return nil, &Error{
				Kind:     KindInvalidResponse,
				Status:   status,
				Provider: provider,
				Message:  "empty access token",
			}
		}
		if tok.Provider == "" {
			tok.Provider = provider
		}
		return &tok, nil
	}

	var apiErr struct {
		Error      string `json:"error"`
		Provider   string `json:"provider"`
		ConnectURL string `json:"connect_url"`
	}
	_ = json.Unmarshal(body, &apiErr)

	e := &Error{
		Status:     status,
		Provider:   provider,
		ConnectURL: apiErr.ConnectURL,
		Message:    apiErr.Error,
	}
	if e.Message == "" {
		e.Message = http.StatusText(status)
	}

	switch status {
	case http.StatusNotFound:
		if apiErr.Error == string(KindUnknownProvider) {
			e.Kind = KindUnknownProvider
		} else {
			e.Kind = KindNotConnected
		}
	case http.StatusConflict:
		e.Kind = KindReauthorizationRequired
	case http.StatusUnauthorized:
		e.Kind = KindUnauthorized
	case http.StatusBadGateway:
		e.Kind = KindUpstreamUnavailable
	default:
		e.Kind = KindUnavailable
	}
	return nil, e
}

// Providers lists the enabled providers known by the broker. It is
// called at startup to validate the provider names referenced by
// delegated routes.
func (c *Client) Providers(ctx context.Context) ([]Provider, error) {
	status, body, err := c.get(ctx, c.baseURL+"/providers", "")
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		e := &Error{
			Kind:    KindUnavailable,
			Status:  status,
			Message: "provider list refused",
		}
		if status == http.StatusUnauthorized {
			e.Kind = KindUnauthorized
			e.Message = "invalid broker secret"
		}
		return nil, e
	}

	var out struct {
		Providers []Provider `json:"providers"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, &Error{
			Kind:    KindInvalidResponse,
			Status:  status,
			Message: "invalid JSON",
		}
	}
	return out.Providers, nil
}

func (c *Client) get(
	ctx context.Context,
	rawURL, userID string,
) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return 0, nil, &Error{
			Kind:    KindUnavailable,
			Message: "build request",
		}
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Broker-Secret", c.secret)
	if userID != "" {
		req.Header.Set("X-User-Id", userID)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return 0, nil, &Error{
			Kind:    KindUnavailable,
			Message: "service unreachable",
		}
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse+1))
	if err != nil {
		return 0, nil, &Error{
			Kind:    KindUnavailable,
			Status:  resp.StatusCode,
			Message: "read response",
		}
	}
	if len(body) > maxResponse {
		return 0, nil, &Error{
			Kind:    KindInvalidResponse,
			Status:  resp.StatusCode,
			Message: "response too large",
		}
	}
	return resp.StatusCode, body, nil
}
