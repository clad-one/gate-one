// Package authn defines the authentication-provider abstraction used
// by Gate One.
//
// The gateway never implements an identity provider itself: it asks a
// Provider to verify an incoming request and to expose a login URL.
// The provider can be:
//
//   - dev:  the embedded development IdP (loopback only, onboarding);
//   - http: any external service implementing the Gate One auth
//     contract (auth-bridge/Keycloak, or a custom adapter);
//   - oidc: a native OpenID Connect Relying Party (same contract,
//     no external bridge).
//
// Keeping the three implementations behind one interface is what
// makes auth-bridge optional: removing it is a configuration choice,
// not a rewrite of the gateway.
package authn

import (
	"context"
	"errors"
	"net/http"
	"time"
)

// Identity is the authenticated user, normalized across providers.
// Header/claim details stay in Claims.
type Identity struct {
	UserID    string
	SessionID string
	// IssuedAt is the token/session issue time (iat), used by subject
	// revocation: a global logout revokes sessions issued before it,
	// without blocking a new login.
	IssuedAt time.Time
	Username string
	Email    string
	Roles    []string
	Scopes   []string
	Claims   map[string]any
}

// Result is the outcome of a successful verification. SetCookies
// carries the raw Set-Cookie header values of any session refresh
// issued by the provider (auth-bridge can silently refresh an access
// token); the gateway relays them to the browser verbatim.
type Result struct {
	Identity
	SetCookies []string
}

// Classified errors: the proxy maps them to the right HTTP answer
// instead of turning every failure into a login redirect.
var (
	// ErrUnauthenticated: no valid session / token. The proxy answers
	// 401 (API/JSON) or redirects a navigation to the login page.
	ErrUnauthenticated = errors.New("authn: unauthenticated")

	// ErrInsufficientScope: the caller is authenticated but lacks the
	// required MCP scope. The proxy answers 403 with the MCP challenge.
	ErrInsufficientScope = errors.New("authn: insufficient scope")

	// ErrProviderUnavailable: the provider itself is unreachable or
	// broken. The proxy answers 502 and NEVER redirects to a login
	// (a login page would not fix a down provider and would loop).
	ErrProviderUnavailable = errors.New("authn: provider unavailable")
)

// Provider verifies requests and describes where a browser must log
// in. LoginURL is the page the guard/proxy redirects to; the external
// contract appends "?returnTo=...".
type Provider interface {
	// Name identifies the implementation (cache key, logs, doctor).
	Name() string

	// Issuer is the OIDC issuer advertised in MCP protected-resource
	// metadata. Empty when the provider has no OAuth/OIDC issuer.
	Issuer() string

	// Verify authenticates a browser/API request (cookies or Bearer).
	Verify(ctx context.Context, r *http.Request) (*Result, error)

	// VerifyMCP authenticates an MCP Bearer token and enforces the
	// required scope (and resource/audience when the provider supports
	// it). It never writes a response: the proxy owns the challenge.
	VerifyMCP(
		ctx context.Context,
		r *http.Request,
		scope, resource string,
	) (*Result, error)

	// CheckRevoked is consulted before reusing a cached identity: a
	// back-channel logout may have revoked a session while its
	// identity was still in the gateway cache. Providers that do not
	// own revocation state (dev, external http) return false.
	CheckRevoked(ctx context.Context, id Identity) (bool, error)

	// LoginURL is the absolute login page. Empty when the provider
	// cannot offer a browser login (an authenticated request then
	// fails at startup, not at runtime).
	LoginURL() string

	// Health probes the provider. A local provider returns nil.
	Health(ctx context.Context) error
}

// LoginHandler is implemented by providers that HOST their login
// surface (dev, native OIDC). The gateway routes the configured login
// host to this handler before any application route.
type LoginHandler interface {
	// LoginHost is the hostname served by this handler (no port).
	LoginHost() string
	// ServeLogin handles /login, /logout, /auth/popup-done, /health.
	ServeLogin(w http.ResponseWriter, r *http.Request)
}

// AuthEvent is a security-relevant authentication lifecycle event
// emitted by a login handler. It carries the identity needed for an
// audit record; the usage sink must pseudonymize the user and must not
// persist the email/username.
type AuthEvent struct {
	Action    string // login | login_failed | logout | backchannel_logout
	Result    string // ok | failed | denied | no_session
	Provider  string
	Issuer    string
	UserID    string
	Username  string
	Email     string
	SessionID string
	At        time.Time
}

// EventSink receives auth lifecycle events. An error from the sink is
// only honoured by a successful login (fail-closed: no session without
// an audit record); logout/backchannel paths log and continue.
type EventSink func(AuthEvent) error
