// Package identityadapter defines the broker-side contract for one
// identity protocol (OIDC first, then SAML/LDAP/mTLS/API key).
//
// The contract is deliberately state-machine oriented: an adapter can
// redirect (OIDC/SAML), challenge (mTLS/API key), show a form (LDAP),
// or return an assertion directly. The broker, never the adapter,
// decides roles, tenant, audiences and token issuance.
package identityadapter

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
)

// Manifest describes an adapter for the broker registry and, later,
// for signed out-of-process plugins.
type Manifest struct {
	Name         string          `json:"name"`
	Version      string          `json:"version"`
	APIVersion   string          `json:"apiVersion"`
	HostAPI      string          `json:"hostAPI"`
	Publisher    string          `json:"publisher,omitempty"`
	KeyID        string          `json:"keyId,omitempty"`
	Capabilities Capabilities    `json:"capabilities"`
	ConfigSchema json.RawMessage `json:"configSchema,omitempty"`
}

// Capabilities declares the steps an adapter can produce. The broker
// refuses a step the adapter did not declare.
type Capabilities struct {
	Redirect   bool `json:"redirect,omitempty"`
	Challenge  bool `json:"challenge,omitempty"`
	Form       bool `json:"form,omitempty"`
	Enrichment bool `json:"enrichment,omitempty"`
}

// Request is the normalized input of Start/Continue. It contains no
// broker policy and no destination authorization decision.
type Request struct {
	Tenant     string
	Method     string
	URL        string
	RemoteAddr string
	Header     http.Header
	Body       []byte
	Params     map[string]string
	State      []byte
}

// StepKind is the next action the broker must perform.
type StepKind string

const (
	StepRedirect  StepKind = "redirect"
	StepChallenge StepKind = "challenge"
	StepForm      StepKind = "form"
	StepResult    StepKind = "result"
)

// Step is one transition of the state machine.
type Step struct {
	Kind        StepKind
	RedirectURL string
	Challenge   string
	Fields      []Field
	Assertion   *Assertion
	State       []byte
}

// Field is one form field for a StepForm.
type Field struct {
	Name     string `json:"name"`
	Label    string `json:"label"`
	Type     string `json:"type"`
	Required bool   `json:"required,omitempty"`
}

// Assertion is the raw identity fact set returned by an adapter. It
// intentionally has no roles, tenant, audience or scope: the broker
// maps facts to policy.
type Assertion struct {
	Subject    string         `json:"subject"`
	Username   string         `json:"username,omitempty"`
	Email      string         `json:"email,omitempty"`
	Groups     []string       `json:"groups,omitempty"`
	Claims     map[string]any `json:"claims,omitempty"`
	TenantHint string         `json:"tenantHint,omitempty"`
}

// Adapter is the single contract implemented by every identity
// protocol, built-in or out-of-process.
type Adapter interface {
	Manifest() Manifest
	Start(ctx context.Context, req Request) (Step, error)
	Continue(ctx context.Context, req Request, state []byte) (Step, error)
	Enrich(ctx context.Context, a Assertion) (Assertion, error)
	Health(ctx context.Context) error
}

// Classified errors: the broker maps them to HTTP answers without
// conflating invalid credentials with an unavailable upstream.
var (
	// ErrUnauthenticated: the credentials are absent or invalid.
	ErrUnauthenticated = errors.New("identityadapter: unauthenticated")

	// ErrInvalidRequest: malformed callback, state, redirect URI...
	ErrInvalidRequest = errors.New("identityadapter: invalid request")

	// ErrProviderUnavailable: upstream IdP unreachable, timeout, TLS,
	// malformed discovery/JWKS. Never a credential failure.
	ErrProviderUnavailable = errors.New("identityadapter: provider unavailable")
)
