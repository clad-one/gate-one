package iam

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"cladone/gate-one/pkg/identityadapter"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// oidcAdapter is the IAM's built-in Google adapter. It implements
// the same IdentityAdapter contract exposed to out-of-process plugins:
// the IAM policy layer only consumes Assertion facts.
type oidcAdapter struct {
	issuer     string
	idp        string
	display    string
	tenantID   string
	publicURL  string
	provider   *oidc.Provider
	verifier   *oidc.IDTokenVerifier
	oauth      *oauth2.Config
	httpClient *http.Client
	now        func() time.Time
	rand       io.Reader
	prompt     string
	endSession string
	clientID   string
}

type adapterState struct {
	Nonce    string `json:"nonce"`
	Verifier string `json:"verifier"`
}

// newOIDCAdapter is the legacy Google constructor (tests).
func newOIDCAdapter(
	ctx context.Context, t Tenant, publicURL string,
	httpClient *http.Client, now func() time.Time, rnd io.Reader,
) (*oidcAdapter, error) {
	return newUpstreamAdapter(
		ctx, t.ID, "google", t.Google, publicURL, httpClient, now, rnd)
}

// newUpstreamAdapter builds a generic OIDC adapter for one upstream
// (Google, Microsoft, any standard OIDC issuer).
func newUpstreamAdapter(
	ctx context.Context, tenantID, idp string, up GoogleConfig,
	publicURL string, httpClient *http.Client,
	now func() time.Time, rnd io.Reader,
) (*oidcAdapter, error) {
	if now == nil {
		now = time.Now
	}
	if rnd == nil {
		rnd = rand.Reader
	}
	if httpClient != nil {
		ctx = oidc.ClientContext(ctx, httpClient)
	}
	display := up.DisplayName
	if display == "" {
		display = idp
	}
	provider, err := oidc.NewProvider(ctx, up.Issuer)
	if err != nil {
		return nil, fmt.Errorf(
			"tenant %s: cannot discover %s issuer %s: %w",
			tenantID, display, up.Issuer, err)
	}
	scopes := up.Scopes
	if len(scopes) == 0 {
		scopes = []string{"openid", "profile", "email"}
	}
	var disc struct {
		EndSessionEndpoint string `json:"end_session_endpoint"`
	}
	_ = provider.Claims(&disc)
	return &oidcAdapter{
		issuer:    up.Issuer,
		idp:       idp,
		display:   display,
		tenantID:  tenantID,
		publicURL: publicURL,
		provider:  provider,
		verifier: provider.Verifier(&oidc.Config{
			ClientID: up.ClientID,
		}),
		oauth: &oauth2.Config{
			ClientID:     up.ClientID,
			ClientSecret: up.ClientSecret,
			Endpoint:     provider.Endpoint(),
			RedirectURL:  publicURL + "/t/" + tenantID + "/callback",
			Scopes:       scopes,
		},
		httpClient: httpClient,
		now:        now,
		rand:       rnd,
		prompt:     strings.TrimSpace(up.Prompt),
		endSession: disc.EndSessionEndpoint,
		clientID:   up.ClientID,
	}, nil
}

func (a *oidcAdapter) Manifest() identityadapter.Manifest {
	return identityadapter.Manifest{
		Name:       "oidc." + a.idp,
		Version:    "1.0.0",
		APIVersion: "v1",
		HostAPI:    ">=1.0 <2.0",
		Publisher:  "Cladone-IT",
		Capabilities: identityadapter.Capabilities{
			Redirect: true,
		},
	}
}

func (a *oidcAdapter) Start(
	_ context.Context, req identityadapter.Request,
) (identityadapter.Step, error) {
	nonce := req.Params["nonce"]
	if nonce == "" {
		nonce = a.randomHex(16)
	}
	iamState := req.Params["iam_state"]
	if iamState == "" {
		iamState = a.randomHex(24)
	}
	verifier := oauth2.GenerateVerifier()
	state, err := json.Marshal(adapterState{
		Nonce: nonce, Verifier: verifier,
	})
	if err != nil {
		return identityadapter.Step{}, err
	}
	opts := []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("nonce", nonce),
		oauth2.S256ChallengeOption(verifier),
	}
	if a.prompt != "" {
		opts = append(opts, oauth2.SetAuthURLParam("prompt", a.prompt))
	}
	url := a.oauth.AuthCodeURL(iamState, opts...)
	return identityadapter.Step{
		Kind:        identityadapter.StepRedirect,
		RedirectURL: url,
		State:       state,
	}, nil
}

func (a *oidcAdapter) Continue(
	ctx context.Context, req identityadapter.Request, state []byte,
) (identityadapter.Step, error) {
	var st adapterState
	if len(state) == 0 || json.Unmarshal(state, &st) != nil ||
		st.Nonce == "" || st.Verifier == "" {
		return identityadapter.Step{}, identityadapter.ErrInvalidRequest
	}
	code := req.Params["code"]
	if code == "" {
		return identityadapter.Step{}, identityadapter.ErrInvalidRequest
	}
	token, err := a.oauth.Exchange(
		ctx, code, oauth2.VerifierOption(st.Verifier))
	if err != nil {
		return identityadapter.Step{}, fmt.Errorf(
			"%w: %s token exchange: %v",
			identityadapter.ErrProviderUnavailable, a.display, err)
	}
	rawID, _ := token.Extra("id_token").(string)
	if rawID == "" {
		return identityadapter.Step{}, fmt.Errorf(
			"%w: %s returned no id_token",
			identityadapter.ErrProviderUnavailable, a.display)
	}
	idToken, err := a.verifier.Verify(ctx, rawID)
	if err != nil {
		return identityadapter.Step{}, fmt.Errorf(
			"%w: %s id_token rejected: %v",
			identityadapter.ErrUnauthenticated, a.display, err)
	}
	var claims map[string]any
	if err := idToken.Claims(&claims); err != nil {
		return identityadapter.Step{}, fmt.Errorf(
			"%w: %s claims unreadable: %v",
			identityadapter.ErrUnauthenticated, a.display, err)
	}
	if nonce, _ := claims["nonce"].(string); nonce != st.Nonce {
		return identityadapter.Step{}, fmt.Errorf(
			"%w: nonce mismatch", identityadapter.ErrUnauthenticated)
	}
	sub, _ := claims["sub"].(string)
	if sub == "" {
		// Microsoft uses `oid` as the stable object id.
		sub, _ = claims["oid"].(string)
	}
	if sub == "" {
		return identityadapter.Step{}, fmt.Errorf(
			"%w: %s subject is empty",
			identityadapter.ErrUnauthenticated, a.display)
	}
	email, _ := claims["email"].(string)
	username, _ := claims["preferred_username"].(string)
	if email == "" {
		// Microsoft personal accounts expose the address as
		// preferred_username/upn, not always as `email`.
		if strings.Contains(username, "@") {
			email = username
		} else if upn, _ := claims["upn"].(string); strings.Contains(upn, "@") {
			email = upn
		}
	}
	if username == "" {
		username, _ = claims["name"].(string)
	}
	if username == "" {
		username = email
	}
	return identityadapter.Step{
		Kind: identityadapter.StepResult,
		Assertion: &identityadapter.Assertion{
			Subject:  sub,
			Username: username,
			Email:    email,
			Groups:   claimStrings(claims["groups"]),
			Claims:   claims,
			IDToken:  rawID,
		},
	}, nil
}

func (a *oidcAdapter) Enrich(
	_ context.Context, in identityadapter.Assertion,
) (identityadapter.Assertion, error) {
	return in, nil
}

func (a *oidcAdapter) Health(ctx context.Context) error {
	if _, err := oidc.NewProvider(ctx, a.issuer); err != nil {
		return fmt.Errorf("%w: %v", identityadapter.ErrProviderUnavailable, err)
	}
	return nil
}

// EndSessionURL is the upstream RP-initiated logout endpoint
// (empty when the IdP does not advertise one, e.g. Google).
func (a *oidcAdapter) EndSessionURL() string { return a.endSession }

// ClientID is the upstream client id (needed by some logout endpoints).
func (a *oidcAdapter) ClientID() string { return a.clientID }

// SetRedirectURL follows an IAM public URL change (tests/dynamic
// ingress).
func (a *oidcAdapter) SetRedirectURL(base string) {
	a.publicURL = strings.TrimRight(base, "/")
	a.oauth.RedirectURL = a.publicURL + "/t/" + a.tenantID + "/callback"
}

func (a *oidcAdapter) randomHex(n int) string {
	buf := make([]byte, n)
	if _, err := io.ReadFull(a.rand, buf); err != nil {
		now := a.now().UnixNano()
		for i := range buf {
			buf[i] = byte(now >> (i % 8 * 8))
		}
	}
	return hex.EncodeToString(buf)
}

var _ identityadapter.Adapter = (*oidcAdapter)(nil)
