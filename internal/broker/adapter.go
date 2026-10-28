package broker

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

// oidcAdapter is the broker's built-in Google adapter. It implements
// the same IdentityAdapter contract exposed to out-of-process plugins:
// the broker's policy layer only consumes Assertion facts.
type oidcAdapter struct {
	issuer     string
	tenantID   string
	publicURL  string
	provider   *oidc.Provider
	verifier   *oidc.IDTokenVerifier
	oauth      *oauth2.Config
	httpClient *http.Client
	now        func() time.Time
	rand       io.Reader
}

type adapterState struct {
	Nonce    string `json:"nonce"`
	Verifier string `json:"verifier"`
}

func newOIDCAdapter(
	ctx context.Context, t Tenant, publicURL string,
	httpClient *http.Client, now func() time.Time, rnd io.Reader,
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
	provider, err := oidc.NewProvider(ctx, t.Google.Issuer)
	if err != nil {
		return nil, fmt.Errorf(
			"tenant %s: cannot discover Google issuer %s: %w",
			t.ID, t.Google.Issuer, err)
	}
	scopes := t.Google.Scopes
	if len(scopes) == 0 {
		scopes = []string{"openid", "profile", "email"}
	}
	return &oidcAdapter{
		issuer:    t.Google.Issuer,
		tenantID:  t.ID,
		publicURL: publicURL,
		provider:  provider,
		verifier: provider.Verifier(&oidc.Config{
			ClientID: t.Google.ClientID,
		}),
		oauth: &oauth2.Config{
			ClientID:     t.Google.ClientID,
			ClientSecret: t.Google.ClientSecret,
			Endpoint:     provider.Endpoint(),
			RedirectURL:  publicURL + "/t/" + t.ID + "/callback",
			Scopes:       scopes,
		},
		httpClient: httpClient,
		now:        now,
		rand:       rnd,
	}, nil
}

func (a *oidcAdapter) Manifest() identityadapter.Manifest {
	return identityadapter.Manifest{
		Name:       "oidc.google",
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
	brokerState := req.Params["broker_state"]
	if brokerState == "" {
		brokerState = a.randomHex(24)
	}
	verifier := oauth2.GenerateVerifier()
	state, err := json.Marshal(adapterState{
		Nonce: nonce, Verifier: verifier,
	})
	if err != nil {
		return identityadapter.Step{}, err
	}
	url := a.oauth.AuthCodeURL(
		brokerState,
		oauth2.SetAuthURLParam("nonce", nonce),
		oauth2.S256ChallengeOption(verifier),
	)
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
			"%w: Google token exchange: %v",
			identityadapter.ErrProviderUnavailable, err)
	}
	rawID, _ := token.Extra("id_token").(string)
	if rawID == "" {
		return identityadapter.Step{}, fmt.Errorf(
			"%w: Google returned no id_token",
			identityadapter.ErrProviderUnavailable)
	}
	idToken, err := a.verifier.Verify(ctx, rawID)
	if err != nil {
		return identityadapter.Step{}, fmt.Errorf(
			"%w: Google id_token rejected: %v",
			identityadapter.ErrUnauthenticated, err)
	}
	var claims map[string]any
	if err := idToken.Claims(&claims); err != nil {
		return identityadapter.Step{}, fmt.Errorf(
			"%w: Google claims unreadable: %v",
			identityadapter.ErrUnauthenticated, err)
	}
	if nonce, _ := claims["nonce"].(string); nonce != st.Nonce {
		return identityadapter.Step{}, fmt.Errorf(
			"%w: nonce mismatch", identityadapter.ErrUnauthenticated)
	}
	sub, _ := claims["sub"].(string)
	if sub == "" {
		return identityadapter.Step{}, fmt.Errorf(
			"%w: Google subject is empty", identityadapter.ErrUnauthenticated)
	}
	email, _ := claims["email"].(string)
	username, _ := claims["preferred_username"].(string)
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

// SetRedirectURL follows a broker public URL change (tests/dynamic
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
