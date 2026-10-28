package authn

import (
	"context"
	"fmt"
	"net/http"

	"github.com/coreos/go-oidc/v3/oidc"
)

// RefreshTTLWarning is the operator-facing message when an OIDC issuer
// does not publish its refresh-token lifetime. It is used at startup
// and by -check.
func RefreshTTLWarning(issuer, providerID string) string {
	id := providerID
	if id == "" {
		id = "default"
	}
	return fmt.Sprintf(
		"OIDC issuer %s (provider %s) does not advertise "+
			"cladone_refresh_token_ttl_seconds; using 30 days for revocation. "+
			"Set authProvider.revocationTtlSeconds (or authProviders[].revocationTtlSeconds) to at least your IdP "+
			"refresh-token lifetime, otherwise a global logout may not block "+
			"refresh tokens after this window. Typical location: Keycloak "+
			"Realm Settings > Tokens (SSO Session Idle/Max, Refresh Token "+
			"Max Reuse); Entra ID token lifetime policy; Auth0 Refresh Token "+
			"Expiration; Okta refresh token lifetime.",
		issuer, id)
}

// ProbeRefreshTTL reads the custom discovery field without building a
// full provider. 0 means the issuer does not advertise it.
func ProbeRefreshTTL(
	ctx context.Context, issuer string, hc *http.Client,
) (int, error) {
	if hc != nil {
		ctx = oidc.ClientContext(ctx, hc)
	}
	p, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return 0, err
	}
	var d struct {
		RefreshTokenTTLSeconds int `json:"cladone_refresh_token_ttl_seconds"`
	}
	if err := p.Claims(&d); err != nil {
		return 0, err
	}
	return d.RefreshTokenTTLSeconds, nil
}
