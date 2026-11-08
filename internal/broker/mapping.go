package broker

import (
	"fmt"
	"strings"
)

// MappingRule translates one upstream claim into broker rights. It is
// evaluated against the federated user's token claims on every login;
// the resulting roles/scopes/claims are never persisted on the user.
type MappingRule struct {
	// Claim is a dot path into the token claims (e.g. groups,
	// realm_access.roles, resource_access.gate-one.roles).
	Claim string `json:"claim"`
	// Values matches any scalar/array value. Empty = claim presence.
	Values []string `json:"values,omitempty"`
	// Roles/Scopes are added to the effective rights.
	Roles  []string `json:"roles,omitempty"`
	Scopes []string `json:"scopes,omitempty"`
	// Claims are copied into the token; reserved claims are refused.
	Claims map[string]any `json:"claims,omitempty"`
}

type rights struct {
	Roles  []string
	Scopes []string
	Claims map[string]any
}

func (r *rights) addRoles(items ...string) {
	r.Roles = append(r.Roles, items...)
}

func (r *rights) addScopes(items ...string) {
	r.Scopes = append(r.Scopes, items...)
}

func (r *rights) addClaims(claims map[string]any) {
	if len(claims) == 0 {
		return
	}
	if r.Claims == nil {
		r.Claims = map[string]any{}
	}
	for k, v := range claims {
		if !reservedClaim(k) {
			r.Claims[k] = v
		}
	}
}

func (r *rights) normalize() {
	r.Roles = uniqueSorted(r.Roles)
	r.Scopes = uniqueSorted(r.Scopes)
}

// mappedRights evaluates tenant mappings and the legacy groupRoles
// mapping against a federated user's claims.
func (rt *tenantRuntime) mappedRights(claims map[string]any) rights {
	var out rights
	if len(claims) == 0 {
		return out
	}
	// Legacy block: group name -> roles. Kept for compatibility.
	for _, group := range claimStrings(claims["groups"]) {
		out.addRoles(rt.cfg.GroupRoles[group]...)
	}
	for _, rule := range rt.cfg.Mappings {
		if !mappingMatches(claims, rule) {
			continue
		}
		out.addRoles(rule.Roles...)
		out.addScopes(rule.Scopes...)
		out.addClaims(rule.Claims)
	}
	return out
}

func mappingMatches(claims map[string]any, rule MappingRule) bool {
	raw, ok := claimAt(claims, rule.Claim)
	if !ok || raw == nil {
		return false
	}
	values := claimStrings(raw)
	if len(rule.Values) == 0 {
		// Presence match: an empty string/slice is not presence.
		if s, ok := raw.(string); ok {
			return strings.TrimSpace(s) != ""
		}
		return len(values) > 0 || raw != nil
	}
	for _, got := range values {
		for _, want := range rule.Values {
			if got == want {
				return true
			}
		}
	}
	return false
}

func claimAt(claims map[string]any, path string) (any, bool) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, false
	}
	var cur any = claims
	for _, part := range strings.Split(path, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		cur, ok = m[part]
		if !ok {
			return nil, false
		}
	}
	return cur, true
}

func claimString(claims map[string]any, path string) string {
	raw, ok := claimAt(claims, path)
	if !ok {
		return ""
	}
	switch v := raw.(type) {
	case string:
		return v
	case []any:
		if len(v) > 0 {
			if s, ok := v[0].(string); ok {
				return s
			}
		}
	}
	return ""
}

// effectiveRights combines tenant defaults, mapped upstream claims and
// the user's admin-managed grants. User grants are the same object for
// local and federated users.
func (rt *tenantRuntime) effectiveRights(
	u *User, claims map[string]any,
) rights {
	var out rights
	out.addRoles(rt.cfg.DefaultRoles...)
	if u != nil {
		for _, admin := range rt.cfg.AdminEmails {
			if strings.EqualFold(admin, u.Email) {
				out.addRoles("admin")
			}
		}
		mapped := rt.mappedRights(claims)
		out.addRoles(mapped.Roles...)
		out.addScopes(mapped.Scopes...)
		out.addClaims(mapped.Claims)
		ruled := rt.ruleRights(claims)
		out.addRoles(ruled.Roles...)
		out.addScopes(ruled.Scopes...)
		out.addClaims(ruled.Claims)
		out.addRoles(u.Roles...)
		out.addScopes(u.Scopes...)
		out.addClaims(u.Claims)
	}
	out.normalize()
	return out
}

func (rt *tenantRuntime) upstreamIssuer(idp string) string {
	if up, ok := rt.cfg.Upstreams[idp]; ok && strings.TrimSpace(up.Issuer) != "" {
		return strings.TrimSpace(up.Issuer)
	}
	if idp == "" || idp == "google" {
		return "https://accounts.google.com"
	}
	return idp
}

func reservedClaim(name string) bool {
	switch name {
	case "iss", "sub", "aud", "exp", "iat", "nbf", "jti", "nonce",
		"tenant", "roles", "scope", "sid", "email", "preferred_username":
		return true
	}
	return false
}

func validateMappingRules(rules []MappingRule) error {
	for i, rule := range rules {
		if strings.TrimSpace(rule.Claim) == "" {
			return fmt.Errorf("mappings[%d].claim is required", i)
		}
		if len(rule.Roles) == 0 && len(rule.Scopes) == 0 &&
			len(rule.Claims) == 0 {
			return fmt.Errorf("mappings[%d]: at least one role, scope or claim is required", i)
		}
		for _, v := range rule.Values {
			if strings.TrimSpace(v) == "" {
				return fmt.Errorf("mappings[%d].values: empty value", i)
			}
		}
		for _, role := range rule.Roles {
			if strings.TrimSpace(role) == "" {
				return fmt.Errorf("mappings[%d].roles: empty role", i)
			}
		}
		for _, scope := range rule.Scopes {
			if strings.TrimSpace(scope) == "" {
				return fmt.Errorf("mappings[%d].scopes: empty scope", i)
			}
		}
		for name := range rule.Claims {
			if reservedClaim(name) {
				return fmt.Errorf("mappings[%d].claims: reserved claim %q", i, name)
			}
		}
	}
	return nil
}

func mergeScopes(scope string, scopes []string) string {
	all := append(strings.Fields(scope), scopes...)
	return strings.Join(uniqueSorted(all), " ")
}

func mergeExtraClaims(dst map[string]any, extra map[string]any) {
	for name, value := range extra {
		if !reservedClaim(name) {
			dst[name] = value
		}
	}
}
