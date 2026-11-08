package broker

import (
	"fmt"
	"path"
	"strconv"
	"strings"
)

// Rule is a when/then policy: it tests the federated token's claims
// (when) and grants rights (then). It is evaluated on every login and
// its results are never persisted on the user.
//
//	"rules": [{
//	  "when": [{ "claim": "email", "match": "domain", "values": ["example.com"] }],
//	  "then": { "roles": ["employee"], "rolesFrom": [{"claim": "groups"}] }
//	}]
type Rule struct {
	When []Condition `json:"when"`
	Then Then        `json:"then"`
}

// Condition tests one claim of the incoming token. Match is exact
// (default), prefix, suffix, domain or glob.
type Condition struct {
	Claim  string   `json:"claim"`
	Match  string   `json:"match,omitempty"`
	Values []string `json:"values,omitempty"`
}

// Then is the grant applied when every condition matches.
type Then struct {
	Roles      []string       `json:"roles,omitempty"`
	Scopes     []string       `json:"scopes,omitempty"`
	Claims     map[string]any `json:"claims,omitempty"`
	RolesFrom  []RolesFrom    `json:"rolesFrom,omitempty"`
	CopyClaims []CopyClaim    `json:"copyClaims,omitempty"`
}

// RolesFrom derives roles from an incoming claim's values.
type RolesFrom struct {
	Claim      string   `json:"claim"`
	Transforms []string `json:"transforms,omitempty"`
}

// CopyClaim copies an incoming claim into the issued token, optionally
// renamed (To) and reshaped (Transforms).
type CopyClaim struct {
	From       string   `json:"from"`
	To         string   `json:"to,omitempty"`
	Transforms []string `json:"transforms,omitempty"`
}

// ruleRights evaluates every rule against the federated claims.
func (rt *tenantRuntime) ruleRights(claims map[string]any) rights {
	var out rights
	if len(claims) == 0 {
		return out
	}
	for _, rule := range rt.cfg.Rules {
		if !ruleMatches(claims, rule.When) {
			continue
		}
		out.addRoles(rule.Then.Roles...)
		out.addScopes(rule.Then.Scopes...)
		out.addClaims(rule.Then.Claims)
		for _, rf := range rule.Then.RolesFrom {
			for _, v := range transformedStrings(claims, rf.Claim, rf.Transforms) {
				if v != "" {
					out.addRoles(v)
				}
			}
		}
		for _, cc := range rule.Then.CopyClaims {
			val, ok := copyClaimValue(claims, cc)
			if !ok {
				continue
			}
			dest := strings.TrimSpace(cc.To)
			if dest == "" {
				dest = cc.From
			}
			out.addClaims(map[string]any{dest: val})
		}
	}
	return out
}

func ruleMatches(claims map[string]any, when []Condition) bool {
	if len(when) == 0 {
		return false
	}
	for _, c := range when {
		if !conditionMatches(claims, c) {
			return false
		}
	}
	return true
}

func conditionMatches(claims map[string]any, c Condition) bool {
	raw, ok := claimAt(claims, c.Claim)
	if !ok || raw == nil {
		return false
	}
	values := claimStrings(raw)
	if len(c.Values) == 0 {
		return len(values) > 0
	}
	for _, got := range values {
		for _, want := range c.Values {
			if matchValue(got, want, c.Match) {
				return true
			}
		}
	}
	return false
}

func matchValue(got, want, op string) bool {
	switch op {
	case "", "exact":
		return got == want
	case "prefix":
		return strings.HasPrefix(strings.ToLower(got), strings.ToLower(want))
	case "suffix":
		return strings.HasSuffix(strings.ToLower(got), strings.ToLower(want))
	case "domain":
		dom := got
		if i := strings.LastIndex(got, "@"); i >= 0 {
			dom = got[i+1:]
		}
		return strings.EqualFold(dom, strings.TrimPrefix(want, "@"))
	case "glob":
		ok, _ := path.Match(strings.ToLower(want), strings.ToLower(got))
		return ok
	default:
		return false
	}
}

// transformedStrings reads a claim and applies the transform pipeline to
// every value.
func transformedStrings(
	claims map[string]any, claim string, transforms []string,
) []string {
	raw, ok := claimAt(claims, claim)
	if !ok || raw == nil {
		return nil
	}
	var out []string
	for _, v := range claimStrings(raw) {
		out = append(out, applyTransforms(v, transforms))
	}
	return out
}

// copyClaimValue returns the (optionally transformed) value to copy.
// Without transforms the raw value is preserved (scalar or array); with
// transforms each value is reshaped and the result collapses to a scalar
// when there is a single one.
func copyClaimValue(claims map[string]any, cc CopyClaim) (any, bool) {
	raw, ok := claimAt(claims, cc.From)
	if !ok || raw == nil {
		return nil, false
	}
	if len(cc.Transforms) == 0 {
		return raw, true
	}
	var out []string
	for _, v := range claimStrings(raw) {
		out = append(out, applyTransforms(v, cc.Transforms))
	}
	switch len(out) {
	case 0:
		return nil, false
	case 1:
		return out[0], true
	default:
		return out, true
	}
}

func applyTransforms(v string, transforms []string) string {
	for _, t := range transforms {
		v = applyTransform(v, t)
	}
	return v
}

// applyTransform applies one transform to a value:
//
//	lower | upper
//	prefix:<p> | suffix:<p>
//	replace:<a>:<b>
//	keep:<sep>:<n>   (n-th field; n<0 counts from the end)
//
// An unknown or malformed transform is a no-op (validation rejects them
// at load time).
func applyTransform(v, t string) string {
	t = strings.TrimSpace(t)
	switch {
	case t == "lower":
		return strings.ToLower(v)
	case t == "upper":
		return strings.ToUpper(v)
	case strings.HasPrefix(t, "prefix:"):
		return strings.TrimPrefix(t, "prefix:") + v
	case strings.HasPrefix(t, "suffix:"):
		return v + strings.TrimPrefix(t, "suffix:")
	case strings.HasPrefix(t, "replace:"):
		rest := strings.TrimPrefix(t, "replace:")
		i := strings.Index(rest, ":")
		if i < 0 {
			return v
		}
		return strings.ReplaceAll(v, rest[:i], rest[i+1:])
	case strings.HasPrefix(t, "keep:"):
		rest := strings.TrimPrefix(t, "keep:")
		i := strings.Index(rest, ":")
		if i < 0 {
			return v
		}
		sep := rest[:i]
		if sep == "" {
			return v
		}
		n, err := strconv.Atoi(strings.TrimSpace(rest[i+1:]))
		if err != nil {
			return v
		}
		parts := strings.Split(v, sep)
		if n < 0 {
			n += len(parts)
		}
		if n < 0 || n >= len(parts) {
			return ""
		}
		return parts[n]
	default:
		return v
	}
}

// validateTransform rejects a malformed transform at load time.
func validateTransform(t string) error {
	t = strings.TrimSpace(t)
	switch {
	case t == "lower", t == "upper":
		return nil
	case strings.HasPrefix(t, "prefix:"), strings.HasPrefix(t, "suffix:"):
		return nil
	case strings.HasPrefix(t, "replace:"):
		rest := strings.TrimPrefix(t, "replace:")
		if strings.Index(rest, ":") < 0 {
			return fmt.Errorf("replace needs <a>:<b>")
		}
		return nil
	case strings.HasPrefix(t, "keep:"):
		rest := strings.TrimPrefix(t, "keep:")
		i := strings.Index(rest, ":")
		if i <= 0 {
			return fmt.Errorf("keep needs <sep>:<n>")
		}
		if _, err := strconv.Atoi(strings.TrimSpace(rest[i+1:])); err != nil {
			return fmt.Errorf("keep index must be an integer")
		}
		return nil
	default:
		return fmt.Errorf("unknown transform %q", t)
	}
}

func validateRules(rules []Rule) error {
	for i, r := range rules {
		if len(r.When) == 0 {
			return fmt.Errorf("rules[%d].when: at least one condition is required", i)
		}
		for j, c := range r.When {
			if strings.TrimSpace(c.Claim) == "" {
				return fmt.Errorf("rules[%d].when[%d].claim is required", i, j)
			}
			switch c.Match {
			case "", "exact", "prefix", "suffix", "domain", "glob":
			default:
				return fmt.Errorf("rules[%d].when[%d].match: unknown operator %q",
					i, j, c.Match)
			}
			for _, v := range c.Values {
				if strings.TrimSpace(v) == "" {
					return fmt.Errorf("rules[%d].when[%d].values: empty value", i, j)
				}
			}
		}
		th := r.Then
		if len(th.Roles) == 0 && len(th.Scopes) == 0 && len(th.Claims) == 0 &&
			len(th.RolesFrom) == 0 && len(th.CopyClaims) == 0 {
			return fmt.Errorf(
				"rules[%d].then: at least one role, scope, claim, rolesFrom or copyClaims is required", i)
		}
		for k, rf := range th.RolesFrom {
			if strings.TrimSpace(rf.Claim) == "" {
				return fmt.Errorf("rules[%d].then.rolesFrom[%d].claim is required", i, k)
			}
			for _, t := range rf.Transforms {
				if err := validateTransform(t); err != nil {
					return fmt.Errorf("rules[%d].then.rolesFrom[%d].transforms: %w", i, k, err)
				}
			}
		}
		for k, cc := range th.CopyClaims {
			if strings.TrimSpace(cc.From) == "" {
				return fmt.Errorf("rules[%d].then.copyClaims[%d].from is required", i, k)
			}
			if cc.To != "" && reservedClaim(cc.To) {
				return fmt.Errorf("rules[%d].then.copyClaims[%d].to: reserved claim %q",
					i, k, cc.To)
			}
			for _, t := range cc.Transforms {
				if err := validateTransform(t); err != nil {
					return fmt.Errorf("rules[%d].then.copyClaims[%d].transforms: %w", i, k, err)
				}
			}
		}
		for name := range th.Claims {
			if reservedClaim(name) {
				return fmt.Errorf("rules[%d].then.claims: reserved claim %q", i, name)
			}
		}
	}
	return nil
}
