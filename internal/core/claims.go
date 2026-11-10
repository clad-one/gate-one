package core

// Claim conditions: one accepted value, or a list of accepted values.
//
// Historically a claim condition was a single string: the claim had to
// be present ("*") or stringify exactly to that value. Multiple
// accepted emails (or any "one of" rule) required duplicating routes.
// A value may now be a JSON array: the condition passes when ANY listed
// value matches. Keys still combine with AND.
//
// The same type is used by auth.identity, rateLimit.when/quota.when
// (the identity half of Match) and uiGate rules, so the server-side and
// client-side gating agree.

import (
	"encoding/json"
	"fmt"
)

// ClaimValues is a claim condition value: one string or a list of
// strings (OR between the listed values).
type ClaimValues []string

// UnmarshalJSON accepts "value" or ["value1", "value2"]. Rejecting
// null, an empty list and empty strings here keeps a typo from turning
// into a condition that silently never matches.
func (v *ClaimValues) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		return fmt.Errorf(
			"claim condition: a string or an array of strings is required")
	}
	var one string
	if err := json.Unmarshal(data, &one); err == nil {
		return v.set([]string{one})
	}
	var list []string
	if err := json.Unmarshal(data, &list); err == nil {
		return v.set(list)
	}
	return fmt.Errorf(
		"claim condition: a string or an array of strings is required")
}

func (v *ClaimValues) set(items []string) error {
	if len(items) == 0 {
		return fmt.Errorf("claim condition: the value list is empty")
	}
	for _, item := range items {
		if item == "" {
			return fmt.Errorf("claim condition: empty value")
		}
	}
	*v = ClaimValues(items)
	return nil
}

// MarshalJSON keeps the historical string form for a single value, so
// the guard script and any consumer that only knows the old shape keep
// working; a list is emitted as an array.
func (v ClaimValues) MarshalJSON() ([]byte, error) {
	if len(v) == 1 {
		return json.Marshal(v[0])
	}
	return json.Marshal([]string(v))
}
