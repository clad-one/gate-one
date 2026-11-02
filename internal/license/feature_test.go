package license

import "testing"

func TestHasFeature(t *testing.T) {
	registered := Status{State: "registered", Features: []string{"audit", "billing"}}
	if !HasFeature(registered, "audit") {
		t.Error("audit feature not granted")
	}
	if HasFeature(registered, "metering") {
		t.Error("unknown feature granted")
	}
	if !HasFeature(registered, "") {
		t.Error("empty feature must be allowed")
	}
	if HasFeature(Status{State: "eval"}, "audit") {
		t.Error("eval licence granted a feature")
	}
}
