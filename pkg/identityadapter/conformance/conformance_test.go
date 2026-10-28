package conformance_test

import (
	"testing"

	"cladone/gate-one/pkg/identityadapter"
	"cladone/gate-one/pkg/identityadapter/conformance"
	"cladone/gate-one/pkg/identityadapter/conformance/testadapter"
)

func TestAC_AUTH_09_IdentityAdapterConformance(t *testing.T) {
	conformance.Run(t, testadapter.New())
}

func TestAC_AUTH_11_EnrichmentOptional(t *testing.T) {
	a := testadapter.New()
	a.Capability.Enrichment = false
	a.EnrichFn = nil
	conformance.Run(t, a)

	out, err := a.Enrich(t.Context(), identityadapter.Assertion{Subject: "u"})
	if err != nil {
		t.Fatal(err)
	}
	if out.Claims != nil {
		t.Fatalf("enrichment without capability changed claims: %+v", out.Claims)
	}
}
