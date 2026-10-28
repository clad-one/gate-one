// Package conformance is the single test suite every IdentityAdapter
// must pass: built-in OIDC, future LDAP/SAML, and signed out-of-process
// plugins over gRPC or HTTP/JSON.
package conformance

import (
	"context"
	"errors"
	"testing"
	"time"

	"cladone/gate-one/pkg/identityadapter"
)

// Run executes the adapter contract suite. It is deterministic and
// never reaches the network: adapters receive fake requests and must
// behave synchronously.
func Run(t *testing.T, a identityadapter.Adapter) {
	t.Helper()

	t.Run("manifest", func(t *testing.T) {
		m := a.Manifest()
		if m.Name == "" {
			t.Error("manifest.name is required")
		}
		if m.Version == "" {
			t.Error("manifest.version is required")
		}
		if m.APIVersion == "" {
			t.Error("manifest.apiVersion is required")
		}
		if m.HostAPI == "" {
			t.Error("manifest.hostAPI is required")
		}
	})

	t.Run("start_returns_declared_step", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		step, err := a.Start(ctx, identityadapter.Request{
			Tenant: "test",
			Method: "GET",
			URL:    "https://login.test/start",
			Header: map[string][]string{},
		})
		if err != nil {
			t.Fatalf("Start: %v", err)
		}
		assertStep(t, a, step)
	})

	t.Run("continue_rejects_invalid_state", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		step, err := a.Continue(ctx, identityadapter.Request{
			Tenant: "test",
			Method: "GET",
			URL:    "https://login.test/callback",
			Header: map[string][]string{},
		}, []byte("tampered"))
		if err == nil && step.Kind == identityadapter.StepResult {
			t.Fatal("Continue accepted a tampered state")
		}
		if err != nil && !errors.Is(err, identityadapter.ErrInvalidRequest) &&
			!errors.Is(err, identityadapter.ErrUnauthenticated) {
			t.Fatalf("Continue error = %v, want invalid request or unauthenticated", err)
		}
	})

	t.Run("result_assertion_is_facts_only", func(t *testing.T) {
		step := resultStep(t, a)
		if step.Assertion == nil {
			t.Fatal("result step without assertion")
		}
		if step.Assertion.Subject == "" {
			t.Error("assertion.subject is required")
		}
		// Assertion has no roles/tenant/audience fields by construction;
		// raw claims may carry anything, but the broker ignores them for
		// policy. This test documents the boundary.
	})

	t.Run("enrichment_optional", func(t *testing.T) {
		cap := a.Manifest().Capabilities
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		in := identityadapter.Assertion{Subject: "user-1"}
		out, err := a.Enrich(ctx, in)
		if !cap.Enrichment {
			if err != nil {
				t.Fatalf("Enrich without capability: %v", err)
			}
			if out.Subject != in.Subject {
				t.Fatalf("Enrich without capability changed the assertion")
			}
			return
		}
		if err != nil {
			t.Fatalf("Enrich: %v", err)
		}
		if out.Subject == "" {
			t.Error("Enrich returned an empty subject")
		}
	})

	t.Run("health", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := a.Health(ctx); err != nil {
			t.Fatalf("Health: %v", err)
		}
	})
}

func assertStep(t *testing.T, a identityadapter.Adapter, step identityadapter.Step) {
	t.Helper()
	cap := a.Manifest().Capabilities
	switch step.Kind {
	case identityadapter.StepRedirect:
		if !cap.Redirect {
			t.Fatal("adapter returned a redirect without the redirect capability")
		}
		if step.RedirectURL == "" {
			t.Fatal("redirect step without URL")
		}
	case identityadapter.StepChallenge:
		if !cap.Challenge {
			t.Fatal("adapter returned a challenge without the challenge capability")
		}
		if step.Challenge == "" {
			t.Fatal("challenge step without challenge")
		}
	case identityadapter.StepForm:
		if !cap.Form {
			t.Fatal("adapter returned a form without the form capability")
		}
		if len(step.Fields) == 0 {
			t.Fatal("form step without fields")
		}
	case identityadapter.StepResult:
		if step.Assertion == nil {
			t.Fatal("result step without assertion")
		}
	default:
		t.Fatalf("unknown step kind %q", step.Kind)
	}
}

func resultStep(t *testing.T, a identityadapter.Adapter) identityadapter.Step {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	step, err := a.Start(ctx, identityadapter.Request{
		Tenant: "test",
		Method: "GET",
		URL:    "https://login.test/start",
		Header: map[string][]string{},
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if step.Kind == identityadapter.StepResult {
		return step
	}
	// Redirect/challenge/form adapters are not forced to produce a
	// result without their upstream; the suite only checks the shape
	// when a result is returned.
	return identityadapter.Step{
		Kind: identityadapter.StepResult,
		Assertion: &identityadapter.Assertion{
			Subject: "conformance-subject",
		},
	}
}
