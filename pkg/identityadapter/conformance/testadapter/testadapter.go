// Package testadapter is a configurable in-memory IdentityAdapter used
// by the conformance suite and by the IAM tests.
package testadapter

import (
	"context"
	"errors"

	"cladone/gate-one/pkg/identityadapter"
)

// Adapter is a deterministic fake.
type Adapter struct {
	Name       string
	Version    string
	Capability identityadapter.Capabilities
	StartStep  identityadapter.Step
	ContStep   identityadapter.Step
	EnrichFn   func(identityadapter.Assertion) (identityadapter.Assertion, error)
	HealthErr  error
}

// New returns the default adapter: it directly returns a result.
func New() *Adapter {
	return &Adapter{
		Name:    "test.adapter",
		Version: "1.0.0",
		Capability: identityadapter.Capabilities{
			Redirect:   true,
			Enrichment: true,
		},
		StartStep: identityadapter.Step{
			Kind: identityadapter.StepResult,
			Assertion: &identityadapter.Assertion{
				Subject:  "user-1",
				Username: "alice",
				Email:    "alice@example.test",
				Groups:   []string{"users"},
			},
			State: []byte("state-1"),
		},
	}
}

func (a *Adapter) Manifest() identityadapter.Manifest {
	name := a.Name
	if name == "" {
		name = "test.adapter"
	}
	version := a.Version
	if version == "" {
		version = "1.0.0"
	}
	return identityadapter.Manifest{
		Name:         name,
		Version:      version,
		APIVersion:   "v1",
		HostAPI:      ">=1.0 <2.0",
		Capabilities: a.Capability,
	}
}

func (a *Adapter) Start(context.Context, identityadapter.Request) (identityadapter.Step, error) {
	if a.StartStep.Kind == "" {
		return identityadapter.Step{
			Kind: identityadapter.StepResult,
			Assertion: &identityadapter.Assertion{
				Subject: "user-1",
			},
		}, nil
	}
	return a.StartStep, nil
}

func (a *Adapter) Continue(_ context.Context, _ identityadapter.Request, state []byte) (identityadapter.Step, error) {
	if string(state) != "state-1" {
		return identityadapter.Step{}, identityadapter.ErrInvalidRequest
	}
	if a.ContStep.Kind == "" {
		return identityadapter.Step{
			Kind: identityadapter.StepResult,
			Assertion: &identityadapter.Assertion{
				Subject: "user-1",
			},
		}, nil
	}
	return a.ContStep, nil
}

func (a *Adapter) Enrich(_ context.Context, in identityadapter.Assertion) (identityadapter.Assertion, error) {
	if a.EnrichFn != nil {
		return a.EnrichFn(in)
	}
	if !a.Capability.Enrichment {
		return in, nil
	}
	if in.Claims == nil {
		in.Claims = map[string]any{}
	}
	in.Claims["enriched"] = true
	return in, nil
}

func (a *Adapter) Health(context.Context) error {
	if a.HealthErr != nil {
		return a.HealthErr
	}
	return nil
}

// ErrUnavailable is a helper for tests.
var ErrUnavailable = errors.New("testadapter: unavailable")
