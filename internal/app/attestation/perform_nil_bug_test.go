package attestation

import (
	"context"
	"errors"
	"testing"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
)

func TestPerformAttestation_NilClockHandledSafely(t *testing.T) {
	defer func() {
		if rec := recover(); rec != nil {
			t.Fatalf("PerformAttestation panicked on nil clock: %v", rec)
		}
	}()

	deps := WorkflowDeps{
		LoadPolicies: func(ctx context.Context, dir string) ([]policy.ControlDefinition, error) {
			return []policy.ControlDefinition{
				{ID: kernel.ControlID("CTL.S3.001")},
			}, nil
		},
		NewObservationRepo: func() (appcontracts.ObservationRepository, error) {
			return nil, errors.New("repo error")
		},
	}

	req := Request{
		PolicySource: "policies/",
		Clock:        nil, // nil clock
	}

	_ = PerformAttestation(context.Background(), deps, req)
}
