package eval

import (
	"context"
	"strings"
	"testing"
	"time"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
)

type depsObservationRepoStub struct{}

func (depsObservationRepoStub) LoadSnapshots(context.Context, string) (appcontracts.LoadResult, error) {
	return appcontracts.LoadResult{}, nil
}

type depsControlRepoStub struct{}

func (depsControlRepoStub) LoadControls(context.Context, string) ([]policy.ControlDefinition, error) {
	return nil, nil
}

type depsMarshalerStub struct{}

func (depsMarshalerStub) MarshalFindings(appcontracts.EnrichedResult) ([]byte, error) {
	return []byte(`{}`), nil
}

func depsEnrichFn(result evaluation.Audit) (appcontracts.EnrichedResult, error) {
	return appcontracts.EnrichedResult{
		Result:         result,
		Findings:       []appcontracts.EnrichedFinding{},
		ExemptedAssets: result.ExemptedAssets,
		Run:            result.Run,
	}, nil
}

func TestBuildDependencies_ValidationErrors(t *testing.T) {
	base := BuildDependenciesInput{
		Plan: EvaluationPlan{
			ControlsPath:     "/ctl",
			ObservationsPath: "/obs",
		},
		Adapters: Adapters{
			FindingMarshaler:  depsMarshalerStub{},
			EnrichFn:          depsEnrichFn,
			ObservationLoader: depsObservationRepoStub{},
			ControlLoader:     depsControlRepoStub{},
		},
	}

	tests := []struct {
		name    string
		mutate  func(*BuildDependenciesInput)
		wantErr string
	}{
		{
			name: "empty plan",
			mutate: func(in *BuildDependenciesInput) {
				in.Plan = EvaluationPlan{}
			},
			wantErr: "evaluation plan is required",
		},
		{
			name: "nil control loader",
			mutate: func(in *BuildDependenciesInput) {
				in.Adapters.ControlLoader = nil
			},
			wantErr: "control loader is not configured",
		},
		{
			name: "nil observation loader",
			mutate: func(in *BuildDependenciesInput) {
				in.Adapters.ObservationLoader = nil
			},
			wantErr: "observation loader is not configured",
		},
		{
			name: "nil finding marshaler",
			mutate: func(in *BuildDependenciesInput) {
				in.Adapters.FindingMarshaler = nil
			},
			wantErr: "finding marshaler is not configured",
		},
		{
			name: "nil enrich function",
			mutate: func(in *BuildDependenciesInput) {
				in.Adapters.EnrichFn = nil
			},
			wantErr: "enrich function is not configured",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := base
			tt.mutate(&in)

			_, err := BuildDependencies(context.Background(), in)
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %v, want contains %q", err, tt.wantErr)
			}
		})
	}
}

func TestBuildDependencies_UsesProvidedLoader(t *testing.T) {
	obsRepo := &depsObservationRepoStub{}
	ctlRepo := &depsControlRepoStub{}

	out, err := BuildDependencies(context.Background(), BuildDependenciesInput{
		Plan: EvaluationPlan{
			ContextName:      "ctx",
			ControlsPath:     "/ctl",
			ObservationsPath: "/obs",
		},
		Adapters: Adapters{
			FindingMarshaler:  depsMarshalerStub{},
			EnrichFn:          depsEnrichFn,
			ObservationLoader: obsRepo,
			ControlLoader:     ctlRepo,
		},
		Runtime: RuntimeConfig{
			MaxUnsafeDuration: time.Hour,
			StaveVersion:      "test",
		},
	})
	if err != nil {
		t.Fatalf("BuildDependencies() error = %v", err)
	}

	if out.Runner.ObservationRepo != obsRepo {
		t.Fatalf("observation repo mismatch: got %#v want %#v", out.Runner.ObservationRepo, obsRepo)
	}
	if out.Config.Output == nil || out.Config.Stderr == nil {
		t.Fatalf("expected default output/stderr writers to be set, got output=%v stderr=%v", out.Config.Output, out.Config.Stderr)
	}
}

func TestBuildDependencies_PassesExemptionConfig(t *testing.T) {
	exemption := &policy.ExemptionConfig{
		Assets: []policy.ExemptionRule{
			{Pattern: "res-*", Reason: "test"},
		},
	}

	out, err := BuildDependencies(context.Background(), BuildDependenciesInput{
		Plan: EvaluationPlan{
			ControlsPath:     "/ctl",
			ObservationsPath: "/obs",
		},
		Adapters: Adapters{
			FindingMarshaler:  depsMarshalerStub{},
			EnrichFn:          depsEnrichFn,
			ObservationLoader: &depsObservationRepoStub{},
			ControlLoader:     &depsControlRepoStub{},
		},
		Runtime: RuntimeConfig{
			ExemptionConfig: exemption,
		},
	})
	if err != nil {
		t.Fatalf("BuildDependencies() error = %v", err)
	}
	if out.Config.ExemptionConfig == nil || len(out.Config.ExemptionConfig.Assets) != 1 {
		t.Fatalf("expected exemption config to be passed through, got %#v", out.Config.ExemptionConfig)
	}
}
