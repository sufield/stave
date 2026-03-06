package eval

import (
	"context"
	"strings"
	"testing"
	"time"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/internal/domain/evaluation"
	"github.com/sufield/stave/internal/domain/evaluation/remediation"
	"github.com/sufield/stave/internal/domain/policy"
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

func depsEnrichFn(result evaluation.Result) appcontracts.EnrichedResult {
	return appcontracts.EnrichedResult{
		Result:        result,
		Findings:      []remediation.Finding{},
		SkippedAssets: result.SkippedAssets,
		Run:           result.Run,
	}
}

func TestBuildDependencies_ValidationErrors(t *testing.T) {
	base := BuildDependenciesInput{
		Plan: EvaluationPlan{
			ControlsPath:     "/ctl",
			ObservationsPath: "/obs",
		},
		FindingMarshaler:  depsMarshalerStub{},
		EnrichFn:          depsEnrichFn,
		ObservationLoader: depsObservationRepoStub{},
		ControlLoader:     depsControlRepoStub{},
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
				in.ControlLoader = nil
			},
			wantErr: "control loader is not configured",
		},
		{
			name: "nil observation loader",
			mutate: func(in *BuildDependenciesInput) {
				in.ObservationLoader = nil
			},
			wantErr: "observation loader is not configured",
		},
		{
			name: "nil finding marshaler",
			mutate: func(in *BuildDependenciesInput) {
				in.FindingMarshaler = nil
			},
			wantErr: "finding marshaler is not configured",
		},
		{
			name: "nil enrich function",
			mutate: func(in *BuildDependenciesInput) {
				in.EnrichFn = nil
			},
			wantErr: "enrich function is not configured",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := base
			tt.mutate(&in)

			_, err := BuildDependencies(in)
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

	out, err := BuildDependencies(BuildDependenciesInput{
		Plan: EvaluationPlan{
			ContextName:      "ctx",
			ControlsPath:     "/ctl",
			ObservationsPath: "/obs",
		},
		FindingMarshaler:  depsMarshalerStub{},
		EnrichFn:          depsEnrichFn,
		ObservationLoader: obsRepo,
		ControlLoader:     ctlRepo,
		MaxUnsafe:         time.Hour,
		ToolVersion:       "test",
	})
	if err != nil {
		t.Fatalf("BuildDependencies() error = %v", err)
	}

	run, ok := out.Runner.(*EvaluateRun)
	if !ok {
		t.Fatalf("runner type = %T, want *EvaluateRun", out.Runner)
	}
	if run.ObservationRepo != obsRepo {
		t.Fatalf("observation repo mismatch: got %#v want %#v", run.ObservationRepo, obsRepo)
	}
	if out.Config.Output == nil || out.Config.Stderr == nil {
		t.Fatalf("expected default output/stderr writers to be set, got output=%v stderr=%v", out.Config.Output, out.Config.Stderr)
	}
}

func TestBuildDependencies_PassesExemptionConfig(t *testing.T) {
	exemption := &policy.ExemptionConfig{
		Resources: []policy.ExemptionRule{
			{Pattern: "res-*", Reason: "test"},
		},
	}

	out, err := BuildDependencies(BuildDependenciesInput{
		Plan: EvaluationPlan{
			ControlsPath:     "/ctl",
			ObservationsPath: "/obs",
		},
		FindingMarshaler:  depsMarshalerStub{},
		EnrichFn:          depsEnrichFn,
		ObservationLoader: &depsObservationRepoStub{},
		ControlLoader:     &depsControlRepoStub{},
		ExemptionConfig:   exemption,
	})
	if err != nil {
		t.Fatalf("BuildDependencies() error = %v", err)
	}
	if out.Config.ExemptionConfig == nil || len(out.Config.ExemptionConfig.Resources) != 1 {
		t.Fatalf("expected exemption config to be passed through, got %#v", out.Config.ExemptionConfig)
	}
}
