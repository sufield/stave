package eval

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/kernel"
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

func (depsMarshalerStub) MarshalFindings(*appcontracts.EnrichedResult) ([]byte, error) {
	return []byte(`{}`), nil
}

func depsEnrichFn(result *evaluation.ComplianceReport) (appcontracts.EnrichedResult, error) {
	return appcontracts.EnrichedResult{
		Result:         *result,
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

			_, err := BuildDependencies(context.Background(), &in)
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

	out, err := BuildDependencies(context.Background(), &BuildDependenciesInput{
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

	out, err := BuildDependencies(context.Background(), &BuildDependenciesInput{
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
	if out.Config.ExemptionRules == nil || len(out.Config.ExemptionRules.Assets) != 1 {
		t.Fatalf("expected exemption config to be passed through, got %#v", out.Config.ExemptionRules)
	}
}

// TestFilterResolvedChains_WarnsOnMissingRefs covers the fix for
// silent-drop tolerance: when a chain references a control not in
// the active set, the drop must be observable to users.
func TestFilterResolvedChains_WarnsOnMissingRefs(t *testing.T) {
	chains := []policy.ChainDefinition{
		{ID: "kept_chain", ControlIDs: []kernel.ControlID{"CTL.A.001", "CTL.A.002"}},
		{ID: "dropped_chain", ControlIDs: []kernel.ControlID{"CTL.A.001", "CTL.MISSING.001"}},
	}
	controls := []policy.ControlDefinition{{ID: "CTL.A.001"}, {ID: "CTL.A.002"}}

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))

	resolved := filterResolvedChains(chains, controls, logger)

	if len(resolved) != 1 || resolved[0].ID != "kept_chain" {
		t.Fatalf("want kept_chain only, got %+v", resolved)
	}
	logOut := buf.String()
	if !strings.Contains(logOut, "dropped_chain") {
		t.Errorf("warning should name the dropped chain; log: %q", logOut)
	}
	if !strings.Contains(logOut, "CTL.MISSING.001") {
		t.Errorf("warning should list the missing control; log: %q", logOut)
	}
	if strings.Contains(logOut, "kept_chain") {
		t.Errorf("warning should not mention the kept chain; log: %q", logOut)
	}
}

func TestFilterResolvedChains_SilentWhenAllRefsResolve(t *testing.T) {
	chains := []policy.ChainDefinition{
		{ID: "chain_a", ControlIDs: []kernel.ControlID{"CTL.A.001"}},
	}
	controls := []policy.ControlDefinition{{ID: "CTL.A.001"}}

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))

	resolved := filterResolvedChains(chains, controls, logger)

	if len(resolved) != 1 {
		t.Fatalf("want 1 resolved chain, got %d", len(resolved))
	}
	if buf.Len() > 0 {
		t.Errorf("no warning expected for fully-resolved chains; log: %q", buf.String())
	}
}
