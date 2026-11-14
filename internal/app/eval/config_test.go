package eval

import (
	"testing"
	"time"

	policy "github.com/sufield/stave/internal/core/controldef"
)

func TestNewConfig_SetsExpectedFields(t *testing.T) {
	plan := EvaluationPlan{
		ContextName:      "dev",
		ControlsPath:     "/tmp/ctl",
		ObservationsPath: "/tmp/obs",
	}
	cfg := NewConfig(plan,
		WithMaxUnsafeDuration(24*time.Hour),
	)

	if cfg.PolicySource != plan.ControlsPath || cfg.ObservationSource != plan.ObservationsPath {
		t.Fatalf("unexpected dirs: %+v", cfg)
	}
	if cfg.Metadata.ControlSource.Source != "dir" {
		t.Fatalf("ControlSource.Source = %q, want dir", cfg.Metadata.ControlSource.Source)
	}
	if cfg.Metadata.ResolvedPaths.Controls != plan.ControlsPath || cfg.Metadata.ResolvedPaths.Observations != plan.ObservationsPath {
		t.Fatalf("ResolvedPaths mismatch: %+v", cfg.Metadata.ResolvedPaths)
	}
}

func TestNewConfig_EndToEnd(t *testing.T) {
	plan := EvaluationPlan{
		ContextName:      "dev",
		ControlsPath:     "/ctl",
		ObservationsPath: "/obs",
	}
	filtered := []policy.ControlDefinition{
		{ID: "CTL.A", Severity: policy.SeverityCritical},
	}

	exceptionCfg := policy.NewExceptionConfig([]policy.ExceptionRule{
		{
			ControlID: "CTL.A",
			Reason:    "known issue",
		},
	})

	cfg := NewConfig(plan,
		WithMaxUnsafeDuration(24*time.Hour),
		WithExceptionConfig(exceptionCfg),
		WithPreloadedControls(filtered),
	)

	if cfg.ExceptionRules == nil || len(cfg.ExceptionRules.Rules()) != 1 {
		t.Fatalf("exception config = %#v", cfg.ExceptionRules)
	}
	if len(cfg.ActivePolicies) != 1 || cfg.ActivePolicies[0].ID != "CTL.A" {
		t.Fatalf("active policies = %#v", cfg.ActivePolicies)
	}
}
