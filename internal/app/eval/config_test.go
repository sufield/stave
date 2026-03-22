package eval

import (
	"io"
	"testing"
	"time"

	"github.com/sufield/stave/pkg/alpha/domain/evaluation"
	"github.com/sufield/stave/pkg/alpha/domain/kernel"
	"github.com/sufield/stave/pkg/alpha/domain/policy"
	clockadp "github.com/sufield/stave/pkg/alpha/domain/ports"
)

func TestNewConfig_SetsExpectedFields(t *testing.T) {
	plan := EvaluationPlan{
		ContextName:      "dev",
		ControlsPath:     "/tmp/ctl",
		ObservationsPath: "/tmp/obs",
	}
	clock := clockadp.FixedClock(time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC))
	cfg := NewConfig(plan,
		WithMaxUnsafeDuration(24*time.Hour),
		WithRuntime(io.Discard, io.Discard, clock, "test"),
		WithAllowUnknownInput(true),
	)

	if cfg.ControlsDir != plan.ControlsPath || cfg.ObservationsDir != plan.ObservationsPath {
		t.Fatalf("unexpected dirs: %+v", cfg)
	}
	if cfg.StaveVersion != "test" {
		t.Fatalf("StaveVersion = %q, want test", cfg.StaveVersion)
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
	invs := []policy.ControlDefinition{
		{ID: "CTL.A", Severity: policy.SeverityCritical},
		{ID: "CTL.B", Severity: policy.SeverityLow},
	}
	filtered, err := FilterControls(invs, ControlFilter{ControlID: kernel.ControlID("CTL.A")})
	if err != nil {
		t.Fatalf("FilterControls() error = %v", err)
	}

	exceptionCfg := policy.NewExceptionConfig([]policy.ExceptionRule{
		{
			ControlID: kernel.ControlID("CTL.A"),
			Reason:    "known issue",
		},
	})

	cfg := NewConfig(plan,
		WithMaxUnsafeDuration(24*time.Hour),
		WithRuntime(io.Discard, io.Discard, clockadp.FixedClock(time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)), "test"),
		WithExceptionConfig(exceptionCfg),
		WithPreloadedControls(filtered),
		WithGitMetadata(&evaluation.GitInfo{
			RepoRoot: "/repo",
			Head:     "abc123",
			Dirty:    true,
		}),
	)

	if cfg.ExceptionConfig == nil || len(cfg.ExceptionConfig.Rules) != 1 {
		t.Fatalf("exception config = %#v", cfg.ExceptionConfig)
	}
	if len(cfg.PreloadedControls) != 1 || cfg.PreloadedControls[0].ID != "CTL.A" {
		t.Fatalf("preloaded controls = %#v", cfg.PreloadedControls)
	}
	if cfg.Metadata.Git == nil || cfg.Metadata.Git.RepoRoot != "/repo" || cfg.Metadata.Git.Head != "abc123" {
		t.Fatalf("git metadata = %+v", cfg.Metadata.Git)
	}
}
