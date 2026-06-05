package apply

import (
	"testing"
	"time"

	appconfig "github.com/sufield/stave/internal/app/config"
	appeval "github.com/sufield/stave/internal/app/eval"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/ports"
)

// Test_RedGate_ProjectConfigDropped asserts the CORRECT behavior for
// buildStaveConfig (stave_config.go:31): the stave.Config it builds for
// the LIVE evaluation path (cliapi.Apply -> applycore.Run) must carry
// the project-scoped config when the apply run loaded one.
//
// evalContext.ProjectConfig holds the parsed stave.yaml (exceptions,
// exclude_controls, enabled_control_packs). applycore.Run only runs
// appeval.ResolveProjectConfig when stave.Config.ProjectConfig != nil
// (runner.go:179). buildStaveConfig never sets that field, so every
// stave.yaml project-scoped setting is silently dropped before reaching
// the evaluator: a finding the user excepted in stave.yaml still appears
// and flips the verdict to NON_COMPLIANT.
//
// This white-box unit test feeds buildStaveConfig an evalContext whose
// ProjectConfig is non-nil (a stave.yaml with an `exceptions:` entry)
// and asserts the resulting stave.Config.ProjectConfig is non-nil.
// Against current code the field is nil, so the test fails (RED).
func Test_RedGate_ProjectConfigDropped(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("panic in buildStaveConfig: %v", r)
		}
	}()

	// A loaded stave.yaml project policy with a project-scoped
	// exception — exactly the input that must survive into the live
	// evaluation path so the excepted finding is suppressed.
	projCfg := &appconfig.WorkspacePolicy{
		Exceptions: []appconfig.PolicyException{
			{ControlID: "CTL.S3.PUBLIC.001", AssetID: "my-bucket", Reason: "risk-accepted"},
		},
		ExcludeControls: []kernel.ControlID{"CTL.S3.LOGGING.001"},
	}

	ec := evalContext{
		Opts:          &Options{},
		Plan:          &appeval.EvaluationPlan{ControlsPath: "/ctl", ObservationsPath: "/obs", ContextName: "stave"},
		ProjectConfig: projCfg,
	}
	deps := &appeval.ApplyDeps{
		Config: appeval.AssessmentConfig{
			Clock: ports.FixedClock(time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)),
		},
	}

	cfg := buildStaveConfig(ec, deps)

	// CORRECT behavior: the project config flows into stave.Config so
	// applycore.Run resolves exceptions / exclude_controls. nil here
	// means stave.yaml is dropped before evaluation.
	if cfg.ProjectConfig == nil {
		t.Fatalf("buildStaveConfig dropped stave.yaml ProjectConfig: cfg.ProjectConfig is nil, so applycore.Run never runs ResolveProjectConfig and excepted/excluded controls still flip the verdict to NON_COMPLIANT")
	}
}
