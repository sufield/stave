package apply

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
	"time"

	appconfig "github.com/sufield/stave/internal/app/config"
	appeval "github.com/sufield/stave/internal/app/eval"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/ports"
)

// Test_Mut_BuildStaveConfig_NoErrorLogOnHappyPath pins the disclosed-fallback
// contract the projectConfig fix established in buildStaveConfig
// (stave_config.go): the embedded pack registry builds successfully in the
// live pipeline, so buildProjectConfigInput returns a nil error and the
// `if err != nil` guard at stave_config.go:48 must be FALSE — no slog.Error
// is emitted. The fix comment is explicit: the error path is "unreachable in
// the live pipeline" and must "fail loud (slog.Error)" ONLY if a corrupt
// registry ever fires.
//
// Negating that guard to `if err == nil` (the surviving CONDITIONALS_NEGATION
// at stave_config.go:48:10) inverts it: on a clean stave.yaml load the mutant
// emits the "build stave project config" error log on every single apply run,
// permanently signalling degraded mode where none exists. This test captures
// the global slog default and asserts that log does NOT appear on the happy
// path, killing the mutant.
func Test_Mut_BuildStaveConfig_NoErrorLogOnHappyPath(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("panic in buildStaveConfig: %v", r)
		}
	}()

	// Swap the global slog default for a capturing handler, restore on exit.
	// The package suite runs serially (no t.Parallel here, gremlins uses
	// --workers 1) so the global swap is safe.
	prev := slog.Default()
	defer slog.SetDefault(prev)
	var buf bytes.Buffer
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelError})))

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

	// The happy path must carry the project config (sanity: confirms we
	// exercised the projectConfig branch at all, so the log assertion is
	// meaningful and not vacuously satisfied by an unrelated code path).
	if cfg.ProjectConfig == nil {
		t.Fatalf("buildStaveConfig dropped ProjectConfig on the happy path")
	}

	// CORRECT behavior: no error log on a clean stave.yaml load. The
	// mutant (err == nil) emits the "build stave project config" error
	// on every successful build.
	if logged := buf.String(); strings.Contains(logged, "build stave project config from loaded stave.yaml") {
		t.Fatalf("buildStaveConfig emitted an error log on the happy path (embedded registry built successfully); degraded-mode disclosure must fire only on a real registry failure.\nlogged: %s", logged)
	}
}
