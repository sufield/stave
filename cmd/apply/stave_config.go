package apply

import (
	"log/slog"
	"maps"
	"time"

	appeval "github.com/sufield/stave/internal/app/eval"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/pkg/stave"
)

// buildStaveConfig translates the cmd/apply runtime state (ec +
// already-built deps) into the public stave.Config shape that
// pkg/stave/cliapi.Apply expects.
//
// Every field is sourced from the same place builder.Build pulled
// it from, so cliapi.Apply produces a *evaluation.ComplianceReport
// byte-identical to what deps.Runner.PerformAssessment would have.
// The translation is plumbing — once this lands, cmd/apply's
// evaluation core is fully library-driven.
func buildStaveConfig(ec evalContext, deps *appeval.ApplyDeps) stave.Config {
	// Built-in catalog fallback: when --controls was not given and no
	// controls/ directory exists, pass an empty ControlsDir so the
	// applycore pipeline (resolveControls) selects the embedded catalog
	// instead of trying to load a non-existent directory.
	controlsDir := ec.Plan.ControlsPath
	if ec.UseBuiltinCatalog {
		controlsDir = ""
	}

	// Carry the loaded stave.yaml project config into the library path.
	// applycore.Run only resolves project-scoped settings (exceptions,
	// exclude_controls, enabled_control_packs) when this field is non-nil;
	// dropping it silently re-surfaced findings the user excepted in
	// stave.yaml and flipped the verdict to NON_COMPLIANT.
	//
	// The embedded pack registry was already built successfully by
	// builder.Build (deps_project.go) before executeEvaluation reaches
	// here, so the only error path — a corrupt embedded registry — is
	// unreachable in the live pipeline. If it ever fires, fail loud
	// (slog.Error) and still carry the exception / exclude settings so
	// the degraded mode is disclosed rather than silently dropping
	// stave.yaml entirely.
	var projectConfig *stave.ProjectConfigInput
	if ec.ProjectConfig != nil {
		pcInput, err := buildProjectConfigInput(ec.ProjectConfig, ec.Opts.controlsSet)
		if err != nil {
			slog.Error("build stave project config from loaded stave.yaml",
				"error", err,
				"note", "pack-based controls will not resolve; exceptions/exclude_controls still applied")
		}
		projectConfig = &pcInput
	}

	cfg := stave.Config{
		// Source paths: same fields cmd/apply has used for years,
		// surfaced through Plan + Opts after PreRunE resolution.
		SnapshotsDir: ec.Plan.ObservationsPath,
		ControlsDir:  controlsDir,
		ChainsDir:    "chains",

		MaxUnsafe: ec.Params.maxUnsafeDuration,
		Now:       clockTime(deps.Config.Clock),

		IntegrityManifest:  ec.Opts.IntegrityManifest,
		IntegrityPublicKey: ec.Opts.IntegrityPublicKey,

		// Already-loaded rule structs flow through unchanged.
		ExemptionRules:      deps.Config.ExemptionRules,
		AcknowledgmentRules: deps.Config.AcknowledgmentRules,
		SLAConfig:           toPublicSLAConfig(deps.Config.SLAConfig),

		// Project-scoped config (exceptions / exclude_controls /
		// enabled_control_packs) so applycore.Run resolves them.
		ProjectConfig: projectConfig,

		// Decoration / wire-format fields preserved from deps so
		// JSON output stays byte-identical.
		Tracer:      deps.Config.Tracer,
		ContextName: ec.Plan.ContextName,
	}
	return cfg
}

// clockTime returns the underlying time when the clock is a
// FixedClock, or the zero value (which the library treats as
// "use real wall clock") otherwise. cliapi.Apply will rebuild a
// FixedClock from a non-zero time so deterministic --now runs
// stay deterministic across the migration.
func clockTime(c interface{ Now() time.Time }) time.Time {
	if c == nil {
		return time.Time{}
	}
	return c.Now()
}

// toPublicSLAConfig is the inverse of pkg/stave/apply.go's
// toEvalSLAConfig — convert from the engine's evaluation.SLAConfig
// back to the public stave.SLAConfig the library accepts.
//
// Callers can pass nil directly into stave.Config.SLAConfig when
// no policy is configured; the conversion preserves the empty case.
func toPublicSLAConfig(c *evaluation.SLAConfig) *stave.SLAConfig {
	if c == nil {
		return nil
	}
	deadlines := make(map[string]float64, len(c.DeadlineBySeverity))
	maps.Copy(deadlines, c.DeadlineBySeverity)
	return &stave.SLAConfig{
		ProfileID:          c.ProfileID,
		DeadlineBySeverity: deadlines,
		EscalationFactor:   c.EscalationFactor,
	}
}
