package apply

import (
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
	cfg := stave.Config{
		// Source paths: same fields cmd/apply has used for years,
		// surfaced through Plan + Opts after PreRunE resolution.
		SnapshotsDir: ec.Plan.ObservationsPath,
		ControlsDir:  ec.Plan.ControlsPath,
		ChainsDir:    "chains",

		MaxUnsafe:         ec.Params.maxUnsafeDuration,
		Now:               clockTime(deps.Config.Clock),
		AllowUnknownInput: ec.Opts.AllowUnknown,

		IntegrityManifest:  ec.Opts.IntegrityManifest,
		IntegrityPublicKey: ec.Opts.IntegrityPublicKey,

		// Already-loaded rule structs flow through unchanged.
		ExemptionRules:      deps.Config.ExemptionRules,
		AcknowledgmentRules: deps.Config.AcknowledgmentRules,
		SLAConfig:           toPublicSLAConfig(deps.Config.SLAConfig),

		// Decoration / wire-format fields preserved from deps so
		// JSON output stays byte-identical.
		GitMetadata: deps.Config.Metadata.Git,
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
