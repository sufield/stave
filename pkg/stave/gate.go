package stave

import (
	"context"
	"errors"
	"fmt"
	"time"

	artifact "github.com/sufield/stave/internal/adapters/artifacts"
	stavecel "github.com/sufield/stave/internal/adapters/cel"
	"github.com/sufield/stave/internal/adapters/observations"
	appcontracts "github.com/sufield/stave/internal/app/contracts"
	infragate "github.com/sufield/stave/internal/app/gate"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/ports"
	"github.com/sufield/stave/internal/core/usecase"
)

// GatePolicy selects the CI failure rule the gate enforces.
// Mirrored as string constants so library callers don't have to
// import the underlying internal/app/config package.
type GatePolicy string

// Gate policy constants. Wire-compatible with the engine's policy
// strings — passed through usecase.Gate untouched.
const (
	// GateFailOnAnyViolation fails when the evaluation has any findings.
	GateFailOnAnyViolation GatePolicy = "fail_on_any_violation"

	// GateFailOnNewViolation fails when current findings include any
	// not present in the baseline.
	GateFailOnNewViolation GatePolicy = "fail_on_new_violation"

	// GateFailOnOverdueUpcoming fails when the controls + observations
	// would surface any upcoming actions whose deadline has passed.
	GateFailOnOverdueUpcoming GatePolicy = "fail_on_overdue_upcoming"
)

// GateConfig parameterizes a [Gate] call.
//
// Different policies need different inputs:
//   - GateFailOnAnyViolation: EvaluationPath
//   - GateFailOnNewViolation: EvaluationPath + BaselinePath
//   - GateFailOnOverdueUpcoming: ControlsDir + ObservationsDir + MaxUnsafe
//
// Now overrides the wall clock for reproducible runs / tests; zero
// uses the real clock. Sanitizer is optional — when nil, baseline
// comparison sees raw IDs.
type GateConfig struct {
	Policy          GatePolicy
	EvaluationPath  string
	BaselinePath    string
	ControlsDir     string
	ObservationsDir string
	MaxUnsafe       time.Duration
	Now             time.Time
	Sanitizer       kernel.Sanitizer
}

// GateResult is the outcome of a [Gate] call.
type GateResult struct {
	// Policy echoes the policy that was evaluated.
	Policy GatePolicy

	// Passed is true when the policy allowed the change.
	Passed bool

	// merged tracks whether MergeTeamVerdict has been invoked at
	// least once. Without it, a freshly zero-valued GateResult that
	// nobody seeded would default Passed=false, but any caller that
	// reads `r.Passed` straight after constructing the zero value
	// would see a spurious FAIL with no Reason. Internal field —
	// MergeTeamVerdict / Gate are the only writers.
	merged bool `json:"-"`

	// Reason is the short human-readable explanation, suitable for
	// CI output. Always populated.
	Reason string

	// CheckedAt is the wall-clock (or Now-overridden) time the gate
	// ran.
	CheckedAt time.Time

	// CurrentViolations is the count of findings in the evaluation
	// artifact (any/new policies) or 0 (overdue policy).
	CurrentViolations int

	// NewViolations is the count of findings not present in the
	// baseline. Only set under GateFailOnNewViolation.
	NewViolations int

	// OverdueCount is the number of upcoming actions whose deadline
	// has passed. Only set under GateFailOnOverdueUpcoming.
	OverdueCount int
}

// PassLabel returns the canonical "PASS" / "FAIL" string used by CLI
// renderers. Centralised so cmd/enforce/gate doesn't open-code the
// ternary at every render site.
func (r *GateResult) PassLabel() string {
	if r.Passed {
		return "PASS"
	}
	return "FAIL"
}

// ExitError translates the gate result into the error sentinel CI
// gates expect: nil on pass, appcontracts.ErrViolationsFound on fail.
// The cmd/enforce/gate runner returns this directly so the
// pkg/stave consumer and the CLI runner share one source of truth
// for exit-code mapping.
func (r *GateResult) ExitError() error {
	if r.Passed {
		return nil
	}
	return appcontracts.ErrViolationsFound
}

// MergeTeamVerdict folds a per-team gate result into this global
// result. A failing team flips Passed to false and appends a
// "team <ID>: <reason>" suffix to Reason; a passing team is a no-op.
// Centralises the AND-merge so cmd/enforce/gate stops mutating
// Passed and Reason inline at the call site.
//
// teamID identifies the source team, teamPassed reflects the team's
// own gate verdict, and teamReason carries the team-side failure
// description. Empty teamReason is fine — Reason still flips to
// the "team X" prefix so the global verdict surfaces the source.
func (r *GateResult) MergeTeamVerdict(teamID string, teamPassed bool, teamReason string) {
	if r == nil {
		return
	}
	// Track that at least one verdict has been observed; without
	// this, a GateResult that nobody mutates would report Passed
	// based on whatever its zero-value happens to be. A passing
	// team also counts as a verdict — the gate has data, it's
	// just clean.
	if !r.merged {
		r.merged = true
		r.Passed = true
	}
	if teamPassed {
		return
	}
	merged := "team " + teamID
	if teamReason != "" {
		merged += ": " + teamReason
	}
	if !r.Passed && r.Reason != "" {
		r.Reason = r.Reason + "; " + merged
	} else {
		r.Reason = merged
	}
	r.Passed = false
}

// Gate enforces a CI failure policy and returns the gate result.
// Wires the same FindingsCounter / BaselineComparer / OverdueCounter
// adapters the CLI uses, so library and CLI agree on every verdict.
//
// Tests that want determinism set GateConfig.Now and pre-place
// fixtures at the path inputs.
func Gate(ctx context.Context, cfg GateConfig) (*GateResult, error) {
	if cfg.Policy == "" {
		return nil, errors.New("stave.Gate: GateConfig.Policy is required")
	}

	loader := artifact.NewLoader()

	findingsCounter, err := infragate.NewFindingsCounter(loader.Evaluation)
	if err != nil {
		return nil, fmt.Errorf("stave.Gate: wire findings counter: %w", err)
	}
	baselineComparer, err := infragate.NewBaselineComparer(
		cfg.Sanitizer,
		loader.Evaluation,
		loader.Baseline,
		func(san kernel.Sanitizer, baseEntries []evaluation.BaselineEntry, currentFindings []remediation.Finding) infragate.BaselineComparisonResult {
			bc := artifact.CompareAgainstBaseline(san, baseEntries, currentFindings)
			return infragate.BaselineComparisonResult{
				Current:    bc.Current,
				Comparison: bc.Comparison,
			}
		},
	)
	if err != nil {
		return nil, fmt.Errorf("stave.Gate: wire baseline comparer: %w", err)
	}
	overdueCounter, err := infragate.NewOverdueCounter(
		func(ctx context.Context, obsDir, ctlDir string) (infragate.Assets, error) {
			return loadAssetsForGate(ctx, obsDir, ctlDir)
		},
		stavecel.NewPredicateEval,
	)
	if err != nil {
		return nil, fmt.Errorf("stave.Gate: wire overdue counter: %w", err)
	}

	req := usecase.GateRequest{
		Policy:            string(cfg.Policy),
		EvaluationPath:    cfg.EvaluationPath,
		BaselinePath:      cfg.BaselinePath,
		ControlsDir:       cfg.ControlsDir,
		ObservationsDir:   cfg.ObservationsDir,
		MaxUnsafeDuration: cfg.MaxUnsafe,
	}
	if !cfg.Now.IsZero() {
		now := cfg.Now
		req.Now = &now
	}
	deps := usecase.GateDeps{
		FindingsCounter:  findingsCounter,
		BaselineComparer: baselineComparer,
		OverdueCounter:   overdueCounter,
		Clock:            ports.RealClock{},
	}
	resp, err := usecase.Gate(ctx, req, deps)
	if err != nil {
		return nil, err
	}
	return &GateResult{
		Policy: GatePolicy(resp.Policy),
		Passed: resp.Passed,
		// merged=true: the engine has already determined Passed, so a
		// subsequent MergeTeamVerdict must AND-merge with it instead of
		// re-seeding Passed=true (which would erase an engine-side FAIL
		// the first time a team verdict folds in).
		merged:            true,
		Reason:            resp.Reason,
		CheckedAt:         resp.CheckedAt,
		CurrentViolations: resp.CurrentViolations,
		NewViolations:     resp.NewViolations,
		OverdueCount:      resp.OverdueUpcoming,
	}, nil
}

// loadAssetsForGate loads observations and controls for the
// overdue-counter policy. Wraps the snapshot + control loaders the
// engine uses so cmd/enforce/gate and pkg/stave.Gate agree on what
// "loaded assets" means.
func loadAssetsForGate(ctx context.Context, obsDir, ctlDir string) (infragate.Assets, error) {
	controls, ctlRepo, err := resolveControls(ctlDir)
	if err != nil {
		return infragate.Assets{}, err
	}
	if ctlRepo != nil {
		loaded, loadErr := ctlRepo.LoadControls(ctx, ctlDir)
		if loadErr != nil {
			return infragate.Assets{}, fmt.Errorf("load controls: %w", loadErr)
		}
		controls = loaded
	}

	obsLoader := observations.NewObservationLoader()
	obsResult, err := obsLoader.LoadSnapshots(ctx, obsDir)
	if err != nil {
		return infragate.Assets{}, fmt.Errorf("load observations: %w", err)
	}

	return infragate.Assets{
		Snapshots: obsResult.Snapshots,
		Controls:  controls,
	}, nil
}
