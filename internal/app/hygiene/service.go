package hygiene

import (
	"time"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
	appworkflow "github.com/sufield/stave/internal/app/workflow"
	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation/risk"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/ports"
)

// RiskOptions configures how risk metrics should be computed for a
// hygiene report.
type RiskOptions struct {
	GlobalMaxUnsafeDuration time.Duration
	Now                     time.Time
	DueSoonThreshold        time.Duration
	StaveVersion            string
	// Optional filters for upcoming metrics (empty = no filter).
	ControlIDs      []kernel.ControlID
	AssetTypes      []kernel.AssetType
	Statuses        []risk.ThresholdStatus
	DueWithin       *time.Duration
	PredicateParser func(any) (*policy.UnsafePredicate, error)
	CELEvaluator    policy.PredicateEval
}

// Service encapsulates the core calculations used by snapshot hygiene
// reports. It operates purely on domain types so it can be reused by different
// frontends (CLI, APIs, tests).
type Service struct{}

type fixedClock struct {
	now time.Time
}

var _ ports.Clock = fixedClock{}

func (c fixedClock) Now() time.Time {
	return c.now
}

// ComputeRisk calculates snapshot risk metrics for the given controls and
// snapshots under the provided options.
func (s *Service) ComputeRisk(
	controls []policy.ControlDefinition,
	snapshots []asset.Snapshot,
	opts RiskOptions,
) appcontracts.RiskStats {
	violations := 0
	if len(controls) > 0 && len(snapshots) > 0 {
		result, err := appworkflow.Evaluate(appworkflow.EvaluateInput{
			Controls:          controls,
			Snapshots:         snapshots,
			MaxUnsafeDuration: opts.GlobalMaxUnsafeDuration,
			Clock:             fixedClock{now: opts.Now},
			StaveVersion:      opts.StaveVersion,
			PredicateParser:   opts.PredicateParser,
			CELEvaluator:      opts.CELEvaluator,
		})
		if err != nil {
			return appcontracts.RiskStats{}
		}
		violations = len(result.Findings)
	}
	summary := computeUpcomingSummary(controls, snapshots, opts)

	return appcontracts.NewRiskStats(violations, summary)
}

func computeUpcomingSummary(
	controls []policy.ControlDefinition,
	snapshots []asset.Snapshot,
	opts RiskOptions,
) risk.ThresholdSummary {
	items := risk.ComputeItems(risk.ThresholdRequest{
		Controls:                controls,
		Snapshots:               snapshots,
		GlobalMaxUnsafeDuration: opts.GlobalMaxUnsafeDuration,
		Now:                     opts.Now,
		PredicateEval:           opts.CELEvaluator,
	})
	var controlIDSet map[kernel.ControlID]struct{}
	if len(opts.ControlIDs) > 0 {
		controlIDSet = make(map[kernel.ControlID]struct{}, len(opts.ControlIDs))
		for _, item := range opts.ControlIDs {
			controlIDSet[item] = struct{}{}
		}
	}

	var assetTypeSet map[kernel.AssetType]struct{}
	if len(opts.AssetTypes) > 0 {
		assetTypeSet = make(map[kernel.AssetType]struct{}, len(opts.AssetTypes))
		for _, item := range opts.AssetTypes {
			assetTypeSet[item] = struct{}{}
		}
	}

	var statusSet map[risk.ThresholdStatus]struct{}
	if len(opts.Statuses) > 0 {
		statusSet = make(map[risk.ThresholdStatus]struct{}, len(opts.Statuses))
		for _, item := range opts.Statuses {
			statusSet[item] = struct{}{}
		}
	}

	items = items.Filter(risk.ThresholdFilter{
		ControlIDs:   controlIDSet,
		AssetTypes:   assetTypeSet,
		Statuses:     statusSet,
		MaxRemaining: derefDuration(opts.DueWithin),
	})
	return items.Summarize(opts.DueSoonThreshold)
}

func derefDuration(d *time.Duration) time.Duration {
	if d == nil {
		return 0
	}
	return *d
}
