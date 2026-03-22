package hygiene

import (
	"time"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
	appworkflow "github.com/sufield/stave/internal/app/workflow"
	"github.com/sufield/stave/pkg/alpha/domain/asset"
	"github.com/sufield/stave/pkg/alpha/domain/evaluation/risk"
	"github.com/sufield/stave/pkg/alpha/domain/kernel"
	"github.com/sufield/stave/pkg/alpha/domain/policy"
	"github.com/sufield/stave/pkg/alpha/domain/ports"
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
	Statuses        []risk.Status
	DueWithin       *time.Duration
	PredicateParser func(any) (*policy.UnsafePredicate, error)
	CELEvaluator    policy.PredicateEval
}

// Service encapsulates the core calculations used by snapshot hygiene
// reports. It operates purely on domain types so it can be reused by different
// frontends (CLI, APIs, tests).
type Service struct{}

// NewService constructs a new Service.
func NewService() *Service {
	return &Service{}
}

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
) risk.Summary {
	items := risk.ComputeItems(risk.Request{
		Controls:                controls,
		Snapshots:               snapshots,
		GlobalMaxUnsafeDuration: opts.GlobalMaxUnsafeDuration,
		Now:                     opts.Now,
		PredicateParser:         opts.PredicateParser,
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

	var statusSet map[risk.Status]struct{}
	if len(opts.Statuses) > 0 {
		statusSet = make(map[risk.Status]struct{}, len(opts.Statuses))
		for _, item := range opts.Statuses {
			statusSet[item] = struct{}{}
		}
	}

	items = items.Filter(risk.FilterCriteria{
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
