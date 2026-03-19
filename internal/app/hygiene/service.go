package hygiene

import (
	"time"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
	service "github.com/sufield/stave/internal/app/service"
	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/evaluation/risk"
	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/domain/policy"
	"github.com/sufield/stave/internal/domain/ports"
	"github.com/sufield/stave/internal/pkg/fp"
)

// RiskOptions configures how risk metrics should be computed for a
// hygiene report.
type RiskOptions struct {
	GlobalMaxUnsafe  time.Duration
	Now              time.Time
	DueSoonThreshold time.Duration
	ToolVersion      string
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
		result, err := service.Evaluate(service.EvaluateInput{
			Controls:        controls,
			Snapshots:       snapshots,
			MaxUnsafe:       opts.GlobalMaxUnsafe,
			Clock:           fixedClock{now: opts.Now},
			ToolVersion:     opts.ToolVersion,
			PredicateParser: opts.PredicateParser,
			CELEvaluator:    opts.CELEvaluator,
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
		Controls:        controls,
		Snapshots:       snapshots,
		GlobalMaxUnsafe: opts.GlobalMaxUnsafe,
		Now:             opts.Now,
		PredicateParser: opts.PredicateParser,
		PredicateEval:   opts.CELEvaluator,
	})
	items = items.Filter(risk.FilterCriteria{
		ControlIDs:   fp.ToSet(opts.ControlIDs),
		AssetTypes:   fp.ToSet(opts.AssetTypes),
		Statuses:     fp.ToSet(opts.Statuses),
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
