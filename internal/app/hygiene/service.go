package hygiene

import (
	"time"

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
) RiskStats {
	violations := 0
	if len(controls) > 0 && len(snapshots) > 0 {
		result := service.Evaluate(service.EvaluateInput{
			Controls:        controls,
			Snapshots:       snapshots,
			MaxUnsafe:       opts.GlobalMaxUnsafe,
			Clock:           fixedClock{now: opts.Now},
			ToolVersion:     opts.ToolVersion,
			PredicateParser: opts.PredicateParser,
		})
		violations = len(result.Findings)
	}
	summary := computeUpcomingSummary(controls, snapshots, opts)

	return RiskStats{
		CurrentViolations: violations,
		Overdue:           summary.Overdue,
		DueNow:            summary.DueNow,
		DueSoon:           summary.DueSoon,
		Later:             summary.Later,
		UpcomingTotal:     summary.Total,
	}
}

type upcomingSummary struct {
	Overdue int
	DueNow  int
	DueSoon int
	Later   int
	Total   int
}

func computeUpcomingSummary(
	controls []policy.ControlDefinition,
	snapshots []asset.Snapshot,
	opts RiskOptions,
) upcomingSummary {
	items := computeUpcomingItems(controls, snapshots, opts)
	items = applyUpcomingFilter(items, opts)
	return summarizeUpcoming(items, opts.DueSoonThreshold)
}

type upcomingItem struct {
	DueAt     time.Time
	Status    risk.Status
	Remaining time.Duration
	ControlID kernel.ControlID
	AssetType kernel.AssetType
}

type UpcomingFilter struct {
	controlIDs    map[kernel.ControlID]struct{}
	assetTypes map[kernel.AssetType]struct{}
	statuses      map[risk.Status]struct{}
	dueWithin     time.Duration
}

func applyUpcomingFilter(items []upcomingItem, opts RiskOptions) []upcomingItem {
	f := compileUpcomingFilter(opts)
	if !f.enabled() {
		return items
	}
	return fp.Filter(items, func(item upcomingItem) bool {
		return f.matchControl(item.ControlID) &&
			f.matchResourceType(item.AssetType) &&
			f.matchStatus(item.Status) &&
			f.matchDueWithin(item.Remaining)
	})
}

func compileUpcomingFilter(opts RiskOptions) UpcomingFilter {
	return UpcomingFilter{
		controlIDs:    fp.ToSet(opts.ControlIDs),
		assetTypes: fp.ToSet(opts.AssetTypes),
		statuses:      fp.ToSet(opts.Statuses),
		dueWithin:     derefDuration(opts.DueWithin),
	}
}

func (f UpcomingFilter) enabled() bool {
	return len(f.controlIDs) > 0 || len(f.assetTypes) > 0 || len(f.statuses) > 0 || f.dueWithin > 0
}

func (f UpcomingFilter) matchControl(id kernel.ControlID) bool {
	if len(f.controlIDs) == 0 {
		return true
	}
	_, ok := f.controlIDs[id]
	return ok
}

func (f UpcomingFilter) matchResourceType(rt kernel.AssetType) bool {
	if len(f.assetTypes) == 0 {
		return true
	}
	_, ok := f.assetTypes[rt]
	return ok
}

func (f UpcomingFilter) matchStatus(status risk.Status) bool {
	if len(f.statuses) == 0 {
		return true
	}
	_, ok := f.statuses[status]
	return ok
}

func (f UpcomingFilter) matchDueWithin(remaining time.Duration) bool {
	if f.dueWithin == 0 {
		return true
	}
	return remaining <= f.dueWithin
}

func computeUpcomingItems(
	controls []policy.ControlDefinition,
	snapshots []asset.Snapshot,
	opts RiskOptions,
) []upcomingItem {
	domainItems := risk.ComputeItems(risk.Request{
		Controls:        controls,
		Snapshots:       snapshots,
		GlobalMaxUnsafe: opts.GlobalMaxUnsafe,
		Now:             opts.Now,
		PredicateParser: opts.PredicateParser,
	})
	return fp.Map(domainItems, func(item risk.Item) upcomingItem {
		return upcomingItem{
			DueAt:     item.DueAt,
			Status:    item.Status,
			Remaining: item.Remaining,
			ControlID: item.ControlID,
			AssetType: item.AssetType,
		}
	})
}

func derefDuration(d *time.Duration) time.Duration {
	if d == nil {
		return 0
	}
	return *d
}

func summarizeUpcoming(items []upcomingItem, dueSoonThreshold time.Duration) upcomingSummary {
	var s upcomingSummary
	s.Total = len(items)
	for _, item := range items {
		switch item.Status {
		case risk.Overdue:
			s.Overdue++
		case risk.DueNow:
			s.DueNow++
		default:
			if item.Remaining > 0 && item.Remaining <= dueSoonThreshold {
				s.DueSoon++
			} else {
				s.Later++
			}
		}
	}
	return s
}
