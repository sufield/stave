package sirbridge

import (
	"cmp"
	"fmt"
	"slices"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/evaluation/engine"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/sir"
)

// EngineCoverageSource implements sir.CoverageSource by running
// engine.CoverageValidator over the per-(control, asset) lifecycle
// map already produced for SIR's exposure-window hydration.
// Validator verdicts are de-duplicated across controls (coverage
// is an asset/observation property, not a control property) so the
// SIR carries one row per (asset, reason) pair.
type EngineCoverageSource struct {
	validator       engine.CoverageValidator
	minRequiredSpan time.Duration
	maxAllowedGap   time.Duration
}

// NewEngineCoverageSource constructs a coverage source that grades
// against the supplied thresholds. The constructor delegates to
// engine.NewCoverageValidator so adapter and engine stay in lock-
// step on what a valid (minSpan, maxGap) pair looks like — a
// degenerate validator here would emit misleading SIR rows.
func NewEngineCoverageSource(minSpan, maxGap time.Duration) (*EngineCoverageSource, error) {
	v, err := engine.NewCoverageValidator(minSpan, maxGap)
	if err != nil {
		return nil, fmt.Errorf("create coverage validator: %w", err)
	}
	return &EngineCoverageSource{
		validator:       *v,
		minRequiredSpan: minSpan,
		maxAllowedGap:   maxGap,
	}, nil
}

// Coverage satisfies sir.CoverageSource. snapshots is accepted for
// interface conformance but unused: the lifecycle map already
// carries the per-asset observation stats the validator reads.
func (s *EngineCoverageSource) Coverage(_ []asset.Snapshot, lifecycles map[kernel.ControlID]map[asset.ID]*asset.ExposureLifecycle) (sir.CoverageReport, error) {
	report := sir.CoverageReport{
		Policy: sir.CoveragePolicy{
			MinRequiredSpan: s.minRequiredSpan,
			MaxAllowedGap:   s.maxAllowedGap,
		},
	}

	// Dedupe key: (asset, reason). The same asset's stats are
	// shared across every per-control lifecycle that observed it,
	// so the validator's verdict is identical too. Emitting once
	// per asset keeps the SIR row count proportional to coverage
	// gaps, not to controls × assets.
	type key struct {
		assetID string
		reason  string
	}
	seen := map[key]sir.CoverageGap{}

	for _, perAsset := range lifecycles {
		for assetID, lc := range perAsset {
			if lc == nil {
				continue
			}
			reason, ok := s.validator.IsSufficient(lc)
			if ok {
				continue
			}
			stats := lc.Stats()
			gap := sir.CoverageGap{
				AssetID: string(assetID),
				Start:   stats.FirstSeenAt(),
				End:     stats.LastSeenAt(),
				Reason:  reason,
			}
			seen[key{string(assetID), reason}] = gap
		}
	}

	if len(seen) > 0 {
		report.Gaps = make([]sir.CoverageGap, 0, len(seen))
		for _, g := range seen {
			report.Gaps = append(report.Gaps, g)
		}
		slices.SortFunc(report.Gaps, func(a, b sir.CoverageGap) int {
			if n := cmp.Compare(a.AssetID, b.AssetID); n != 0 {
				return n
			}
			if n := a.Start.Compare(b.Start); n != 0 {
				return n
			}
			return cmp.Compare(a.Reason, b.Reason)
		})
	}

	return report, nil
}
