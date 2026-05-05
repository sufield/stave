// Package shadow composes two evaluation.FindingSource
// implementations into a single source that returns the primary's
// findings while running the secondary in dark-launch mode for
// divergence observation.
//
// Architectural placement: this package lives under adapters/
// rather than core/ because the decorator's job is composing
// existing FindingSource interfaces — a shape that belongs at
// the integration boundary, not in the core domain. The
// composition itself imports nothing platform-specific; it
// stays adapter-clean.
package shadow

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/kernel"
)

// ShadowFindingSource runs two FindingSource implementations on
// every ProduceFindings call. The primary's result is returned
// to the caller verbatim; the secondary's result is compared to
// the primary's, divergence counts are logged at slog.LevelDebug,
// and the secondary's findings are discarded.
//
// Sequential execution by design: the secondary runs after the
// primary completes, capped by `timeout`. Concurrent execution
// would buy nothing during dark-launch validation while
// complicating context cancellation, log ordering, and divergence
// accounting. If concurrency becomes a real need post-launch,
// it should arrive as a deliberate, separate change.
type ShadowFindingSource struct {
	primary   evaluation.FindingSource
	secondary evaluation.FindingSource
	logger    *slog.Logger
	timeout   time.Duration
}

// NewShadowFindingSource constructs a shadow source. Logger may
// be nil — divergence reporting then routes to slog.Default.
// Timeout is the hard cap on secondary execution; non-positive
// values are treated as 30 seconds (matches Iter 2.4's
// STAVE_SHADOW_TIMEOUT default).
func NewShadowFindingSource(primary, secondary evaluation.FindingSource, logger *slog.Logger, timeout time.Duration) *ShadowFindingSource {
	if logger == nil {
		logger = slog.Default()
	}
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	return &ShadowFindingSource{
		primary:   primary,
		secondary: secondary,
		logger:    logger,
		timeout:   timeout,
	}
}

// ProduceFindings runs primary, then (if primary succeeded) the
// secondary under a bounded context. Secondary failures, panics,
// and timeouts are caught, logged, and never propagated — the
// user-visible report must look identical to a non-shadowed run.
func (s *ShadowFindingSource) ProduceFindings(ctx context.Context, req evaluation.FindingRequest) ([]evaluation.Finding, error) {
	if s == nil {
		return nil, errors.New("shadow: nil receiver")
	}
	if s.primary == nil {
		return nil, errors.New("shadow: primary source is required")
	}

	primaryStart := time.Now()
	primaryFindings, primaryErr := s.primary.ProduceFindings(ctx, req)
	primaryElapsed := time.Since(primaryStart)
	if primaryErr != nil {
		// Skip secondary on primary failure — there is nothing to
		// compare against, and running secondary would only add
		// noise to the log.
		return primaryFindings, primaryErr
	}

	// Secondary may be unset (the Iter 2.4 stub or a future
	// configuration that disables shadow comparison without
	// removing the wrapper). Skip silently — no divergence to
	// report and no timing of interest.
	if s.secondary == nil {
		return primaryFindings, nil
	}

	secondaryCtx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	secondaryFindings, secondaryElapsed, secondaryErr := s.runSecondary(secondaryCtx, req)
	missing, extra, severityDiff := compareFindings(primaryFindings, secondaryFindings)

	s.logger.Debug("shadow",
		slog.Int("primary_findings", len(primaryFindings)),
		slog.Duration("primary_elapsed", primaryElapsed),
		slog.Int("secondary_findings", len(secondaryFindings)),
		slog.Duration("secondary_elapsed", secondaryElapsed),
		slog.Int("diverge_missing", missing),
		slog.Int("diverge_extra", extra),
		slog.Int("diverge_severity", severityDiff),
		slog.Any("secondary_err", secondaryErr),
	)

	return primaryFindings, nil
}

// runSecondary invokes the secondary source and absorbs panics.
// A panic in the dark-launch source must NEVER reach the user's
// report — defer-recover swallows it and returns a typed error
// that the divergence log records.
func (s *ShadowFindingSource) runSecondary(ctx context.Context, req evaluation.FindingRequest) (out []evaluation.Finding, elapsed time.Duration, err error) {
	start := time.Now()
	defer func() {
		elapsed = time.Since(start)
		if r := recover(); r != nil {
			err = fmt.Errorf("shadow secondary panicked: %v", r)
			out = nil
		}
	}()
	out, err = s.secondary.ProduceFindings(ctx, req)
	return out, time.Since(start), err
}

// compareFindings returns the divergence summary between two
// finding sets keyed by (ControlID, AssetID):
//   - missing: present in primary, absent in secondary
//   - extra: present in secondary, absent in primary
//   - severityDiff: shared key but different ControlSeverity
func compareFindings(primary, secondary []evaluation.Finding) (missing, extra, severityDiff int) {
	type key struct {
		ControlID kernel.ControlID
		AssetID   string
	}
	primaryByKey := make(map[key]evaluation.Finding, len(primary))
	for i := range primary {
		k := key{ControlID: primary[i].ControlID, AssetID: string(primary[i].AssetID)}
		primaryByKey[k] = primary[i]
	}
	secondaryByKey := make(map[key]evaluation.Finding, len(secondary))
	for i := range secondary {
		k := key{ControlID: secondary[i].ControlID, AssetID: string(secondary[i].AssetID)}
		secondaryByKey[k] = secondary[i]
	}
	for k := range primaryByKey {
		if _, ok := secondaryByKey[k]; !ok {
			missing++
		}
	}
	for k := range secondaryByKey {
		sf := secondaryByKey[k]
		pf, ok := primaryByKey[k]
		if !ok {
			extra++
			continue
		}
		if pf.ControlSeverity != sf.ControlSeverity {
			severityDiff++
		}
	}
	return missing, extra, severityDiff
}

// Compile-time assertion.
var _ evaluation.FindingSource = (*ShadowFindingSource)(nil)
