package engine

import (
	"cmp"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/risk"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/ports"
)

// Runner executes evaluation logic over snapshots.
type Runner struct {
	Logger            *slog.Logger
	Controls          []policy.ControlDefinition
	MaxUnsafeDuration time.Duration
	// MaxGapThreshold controls when sparse observations become INCONCLUSIVE.
	// If zero, defaultRunnerMaxGapThreshold is used.
	MaxGapThreshold time.Duration
	Confidence      evaluation.ConfidenceCalculator
	Clock           ports.Clock
	Hasher          ports.Digester
	Exemptions      *policy.ExemptionConfig
	Exceptions      *policy.ExceptionConfig
	PredicateParser func(any) (*policy.UnsafePredicate, error)
	// CELEvaluator evaluates predicates using the CEL engine.
	// Required — the built-in predicate evaluator has been removed.
	CELEvaluator policy.PredicateEval
}

// Compile-time check: Runner satisfies strategyDeps.
var _ strategyDeps = (*Runner)(nil)

func (e *Runner) logger() *slog.Logger {
	if e.Logger != nil {
		return e.Logger
	}
	return slog.Default()
}

// maxUnsafeDurationFor returns the max unsafe duration for a control.
// Uses per-control override if set, otherwise falls back to CLI default.
func (e *Runner) maxUnsafeDurationFor(ctl *policy.ControlDefinition) time.Duration {
	return ctl.EffectiveMaxUnsafeDuration(e.MaxUnsafeDuration)
}

// predicateParser returns the configured predicate parser function.
func (e *Runner) predicateParser() policy.PredicateParser {
	return e.PredicateParser
}

// confidenceCalculator returns the configured confidence thresholds,
// defaulting to standard multipliers if not explicitly set.
func (e *Runner) confidenceCalculator() evaluation.ConfidenceCalculator {
	if e.Confidence.HighMultiplier > 0 && e.Confidence.MedMultiplier > 0 {
		return e.Confidence
	}
	return evaluation.DefaultConfidenceCalculator()
}

// normalizeSnapshots returns a copy of snapshots sorted by captured_at ascending.
func (e *Runner) normalizeSnapshots(snapshots []asset.Snapshot) []asset.Snapshot {
	sorted := slices.Clone(snapshots)
	slices.SortFunc(sorted, func(a, b asset.Snapshot) int {
		return a.CapturedAt.Compare(b.CapturedAt)
	})
	return sorted
}

// deterministicNow picks a deterministic "now" from sorted snapshots.
// Uses last snapshot's CapturedAt for reproducibility. Falls back to clock when empty.
func (e *Runner) deterministicNow(sorted []asset.Snapshot) time.Time {
	if len(sorted) > 0 {
		return sorted[len(sorted)-1].CapturedAt
	}
	return e.Clock.Now()
}

// EvaluateOptions holds per-run parameters that are not part of Runner's
// reusable configuration.
type EvaluateOptions struct {
	StaveVersion string
	InputHashes  *evaluation.InputHashes
}

// runSession holds the per-evaluation state that would otherwise be drilled
// through every helper call. It separates "what the engine is doing right now"
// from "how the engine is configured" (Runner).
type runSession struct {
	runner      *Runner
	snapshots   []asset.Snapshot // sorted by CapturedAt
	now         time.Time
	acc         *Accumulator
	identityIdx IdentityIndex
	opts        EvaluateOptions
}

// Evaluate processes snapshots and returns findings for unsafe duration violations.
func (e *Runner) Evaluate(snapshots []asset.Snapshot, opts ...EvaluateOptions) (evaluation.Audit, error) {
	if e.Clock == nil {
		return evaluation.Audit{}, errors.New("precondition failed: Runner.Evaluate requires non-nil Clock")
	}
	var opt EvaluateOptions
	if len(opts) > 0 {
		opt = opts[0]
	}
	sorted := e.normalizeSnapshots(snapshots)
	timelinesPerInv, err := BuildTimelinesPerControl(e.Controls, sorted, e.CELEvaluator)
	if err != nil {
		return evaluation.Audit{}, fmt.Errorf("build timelines: %w", err)
	}
	assetHint := 0
	if len(sorted) > 0 {
		assetHint = len(sorted[0].Assets)
	}

	sess := &runSession{
		runner:      e,
		snapshots:   sorted,
		now:         e.deterministicNow(sorted),
		acc:         NewAccumulator(assetHint),
		identityIdx: BuildIdentityIndex(sorted),
		opts:        opt,
	}

	for _, ctl := range e.Controls {
		// Skip control types the evaluator cannot process.
		if !ctl.IsEvaluatable() {
			sess.acc.AddSkippedControl(
				ctl.ID,
				ctl.Name,
				"type not evaluatable: "+ctl.Type.String(),
			)
			continue
		}
		sess.evaluateControl(&ctl, timelinesPerInv[ctl.ID])
	}

	return sess.buildResult(), nil
}

// evaluateControl evaluates a single control across all asset timelines.
func (s *runSession) evaluateControl(
	ctl *policy.ControlDefinition,
	timelines map[asset.ID]*asset.Timeline,
) {
	strategy := s.runner.strategyFor(ctl)
	// Deterministic iteration: sort asset IDs first.
	assetIDs := make([]asset.ID, 0, len(timelines))
	for id := range timelines {
		assetIDs = append(assetIDs, id)
	}
	slices.Sort(assetIDs)
	for _, assetID := range assetIDs {
		timeline := timelines[assetID]
		// Check if asset is exempted.
		if rule := s.runner.Exemptions.ShouldExempt(assetID); rule != nil {
			if s.acc.TrackExemption(assetID) {
				s.acc.AddExemptedAsset(assetID, rule.Pattern, rule.Reason)
			}
			s.acc.AddRow(evaluation.Row{
				ControlID:   ctl.ID,
				AssetID:     assetID,
				AssetType:   timeline.Asset().Type,
				AssetDomain: timeline.Asset().Type.Domain(),
				Decision:    evaluation.DecisionSkipped,
				Confidence:  evaluation.ConfidenceHigh,
				Reason:      rule.Reason,
			})
			continue
		}
		// Track assets that were actually evaluated (not exempted).
		s.acc.seenAssets.Add(assetID)
		if timeline.CurrentlyUnsafe() {
			s.acc.unsafeAssets.Add(assetID)
		}
		row, findings := strategy.Evaluate(timeline, s.now, s.identityIdx)
		s.acc.AddRow(row)
		s.acc.AddFindings(findings)
	}
}

// buildResult sorts accumulated data, computes risk, and constructs the final Audit.
func (s *runSession) buildResult() evaluation.Audit {
	// Sort findings for deterministic output.
	evaluation.SortFindings(s.acc.findings)
	// Sort exempted assets for deterministic output.
	slices.SortFunc(s.acc.exemptedByAst, func(a, b asset.ExemptedAsset) int {
		return cmp.Compare(a.ID, b.ID)
	})
	// Sort rows for deterministic output (by control_id, then asset_id).
	slices.SortFunc(s.acc.rows, func(a, b evaluation.Row) int {
		if c := cmp.Compare(a.ControlID, b.ControlID); c != 0 {
			return c
		}
		return cmp.Compare(a.AssetID, b.AssetID)
	})
	regularFindings, exceptedFindings := partitionFindings(s.acc.findings, s.runner.Exceptions, s.now)

	upcoming := risk.ComputeItems(risk.ThresholdRequest{
		Controls:                s.runner.Controls,
		Snapshots:               s.snapshots,
		GlobalMaxUnsafeDuration: s.runner.MaxUnsafeDuration,
		Now:                     s.now,
		PredicateEval:           s.runner.CELEvaluator,
	})
	status := evaluation.ClassifySafetyStatus(len(regularFindings), upcoming)

	return evaluation.Audit{
		Run: evaluation.RunInfo{
			StaveVersion:      s.opts.StaveVersion,
			Offline:           true,
			Now:               s.now,
			MaxUnsafeDuration: kernel.Duration(s.runner.MaxUnsafeDuration),
			Snapshots:         len(s.snapshots),
			InputHashes:       s.opts.InputHashes,
			PackHash:          s.runner.computePackHash(),
		},
		Summary: evaluation.Summary{
			AssetsEvaluated: len(s.acc.seenAssets),
			AttackSurface:   len(s.acc.unsafeAssets),
			Violations:      len(regularFindings),
		},
		SafetyStatus:     status,
		AtRisk:           upcoming,
		Findings:         regularFindings,
		ExceptedFindings: exceptedFindings,
		Skipped:          s.acc.skippedByCtl,
		ExemptedAssets:   s.acc.exemptedByAst,
		Rows:             s.acc.rows,
	}
}

// partitionFindings separates findings into regular and excepted based on active exception rules.
func partitionFindings(
	findings []evaluation.Finding,
	exceptions *policy.ExceptionConfig,
	now time.Time,
) ([]evaluation.Finding, []evaluation.ExceptedFinding) {
	var regular []evaluation.Finding
	var excepted []evaluation.ExceptedFinding
	for _, f := range findings {
		if rule := exceptions.ShouldExcept(f.ControlID, f.AssetID, now); rule != nil {
			excepted = append(excepted, evaluation.ExceptedFinding{
				ControlID: f.ControlID,
				AssetID:   f.AssetID,
				Reason:    rule.Reason,
				Expires:   rule.Expires,
			})
		} else {
			regular = append(regular, f)
		}
	}
	return regular, excepted
}

// computePackHash returns a deterministic SHA-256 hex digest of the evaluated
// control set, keyed on sorted control IDs. This enables auditability of
// which controls were active during an evaluation run.
func (e *Runner) computePackHash() kernel.Digest {
	if len(e.Controls) == 0 || e.Hasher == nil {
		return ""
	}
	ids := make([]string, len(e.Controls))
	for i, ctl := range e.Controls {
		ids[i] = string(ctl.ID)
	}
	slices.Sort(ids)
	return e.Hasher.Digest(ids, '\n')
}

// DefaultMaxGapThreshold is the conservative default for when sparse
// observations become INCONCLUSIVE. Override via Runner.MaxGapThreshold.
const DefaultMaxGapThreshold = 12 * time.Hour

func (e *Runner) maxGapThreshold() time.Duration {
	if e.MaxGapThreshold > 0 {
		return e.MaxGapThreshold
	}
	return DefaultMaxGapThreshold
}
