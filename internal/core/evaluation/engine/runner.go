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
//
// Fields are grouped by concern:
//   - Infrastructure: long-lived services (Logger, Clock, Hasher, CELEvaluator)
//   - Policy: the rules being evaluated (Controls, Exemptions, Exceptions)
//   - Thresholds: per-run parameters from CLI flags (MaxUnsafeDuration, MaxGapThreshold)
type Runner struct {
	// Infrastructure — stateless services injected at construction.
	Logger          *slog.Logger
	Clock           ports.Clock
	Hasher          ports.Digester
	CELEvaluator    policy.PredicateEval
	PredicateParser func(any) (*policy.UnsafePredicate, error)
	Confidence      evaluation.ConfidenceCalculator

	// Policy — the ruleset for this evaluation run.
	Controls   []policy.ControlDefinition
	Exemptions *policy.ExemptionConfig
	Exceptions *policy.ExceptionConfig

	// Thresholds — per-run parameters, typically from CLI flags.
	MaxUnsafeDuration time.Duration
	MaxGapThreshold   time.Duration // If zero, defaultRunnerMaxGapThreshold is used.
}

// NewRunner creates a Runner with sensible defaults for optional fields.
// Callers should set required fields (Controls, CELEvaluator) after construction.
func NewRunner() *Runner {
	return &Runner{
		Logger:          slog.Default(),
		MaxGapThreshold: DefaultMaxGapThreshold,
		Confidence:      evaluation.DefaultConfidenceCalculator(),
	}
}

// Compile-time check: Runner satisfies strategyDeps.
var _ strategyDeps = (*Runner)(nil)

func (e *Runner) logger() *slog.Logger { return e.Logger }

// maxUnsafeDurationFor returns the max unsafe duration for a control.
// Uses per-control override if set, otherwise falls back to CLI default.
func (e *Runner) maxUnsafeDurationFor(ctl *policy.ControlDefinition) time.Duration {
	return ctl.EffectiveMaxUnsafeDuration(e.MaxUnsafeDuration)
}

// predicateParser returns the configured predicate parser function.
func (e *Runner) predicateParser() policy.PredicateParser {
	return e.PredicateParser
}

func (e *Runner) confidenceCalculator() evaluation.ConfidenceCalculator { return e.Confidence }

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
func (e *Runner) Evaluate(snapshots []asset.Snapshot, opts ...EvaluateOptions) (evaluation.ComplianceReport, error) {
	if e.Clock == nil {
		return evaluation.ComplianceReport{}, errors.New("precondition failed: Runner.Evaluate requires non-nil Clock")
	}
	var opt EvaluateOptions
	if len(opts) > 0 {
		opt = opts[0]
	}
	sorted := e.normalizeSnapshots(snapshots)
	timelinesPerInv, err := BuildTimelinesPerControl(e.Controls, sorted, e.CELEvaluator)
	if err != nil {
		return evaluation.ComplianceReport{}, fmt.Errorf("build timelines: %w", err)
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
			s.acc.AddRow(evaluation.ResourceCheck{
				ControlID:   ctl.ID,
				AssetID:     assetID,
				AssetType:   timeline.Asset().Type,
				AssetDomain: timeline.Asset().Type.Domain(),
				Verdict:     evaluation.VerdictSkipped,
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
		observation, findings := strategy.Evaluate(timeline, s.now, s.identityIdx)
		s.acc.AddRow(observation)
		s.acc.AddFindings(findings)
	}
}

// buildResult sorts accumulated data, computes risk, and constructs the final ComplianceReport.
func (s *runSession) buildResult() evaluation.ComplianceReport {
	// Sort findings for deterministic output.
	evaluation.SortFindings(s.acc.findings)
	// Sort exempted assets for deterministic output.
	slices.SortFunc(s.acc.exemptedByAst, func(a, b asset.ExemptedAsset) int {
		return cmp.Compare(a.ID, b.ID)
	})
	// Sort rows for deterministic output (by control_id, then asset_id).
	slices.SortFunc(s.acc.rows, func(a, b evaluation.ResourceCheck) int {
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
	status := evaluation.DeriveSecurityState(len(regularFindings), upcoming)

	return evaluation.ComplianceReport{
		Run: evaluation.RunInfo{
			StaveVersion:      s.opts.StaveVersion,
			Offline:           true,
			Now:               s.now,
			MaxUnsafeDuration: kernel.Duration(s.runner.MaxUnsafeDuration),
			Snapshots:         len(s.snapshots),
			InputHashes:       s.opts.InputHashes,
			PackHash:          s.runner.computePackHash(),
		},
		Summary: evaluation.ComplianceSummary{
			TotalAssets:      len(s.acc.seenAssets),
			ExposedResources: len(s.acc.unsafeAssets),
			Violations:       len(regularFindings),
		},
		SecurityState:    status,
		RiskSignals:      upcoming,
		Findings:         regularFindings,
		ExceptedFindings: exceptedFindings,
		SkippedControls:  s.acc.skippedByCtl,
		ExemptedAssets:   s.acc.exemptedByAst,
		Checks:           s.acc.rows,
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

func (e *Runner) maxGapThreshold() time.Duration { return e.MaxGapThreshold }
