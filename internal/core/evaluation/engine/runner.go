package engine

import (
	"cmp"
	"errors"
	"fmt"
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
	Controls          []policy.ControlDefinition
	MaxUnsafeDuration time.Duration
	// MaxGapThreshold controls when sparse observations become INCONCLUSIVE.
	// If zero, defaultRunnerMaxGapThreshold is used.
	MaxGapThreshold time.Duration
	Clock           ports.Clock
	Hasher          ports.Digester
	Exemptions      *policy.ExemptionConfig
	Exceptions      *policy.ExceptionConfig
	StaveVersion    string
	InputHashes     *evaluation.InputHashes
	PredicateParser func(any) (*policy.UnsafePredicate, error)
	// CELEvaluator evaluates predicates using the CEL engine.
	// Required — the built-in predicate evaluator has been removed.
	CELEvaluator policy.PredicateEval
	// identitiesByTime maps snapshot capture times to their identities.
	// Set during Evaluate so finding generation can look up the identities
	// from the snapshot where the asset was last seen unsafe.
	identitiesByTime map[time.Time][]asset.CloudIdentity
}

// identitiesAt returns the identities from the snapshot captured at the given time.
// Falls back to the latest snapshot's identities if no exact match is found.
func (e *Runner) identitiesAt(t time.Time) []asset.CloudIdentity {
	if ids, ok := e.identitiesByTime[t]; ok {
		return ids
	}
	// Fallback: find the closest snapshot at or before t.
	var best time.Time
	for capturedAt := range e.identitiesByTime {
		if !capturedAt.After(t) && capturedAt.After(best) {
			best = capturedAt
		}
	}
	if !best.IsZero() {
		return e.identitiesByTime[best]
	}
	return nil
}

// getMaxUnsafeDurationForControl returns the max unsafe duration for a control.
// Uses per-control override if set, otherwise falls back to CLI default.
func (e *Runner) getMaxUnsafeDurationForControl(ctl *policy.ControlDefinition) time.Duration {
	return ctl.EffectiveMaxUnsafeDuration(e.MaxUnsafeDuration)
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

// Evaluate processes snapshots and returns findings for unsafe duration violations.
func (e *Runner) Evaluate(snapshots []asset.Snapshot) (evaluation.Result, error) {
	if e.Clock == nil {
		return evaluation.Result{}, errors.New("precondition failed: Runner.Evaluate requires non-nil Clock")
	}
	sorted := e.normalizeSnapshots(snapshots)
	now := e.deterministicNow(sorted)
	e.identitiesByTime = make(map[time.Time][]asset.CloudIdentity, len(sorted))
	for i := range sorted {
		e.identitiesByTime[sorted[i].CapturedAt] = sorted[i].Identities
	}
	timelinesPerInv, err := BuildTimelinesPerControl(e.Controls, sorted, e.CELEvaluator)
	if err != nil {
		return evaluation.Result{}, fmt.Errorf("build timelines: %w", err)
	}
	assetHint := 0
	if len(sorted) > 0 {
		assetHint = len(sorted[0].Assets)
	}
	acc := NewAccumulator(assetHint)
	for _, ctl := range e.Controls {
		// Skip control types the evaluator cannot process.
		if !ctl.IsEvaluatable() {
			acc.AddSkippedControl(
				ctl.ID,
				ctl.Name,
				"type not evaluatable: "+ctl.Type.String(),
			)
			continue
		}
		e.evaluateControl(&ctl, timelinesPerInv[ctl.ID], now, acc)
	}
	return e.buildResult(acc, sorted, now, len(snapshots)), nil
}

// evaluateControl evaluates a single control across all asset timelines.
func (e *Runner) evaluateControl(
	ctl *policy.ControlDefinition,
	timelines map[asset.ID]*asset.Timeline,
	now time.Time,
	acc *Accumulator,
) {
	strategy := e.strategyFor(ctl)
	// Deterministic iteration: sort asset IDs first.
	assetIDs := make([]asset.ID, 0, len(timelines))
	for id := range timelines {
		assetIDs = append(assetIDs, id)
	}
	slices.Sort(assetIDs)
	for _, assetID := range assetIDs {
		timeline := timelines[assetID]
		// Check if asset is exempted.
		if rule := e.Exemptions.ShouldExempt(assetID); rule != nil {
			if acc.TrackExemption(assetID) {
				acc.AddExemptedAsset(assetID, rule.Pattern, rule.Reason)
			}
			acc.AddRow(evaluation.Row{
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
		acc.seenAssets.Add(assetID)
		if timeline.CurrentlyUnsafe() {
			acc.unsafeAssets.Add(assetID)
		}
		row, findings := strategy.Evaluate(timeline, now)
		acc.AddRow(row)
		acc.AddFindings(findings)
	}
}

// buildResult sorts accumulated data, computes risk, and constructs the final Result.
func (e *Runner) buildResult(acc *Accumulator, snapshots []asset.Snapshot, now time.Time, snapshotCount int) evaluation.Result {
	// Sort findings for deterministic output.
	evaluation.SortFindings(acc.findings)
	// Sort exempted assets for deterministic output.
	slices.SortFunc(acc.exemptedByAst, func(a, b asset.ExemptedAsset) int {
		return cmp.Compare(a.ID, b.ID)
	})
	// Sort rows for deterministic output (by control_id, then asset_id).
	slices.SortFunc(acc.rows, func(a, b evaluation.Row) int {
		if c := cmp.Compare(a.ControlID, b.ControlID); c != 0 {
			return c
		}
		return cmp.Compare(a.AssetID, b.AssetID)
	})
	regularFindings, exceptedFindings := e.partitionFindings(acc.findings, now)

	upcoming := risk.ComputeItems(risk.ThresholdRequest{
		Controls:                e.Controls,
		Snapshots:               snapshots,
		GlobalMaxUnsafeDuration: e.MaxUnsafeDuration,
		Now:                     now,
		PredicateEval:           e.CELEvaluator,
	})
	status := evaluation.ClassifySafetyStatus(len(regularFindings), upcoming)

	return evaluation.Result{
		Run: evaluation.RunInfo{
			StaveVersion:      e.StaveVersion,
			Offline:           true,
			Now:               now,
			MaxUnsafeDuration: kernel.Duration(e.MaxUnsafeDuration),
			Snapshots:         snapshotCount,
			InputHashes:       e.InputHashes,
			PackHash:          e.computePackHash(),
		},
		Summary: evaluation.Summary{
			AssetsEvaluated: len(acc.seenAssets),
			AttackSurface:   len(acc.unsafeAssets),
			Violations:      len(regularFindings),
		},
		SafetyStatus:     status,
		AtRisk:           upcoming,
		Findings:         regularFindings,
		ExceptedFindings: exceptedFindings,
		Skipped:          acc.skippedByCtl,
		ExemptedAssets:   acc.exemptedByAst,
		Rows:             acc.rows,
	}
}

// partitionFindings separates findings into regular and excepted based on active exception rules.
func (e *Runner) partitionFindings(findings []evaluation.Finding, now time.Time) (
	[]evaluation.Finding, []evaluation.ExceptedFinding,
) {
	var regular []evaluation.Finding
	var excepted []evaluation.ExceptedFinding
	for _, f := range findings {
		if rule := e.Exceptions.ShouldExcept(f.ControlID, f.AssetID, now); rule != nil {
			excepted = append(excepted, evaluation.ExceptedFinding{
				ControlID: f.ControlID,
				AssetID:   f.AssetID,
				Reason:    rule.Reason,
				Expires:   rule.Expires.String(),
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
