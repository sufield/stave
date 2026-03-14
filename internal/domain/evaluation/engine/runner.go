package engine

import (
	"cmp"
	"errors"
	"slices"
	"time"

	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/evaluation"
	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/domain/policy"
	"github.com/sufield/stave/internal/domain/ports"
)

// Runner executes evaluation logic over snapshots.
type Runner struct {
	Controls  []policy.ControlDefinition
	MaxUnsafe time.Duration
	// MaxGapThreshold controls when sparse observations become INCONCLUSIVE.
	// If zero, defaultRunnerMaxGapThreshold is used.
	MaxGapThreshold time.Duration
	Clock           ports.Clock
	Hasher          ports.Digester
	Exemptions      *policy.ExemptionConfig
	Exceptions      *policy.ExceptionConfig
	ToolVersion     string
	InputHashes     *evaluation.InputHashes
	PredicateParser func(any) (*policy.UnsafePredicate, error)
}

// getMaxUnsafeForControl returns the max unsafe duration for a control.
// Uses per-control override if set, otherwise falls back to CLI default.
func (e *Runner) getMaxUnsafeForControl(ctl *policy.ControlDefinition) time.Duration {
	return ctl.EffectiveMaxUnsafe(e.MaxUnsafe)
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

	timelinesPerInv := BuildTimelinesPerControl(e.Controls, sorted, e.PredicateParser)

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

	return e.buildResult(acc, now, len(snapshots)), nil
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
		if rule := e.Exemptions.ShouldExempt(string(assetID)); rule != nil {
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

// buildResult sorts accumulated data and constructs the final Result.
func (e *Runner) buildResult(acc *Accumulator, now time.Time, snapshotCount int) evaluation.Result {
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

	return evaluation.Result{
		Run: evaluation.RunInfo{
			ToolVersion: e.ToolVersion,
			Offline:     true,
			Now:         now,
			MaxUnsafe:   kernel.Duration(e.MaxUnsafe),
			Snapshots:   snapshotCount,
			InputHashes: e.InputHashes,
			PackHash:    e.computePackHash(),
		},
		Summary: evaluation.Summary{
			AssetsEvaluated: len(acc.seenAssets),
			AttackSurface:   len(acc.unsafeAssets),
			Violations:      len(regularFindings),
		},
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
