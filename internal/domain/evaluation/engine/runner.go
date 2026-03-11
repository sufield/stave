package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"sort"
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
	Exemptions      *policy.ExemptionConfig
	Suppressions    *policy.SuppressionConfig
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
func normalizeSnapshots(snapshots []asset.Snapshot) []asset.Snapshot {
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
func (e *Runner) Evaluate(snapshots []asset.Snapshot) evaluation.Result {
	if e.Clock == nil {
		panic("precondition failed: Runner.Evaluate requires non-nil Clock")
	}
	sorted := normalizeSnapshots(snapshots)
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

		e.evaluateControlAcrossTimelines(&ctl, timelinesPerInv[ctl.ID], now, acc)
	}

	return e.sortAndBuildResult(acc, now, len(snapshots))
}

// evaluateControlAcrossTimelines evaluates a single control across all asset timelines.
func (e *Runner) evaluateControlAcrossTimelines(
	ctl *policy.ControlDefinition,
	timelines map[string]*asset.Timeline,
	now time.Time,
	acc *Accumulator,
) {
	strategy := e.strategyFor(ctl)

	for assetID, timeline := range timelines {
		// Check if asset is exempted.
		if rule := e.Exemptions.ShouldExempt(assetID); rule != nil {
			if acc.TrackExemption(asset.ID(assetID)) {
				acc.AddSkippedAsset(asset.ID(assetID), rule.Pattern, rule.Reason)
			}
			acc.AddRow(evaluation.Row{
				ControlID:   ctl.ID,
				AssetID:     asset.ID(assetID),
				AssetType:   timeline.Asset().Type,
				AssetDomain: timeline.Asset().Type.Domain(),
				Decision:    evaluation.DecisionSkipped,
				Confidence:  evaluation.ConfidenceHigh,
				Reason:      rule.Reason,
			})
			continue
		}

		// Track assets that were actually evaluated (not exempted).
		acc.seenAssets.Add(asset.ID(assetID))

		if timeline.CurrentlyUnsafe() {
			acc.unsafeAssets.Add(asset.ID(assetID))
		}

		row, findings := strategy.Evaluate(timeline, now)
		acc.AddRow(row)
		acc.AddFindings(findings)
	}
}

// sortAndBuildResult sorts accumulated data and constructs the final Result.
func (e *Runner) sortAndBuildResult(acc *Accumulator, now time.Time, snapshotCount int) evaluation.Result {
	// Sort findings for deterministic output.
	evaluation.SortFindings(acc.findings)

	// Sort skipped assets for deterministic output.
	sort.Slice(acc.skippedByAst, func(i, j int) bool {
		return acc.skippedByAst[i].ID < acc.skippedByAst[j].ID
	})

	// Sort rows for deterministic output (by control_id, then asset_id).
	sort.Slice(acc.rows, func(i, j int) bool {
		if acc.rows[i].ControlID != acc.rows[j].ControlID {
			return acc.rows[i].ControlID < acc.rows[j].ControlID
		}
		return acc.rows[i].AssetID < acc.rows[j].AssetID
	})

	regularFindings, suppressedFindings := e.partitionFindings(acc.findings, now)

	return evaluation.Result{
		Run: evaluation.RunInfo{
			ToolVersion: e.ToolVersion,
			Offline:     true,
			Now:         now,
			MaxUnsafe:   kernel.Duration(e.MaxUnsafe),
			Snapshots:   snapshotCount,
			InputHashes: e.InputHashes,
			PackHash:    computePackHash(e.Controls),
		},
		Summary: evaluation.Summary{
			AssetsEvaluated: len(acc.seenAssets),
			AttackSurface:   len(acc.unsafeAssets),
			Violations:      len(regularFindings),
		},
		Findings:           regularFindings,
		SuppressedFindings: suppressedFindings,
		Skipped:            acc.skippedByCtl,
		SkippedAssets:      acc.skippedByAst,
		Rows:               acc.rows,
	}
}

// partitionFindings separates findings into regular and suppressed based on active suppression rules.
func (e *Runner) partitionFindings(findings []evaluation.Finding, now time.Time) (
	[]evaluation.Finding, []evaluation.SuppressedFinding,
) {
	var regular []evaluation.Finding
	var suppressed []evaluation.SuppressedFinding
	for _, f := range findings {
		if rule := e.Suppressions.ShouldSuppress(f.ControlID, f.AssetID, now); rule != nil {
			suppressed = append(suppressed, evaluation.SuppressedFinding{
				ControlID: f.ControlID,
				AssetID:   f.AssetID,
				Reason:    rule.Reason,
				Expires:   rule.Expires.String(),
			})
		} else {
			regular = append(regular, f)
		}
	}
	return regular, suppressed
}

// computePackHash returns a deterministic SHA-256 hex digest of the evaluated
// control set, keyed on sorted control IDs. This enables auditability of
// which controls were active during an evaluation run.
func computePackHash(controls []policy.ControlDefinition) kernel.Digest {
	if len(controls) == 0 {
		return ""
	}
	ids := make([]string, len(controls))
	for i, ctl := range controls {
		ids[i] = string(ctl.ID)
	}
	sort.Strings(ids)
	h := sha256.New()
	for _, id := range ids {
		h.Write([]byte(id))
		h.Write([]byte{'\n'})
	}
	return kernel.Digest(hex.EncodeToString(h.Sum(nil)))
}
