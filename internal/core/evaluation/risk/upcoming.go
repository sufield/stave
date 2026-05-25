package risk

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	findingsdata "github.com/sufield/stave/internal/core/findings"
	"github.com/sufield/stave/internal/core/kernel"
)

// ValidateStatuses normalizes and validates a slice of status strings.
// Stays in risk/ — it's a producer-side helper, not a data shape.
func ValidateStatuses(statuses []string) ([]findingsdata.ThresholdStatus, error) {
	out := make([]findingsdata.ThresholdStatus, 0, len(statuses))
	for _, raw := range statuses {
		norm := findingsdata.ThresholdStatus(strings.ToUpper(strings.TrimSpace(raw)))
		switch norm {
		case "":
			continue
		case findingsdata.StatusOverdue, findingsdata.StatusDueNow, findingsdata.StatusUpcoming:
			out = append(out, norm)
		default:
			return nil, fmt.Errorf("invalid status %q (expected: OVERDUE, DUE_NOW, UPCOMING)", raw)
		}
	}
	return out, nil
}

// ThresholdRequest provides the inputs required to compute upcoming risk.
type ThresholdRequest struct {
	Controls                []policy.ControlDefinition
	Snapshots               []asset.Snapshot
	GlobalMaxUnsafeDuration time.Duration
	Now                     time.Time
	PredicateEval           policy.PredicateEval
	// Exemptions is optional; when set, exempted assets are skipped
	// from risk computation just as they are skipped from the main
	// finding pipeline. Without this, exempted assets could surface
	// as risk signals and still flip overall posture to AT_RISK.
	Exemptions *policy.ExemptionConfig
	// SuppressedFindings is an optional set of (controlID, assetID)
	// pairs that have been excepted or acknowledged at the report
	// boundary. ComputeItems skips matching items so a fully-
	// acknowledged report does not produce AT_RISK posture via
	// upcoming threshold signals. Distinct from Exemptions, which
	// suppress the asset entirely; Suppression is per-(control,asset).
	SuppressedFindings map[SuppressionKey]struct{}
}

// SuppressionKey is the (control, asset) tuple used to mark a finding
// as already accepted by the operator (via security exception or
// acknowledgment) so risk signal computation can skip it.
type SuppressionKey struct {
	ControlID kernel.ControlID
	AssetID   asset.ID
}

type assetState struct {
	FirstUnsafeAt   time.Time
	LastSeenUnsafe  time.Time
	LastObservedAt  time.Time
	CurrentlyUnsafe bool
	AssetType       kernel.AssetType
}

// ComputeItems returns deterministic upcoming threshold items for
// currently-unsafe assets.
//
// Suppression model: callers pass `SuppressedFindings` for the
// (control, asset) pairs the operator has already accepted via
// exception or acknowledgment. Those pairs are excluded from the
// returned items so a fully-accepted-risk report cannot flip
// overall posture to AT_RISK via the upcoming-threshold signal
// path. The earlier shape generated signals from raw control
// applicability, ignoring acceptance state — accepting risk did
// not erase the AT_RISK posture, which is the wrong default for
// most operators (the "I have decided this is OK" workflow).
func ComputeItems(req ThresholdRequest) findingsdata.ThresholdItems {
	if len(req.Snapshots) == 0 || len(req.Controls) == 0 {
		return nil
	}

	// 1. Prepare snapshots
	sortedSnaps := slices.Clone(req.Snapshots)
	slices.SortFunc(sortedSnaps, func(a, b asset.Snapshot) int {
		return a.CapturedAt.Compare(b.CapturedAt)
	})

	// 2. Identify relevant controls
	var items findingsdata.ThresholdItems
	for i := range req.Controls {
		ctl := &req.Controls[i]
		if !ctl.IsTemporalControl() {
			continue
		}

		threshold := ctl.EffectiveMaxUnsafeDuration(req.GlobalMaxUnsafeDuration)
		states := computeAssetStates(ctl, sortedSnaps, req.PredicateEval, req.Exemptions)

		// 3. Convert states to risk items
		for id, st := range states {
			if !st.CurrentlyUnsafe || st.FirstUnsafeAt.IsZero() {
				continue
			}
			if _, suppressed := req.SuppressedFindings[SuppressionKey{ControlID: ctl.ID, AssetID: id}]; suppressed {
				continue
			}

			dueAt := st.FirstUnsafeAt.Add(threshold).UTC()
			items = append(items, findingsdata.ThresholdItem{
				DueAt:          dueAt,
				Status:         classifyStatus(req.Now, dueAt),
				Remaining:      dueAt.Sub(req.Now),
				ControlID:      ctl.ID,
				AssetID:        id,
				AssetType:      st.AssetType,
				FirstUnsafeAt:  st.FirstUnsafeAt.UTC(),
				LastSeenUnsafe: st.LastSeenUnsafe.UTC(),
				Threshold:      threshold,
			})
		}
	}

	// 4. Deterministic Sort
	sortItems(items)
	return items
}

func computeAssetStates(
	ctl *policy.ControlDefinition,
	snapshots []asset.Snapshot,
	eval policy.PredicateEval,
	exemptions *policy.ExemptionConfig,
) map[asset.ID]*assetState {
	states := make(map[asset.ID]*assetState)

	// Pre-stringify the control's scope tags once outside the
	// per-asset loop. Vendor applicability flows through the
	// shared helper kernel.AppliesToVendor — the single source
	// of truth shared with engine/lifecycles.go.
	ctlTags := slices.Clone(ctl.ScopeTags)

	for _, snap := range snapshots {
		for _, a := range snap.Assets {
			// Vendor applicability filter — a control scoped to
			// one vendor must not produce risk signals against
			// assets of another vendor.
			if !kernel.AppliesToVendor(ctlTags, a.Vendor) {
				continue
			}

			// Asset-level exemptions: an exempted asset must not
			// surface as a risk signal, mirroring the main
			// finding pipeline's exemption check in
			// engine/assessor.go.
			if exemptions != nil && exemptions.ShouldExempt(a.ID) != nil {
				continue
			}

			st, ok := states[a.ID]
			if !ok {
				st = &assetState{AssetType: a.Type}
				states[a.ID] = st
			}

			// Record that we observed the asset in this snapshot
			// regardless of whether the evaluator runs or returns an
			// error. The main lifecycle's RecordInconclusive does the
			// same — it advances lastObservedAt while preserving the
			// exposure window — and the risk view must agree with the
			// main view about which snapshots saw which assets.
			if snap.CapturedAt.After(st.LastObservedAt) || st.LastObservedAt.IsZero() {
				st.LastObservedAt = snap.CapturedAt
			}

			if eval == nil {
				continue
			}
			result, evalErr := eval(*ctl, a, snap.Identities)
			if evalErr != nil {
				// Inconclusive evaluation — freeze streak, do not reset.
				// LastObservedAt above keeps the asset in the risk
				// view so coverage does not diverge from the main
				// lifecycle, which records inconclusives explicitly.
				continue
			}

			if result {
				if st.FirstUnsafeAt.IsZero() {
					st.FirstUnsafeAt = snap.CapturedAt
				}
				st.LastSeenUnsafe = snap.CapturedAt
				st.CurrentlyUnsafe = true
			} else {
				// Confirmed safe — reset streak.
				st.FirstUnsafeAt = time.Time{}
				st.LastSeenUnsafe = time.Time{}
				st.CurrentlyUnsafe = false
			}
		}
	}
	return states
}

func classifyStatus(now, dueAt time.Time) findingsdata.ThresholdStatus {
	if now.After(dueAt) {
		return findingsdata.StatusOverdue
	}
	if now.Equal(dueAt) {
		return findingsdata.StatusDueNow
	}
	return findingsdata.StatusUpcoming
}

func sortItems(items findingsdata.ThresholdItems) {
	rank := func(s findingsdata.ThresholdStatus) int {
		switch s {
		case findingsdata.StatusOverdue:
			return 0
		case findingsdata.StatusDueNow:
			return 1
		default:
			return 2
		}
	}

	slices.SortFunc(items, func(a, b findingsdata.ThresholdItem) int {
		// Status rank is the primary key so all Overdue items sort
		// before all DueNow items, and DueNow before later. The
		// previous primary-by-DueAt order interleaved overdue rows
		// with sufficiently-old upcoming ones — operators reading
		// the list expected "what's blown the deadline" at the top
		// regardless of how long blown.
		return cmp.Or(
			cmp.Compare(rank(a.Status), rank(b.Status)),
			a.DueAt.Compare(b.DueAt),
			cmp.Compare(string(a.ControlID), string(b.ControlID)),
			cmp.Compare(string(a.AssetID), string(b.AssetID)),
			cmp.Compare(string(a.AssetType), string(b.AssetType)),
		)
	})
}
