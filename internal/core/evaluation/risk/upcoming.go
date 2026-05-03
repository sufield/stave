package risk

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
)

// ThresholdStatus represents urgency for when an unsafe threshold is due.
type ThresholdStatus string

// StatusOverdue and related constants.
const (
	// StatusOverdue constants.
	StatusOverdue  ThresholdStatus = "OVERDUE"
	StatusDueNow   ThresholdStatus = "DUE_NOW"
	StatusUpcoming ThresholdStatus = "UPCOMING"
)

// ValidateStatuses normalizes and validates a slice of status strings.
func ValidateStatuses(statuses []string) ([]ThresholdStatus, error) {
	out := make([]ThresholdStatus, 0, len(statuses))
	for _, raw := range statuses {
		norm := ThresholdStatus(strings.ToUpper(strings.TrimSpace(raw)))
		switch norm {
		case "":
			continue
		case StatusOverdue, StatusDueNow, StatusUpcoming:
			out = append(out, norm)
		default:
			return nil, fmt.Errorf("invalid status %q (expected: OVERDUE, DUE_NOW, UPCOMING)", raw)
		}
	}
	return out, nil
}

// ThresholdItem captures one control/asset threshold approaching or exceeding its limit.
type ThresholdItem struct {
	DueAt          time.Time
	Status         ThresholdStatus
	Remaining      time.Duration
	ControlID      kernel.ControlID
	AssetID        asset.ID
	AssetType      kernel.AssetType
	FirstUnsafeAt  time.Time
	LastSeenUnsafe time.Time
	Threshold      time.Duration
}

// IsOverdue reports whether this item has crossed its SLA
// threshold. Wraps the (Status == StatusOverdue) probe so
// counters and summary builders stop comparing the field to a
// constant directly.
func (t *ThresholdItem) IsOverdue() bool {
	return t != nil && t.Status == StatusOverdue
}

// ThresholdItems is a collection of upcoming risk it.
type ThresholdItems []ThresholdItem

// CountOverdue returns the number of items with OVERDUE status.
func (it ThresholdItems) CountOverdue() int {
	count := 0
	for i := range it {
		if it[i].IsOverdue() {
			count++
		}
	}
	return count
}

// HasAnyRisk reports whether any item is overdue, due now, or upcoming.
func (it ThresholdItems) HasAnyRisk() bool {
	return len(it) > 0
}

// ThresholdSummary holds aggregate counts of risk items bucketed by urgency.
type ThresholdSummary struct {
	Overdue int
	DueNow  int
	DueSoon int
	Later   int
	Total   int
}

// ThresholdFilter specifies which items to include in a view.
type ThresholdFilter struct {
	ControlIDs   map[kernel.ControlID]struct{}
	AssetTypes   map[kernel.AssetType]struct{}
	Statuses     map[ThresholdStatus]struct{}
	MaxRemaining time.Duration
}

// Filter returns items matching the criteria.
func (it ThresholdItems) Filter(c ThresholdFilter) ThresholdItems {
	if len(it) == 0 {
		return nil
	}

	out := make(ThresholdItems, 0, len(it))
	for i := range it {
		threshold := &it[i]
		if c.matches(*threshold) {
			out = append(out, *threshold)
		}
	}
	return out
}

func (c ThresholdFilter) matches(item ThresholdItem) bool {
	if len(c.ControlIDs) > 0 {
		if _, ok := c.ControlIDs[item.ControlID]; !ok {
			return false
		}
	}
	if len(c.AssetTypes) > 0 {
		if _, ok := c.AssetTypes[item.AssetType]; !ok {
			return false
		}
	}
	if len(c.Statuses) > 0 {
		if _, ok := c.Statuses[item.Status]; !ok {
			return false
		}
	}
	if c.MaxRemaining > 0 && item.Remaining > c.MaxRemaining {
		return false
	}
	return true
}

// Summarize buckets items by urgency relative to a "due soon" threshold.
func (it ThresholdItems) Summarize(dueSoonThreshold time.Duration) ThresholdSummary {
	var s ThresholdSummary
	s.Total = len(it)
	for i := range it {
		threshold := &it[i]
		switch threshold.Status {
		case StatusOverdue:
			s.Overdue++
		case StatusDueNow:
			s.DueNow++
		default:
			if threshold.Remaining > 0 && threshold.Remaining <= dueSoonThreshold {
				s.DueSoon++
			} else {
				s.Later++
			}
		}
	}
	return s
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
func ComputeItems(req ThresholdRequest) ThresholdItems {
	if len(req.Snapshots) == 0 || len(req.Controls) == 0 {
		return nil
	}

	// 1. Prepare snapshots
	sortedSnaps := slices.Clone(req.Snapshots)
	slices.SortFunc(sortedSnaps, func(a, b asset.Snapshot) int {
		return a.CapturedAt.Compare(b.CapturedAt)
	})

	// 2. Identify relevant controls
	var items ThresholdItems
	for i := range req.Controls {
		ctl := &req.Controls[i]
		if !ctl.IsTemporalControl() {
			continue
		}

		threshold := ctl.EffectiveMaxUnsafeDuration(req.GlobalMaxUnsafeDuration)
		states := computeAssetStates(*ctl, sortedSnaps, req.PredicateEval, req.Exemptions)

		// 3. Convert states to risk items
		for id, st := range states {
			if !st.CurrentlyUnsafe || st.FirstUnsafeAt.IsZero() {
				continue
			}
			if _, suppressed := req.SuppressedFindings[SuppressionKey{ControlID: ctl.ID, AssetID: id}]; suppressed {
				continue
			}

			dueAt := st.FirstUnsafeAt.Add(threshold).UTC()
			items = append(items, ThresholdItem{
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
	ctl policy.ControlDefinition,
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
			result, evalErr := eval(ctl, a, snap.Identities)
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

func classifyStatus(now, dueAt time.Time) ThresholdStatus {
	if now.After(dueAt) {
		return StatusOverdue
	}
	if now.Equal(dueAt) {
		return StatusDueNow
	}
	return StatusUpcoming
}

func sortItems(items ThresholdItems) {
	rank := func(s ThresholdStatus) int {
		switch s {
		case StatusOverdue:
			return 0
		case StatusDueNow:
			return 1
		default:
			return 2
		}
	}

	slices.SortFunc(items, func(a, b ThresholdItem) int {
		return cmp.Or(
			a.DueAt.Compare(b.DueAt),
			cmp.Compare(rank(a.Status), rank(b.Status)),
			cmp.Compare(string(a.ControlID), string(b.ControlID)),
			cmp.Compare(string(a.AssetID), string(b.AssetID)),
			cmp.Compare(string(a.AssetType), string(b.AssetType)),
		)
	})
}
