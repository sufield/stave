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

const (
	StatusOverdue  ThresholdStatus = "OVERDUE"
	StatusDueNow   ThresholdStatus = "DUE_NOW"
	StatusUpcoming ThresholdStatus = "UPCOMING"
)

// AllThresholdStatuses returns all valid ThresholdStatus values as strings.
func AllThresholdStatuses() []string {
	return []string{string(StatusOverdue), string(StatusDueNow), string(StatusUpcoming)}
}

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

// ThresholdItems is a collection of upcoming risk it.
type ThresholdItems []ThresholdItem

// CountOverdue returns the number of items with OVERDUE status.
func (it ThresholdItems) CountOverdue() int {
	count := 0
	for _, item := range it {
		if item.Status == StatusOverdue {
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
	for _, item := range it {
		if c.matches(item) {
			out = append(out, item)
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
	for _, item := range it {
		switch item.Status {
		case StatusOverdue:
			s.Overdue++
		case StatusDueNow:
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

// ThresholdRequest provides the inputs required to compute upcoming risk.
type ThresholdRequest struct {
	Controls                []policy.ControlDefinition
	Snapshots               []asset.Snapshot
	GlobalMaxUnsafeDuration time.Duration
	Now                     time.Time
	PredicateParser         func(any) (*policy.UnsafePredicate, error) // kept for signature compat
	PredicateEval           policy.PredicateEval
}

type assetState struct {
	FirstUnsafeAt   time.Time
	LastSeenUnsafe  time.Time
	CurrentlyUnsafe bool
	AssetType       kernel.AssetType
}

// ComputeItems returns deterministic upcoming threshold items for currently-unsafe assets.
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
	for _, ctl := range req.Controls {
		if ctl.Type != policy.TypeUnsafeDuration && ctl.Type != policy.TypeUnsafeState {
			continue
		}

		threshold := ctl.EffectiveMaxUnsafeDuration(req.GlobalMaxUnsafeDuration)
		states := computeAssetStates(ctl, sortedSnaps, req.PredicateEval)

		// 3. Convert states to risk items
		for id, st := range states {
			if !st.CurrentlyUnsafe || st.FirstUnsafeAt.IsZero() {
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
) map[asset.ID]*assetState {
	states := make(map[asset.ID]*assetState)

	for _, snap := range snapshots {
		for _, a := range snap.Assets {
			st, ok := states[a.ID]
			if !ok {
				st = &assetState{AssetType: a.Type}
				states[a.ID] = st
			}

			isUnsafe := false
			if eval != nil {
				if result, err := eval(ctl, a, snap.Identities); err == nil {
					isUnsafe = result
				}
			}

			if isUnsafe {
				if st.FirstUnsafeAt.IsZero() {
					st.FirstUnsafeAt = snap.CapturedAt
				}
				st.LastSeenUnsafe = snap.CapturedAt
				st.CurrentlyUnsafe = true
			} else {
				// Reset streak
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
