package risk

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/domain/policy"
)

// Status represents urgency for when an unsafe threshold is due.
type Status string

const (
	StatusOverdue  Status = "OVERDUE"
	StatusDueNow   Status = "DUE_NOW"
	StatusUpcoming Status = "UPCOMING"
)

// ValidateStatuses normalizes and validates a slice of status strings.
func ValidateStatuses(statuses []string) ([]Status, error) {
	out := make([]Status, 0, len(statuses))
	for _, raw := range statuses {
		norm := Status(strings.ToUpper(strings.TrimSpace(raw)))
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

// Item captures one control/asset threshold approaching or exceeding its limit.
type Item struct {
	DueAt          time.Time
	Status         Status
	Remaining      time.Duration
	ControlID      kernel.ControlID
	AssetID        asset.ID
	AssetType      kernel.AssetType
	FirstUnsafeAt  time.Time
	LastSeenUnsafe time.Time
	Threshold      time.Duration
}

// Items is a collection of upcoming risk items.
type Items []Item

// CountOverdue returns the number of items with OVERDUE status.
func (items Items) CountOverdue() int {
	count := 0
	for _, item := range items {
		if item.Status == StatusOverdue {
			count++
		}
	}
	return count
}

// HasAnyRisk reports whether any item is overdue, due now, or upcoming.
func (items Items) HasAnyRisk() bool {
	return len(items) > 0
}

// Summary holds aggregate counts of risk items bucketed by urgency.
type Summary struct {
	Overdue int
	DueNow  int
	DueSoon int
	Later   int
	Total   int
}

// FilterCriteria specifies which items to include in a view.
type FilterCriteria struct {
	ControlIDs   map[kernel.ControlID]struct{}
	AssetTypes   map[kernel.AssetType]struct{}
	Statuses     map[Status]struct{}
	MaxRemaining time.Duration
}

// Filter returns items matching the criteria.
func (items Items) Filter(c FilterCriteria) Items {
	if len(items) == 0 {
		return nil
	}

	out := make(Items, 0, len(items))
	for _, item := range items {
		if c.matches(item) {
			out = append(out, item)
		}
	}
	return out
}

func (c FilterCriteria) matches(item Item) bool {
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
func (items Items) Summarize(dueSoonThreshold time.Duration) Summary {
	var s Summary
	s.Total = len(items)
	for _, item := range items {
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

// Request provides the inputs required to compute upcoming risk.
type Request struct {
	Controls        []policy.ControlDefinition
	Snapshots       []asset.Snapshot
	GlobalMaxUnsafe time.Duration
	Now             time.Time
	PredicateParser func(any) (*policy.UnsafePredicate, error)
}

type assetState struct {
	FirstUnsafeAt   time.Time
	LastSeenUnsafe  time.Time
	CurrentlyUnsafe bool
	AssetType       kernel.AssetType
}

// ComputeItems returns deterministic upcoming threshold items for currently-unsafe assets.
func ComputeItems(req Request) Items {
	if len(req.Snapshots) == 0 || len(req.Controls) == 0 {
		return nil
	}

	// 1. Prepare snapshots
	sortedSnaps := slices.Clone(req.Snapshots)
	slices.SortFunc(sortedSnaps, func(a, b asset.Snapshot) int {
		return a.CapturedAt.Compare(b.CapturedAt)
	})

	// 2. Identify relevant controls
	var items Items
	for _, ctl := range req.Controls {
		if ctl.Type != policy.TypeUnsafeDuration && ctl.Type != policy.TypeUnsafeState {
			continue
		}

		threshold := ctl.EffectiveMaxUnsafe(req.GlobalMaxUnsafe)
		states := computeAssetStates(ctl, sortedSnaps, req.PredicateParser)

		// 3. Convert states to risk items
		for id, st := range states {
			if !st.CurrentlyUnsafe || st.FirstUnsafeAt.IsZero() {
				continue
			}

			dueAt := st.FirstUnsafeAt.Add(threshold).UTC()
			items = append(items, Item{
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
	parser func(any) (*policy.UnsafePredicate, error),
) map[asset.ID]*assetState {
	states := make(map[asset.ID]*assetState)

	for _, snap := range snapshots {
		for _, a := range snap.Assets {
			st, ok := states[a.ID]
			if !ok {
				st = &assetState{AssetType: a.Type}
				states[a.ID] = st
			}

			ctx := policy.NewAssetEvalContextWithIdentities(a, policy.ControlParams(ctl.Params), snap.Identities)
			ctx.PredicateParser = parser

			isUnsafe := ctl.UnsafePredicate.EvaluateWithContext(ctx)

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

func classifyStatus(now, dueAt time.Time) Status {
	if now.After(dueAt) {
		return StatusOverdue
	}
	if now.Equal(dueAt) {
		return StatusDueNow
	}
	return StatusUpcoming
}

func sortItems(items Items) {
	rank := func(s Status) int {
		switch s {
		case StatusOverdue:
			return 0
		case StatusDueNow:
			return 1
		default:
			return 2
		}
	}

	slices.SortFunc(items, func(a, b Item) int {
		return cmp.Or(
			a.DueAt.Compare(b.DueAt),
			cmp.Compare(rank(a.Status), rank(b.Status)),
			cmp.Compare(string(a.ControlID), string(b.ControlID)),
			cmp.Compare(string(a.AssetID), string(b.AssetID)),
			cmp.Compare(string(a.AssetType), string(b.AssetType)),
		)
	})
}
