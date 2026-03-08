package risk

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/domain/policy"
	"github.com/sufield/stave/internal/pkg/fp"
)

// Status represents urgency for when an unsafe threshold is due.
type Status string

const (
	Overdue  Status = "OVERDUE"
	DueNow   Status = "DUE_NOW"
	Upcoming Status = "UPCOMING"
)

var validStatuses = map[Status]struct{}{
	Overdue:  {},
	DueNow:   {},
	Upcoming: {},
}

// ValidStatus reports whether s is a recognized risk status.
func ValidStatus(s Status) bool {
	_, ok := validStatuses[s]
	return ok
}

// ValidateStatuses normalises and validates a slice of status strings.
// Empty strings are skipped. Returns an error on the first invalid value.
func ValidateStatuses(statuses []string) ([]Status, error) {
	out := make([]Status, 0, len(statuses))
	for _, raw := range statuses {
		normalized := Status(strings.ToUpper(strings.TrimSpace(raw)))
		if normalized == "" {
			continue
		}
		if !ValidStatus(normalized) {
			return nil, fmt.Errorf("invalid status %q (use: OVERDUE, DUE_NOW, UPCOMING)", raw)
		}
		out = append(out, normalized)
	}
	return out, nil
}

// Item captures one control/asset due threshold candidate.
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

// Items is a collection of upcoming risk items with query methods.
type Items []Item

// CountOverdue returns the number of items with OVERDUE status.
func (items Items) CountOverdue() int {
	return fp.CountFunc(items, func(item Item) bool { return item.Status == Overdue })
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

// FilterCriteria specifies which items to include.
// Empty/nil maps and zero MaxRemaining mean no restriction on that dimension.
type FilterCriteria struct {
	ControlIDs   map[kernel.ControlID]struct{}
	AssetTypes   map[kernel.AssetType]struct{}
	Statuses     map[Status]struct{}
	MaxRemaining time.Duration // 0 means no limit
}

// Filter returns items matching all non-empty criteria.
func (items Items) Filter(c FilterCriteria) Items {
	if !c.active() {
		return items
	}
	out := make(Items, 0, len(items))
	for _, item := range items {
		if c.matches(item) {
			out = append(out, item)
		}
	}
	return out
}

func (c FilterCriteria) active() bool {
	return len(c.ControlIDs) > 0 || len(c.AssetTypes) > 0 || len(c.Statuses) > 0 || c.MaxRemaining > 0
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

// Summarize buckets items by urgency. Items with Remaining within
// dueSoonThreshold are counted as DueSoon; others are Later.
func (items Items) Summarize(dueSoonThreshold time.Duration) Summary {
	var s Summary
	s.Total = len(items)
	for _, item := range items {
		switch item.Status {
		case Overdue:
			s.Overdue++
		case DueNow:
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

// Request provides the inputs required to compute upcoming risk items.
type Request struct {
	Controls        []policy.ControlDefinition
	Snapshots       []asset.Snapshot
	GlobalMaxUnsafe time.Duration
	Now             time.Time
	PredicateParser func(any) (*policy.UnsafePredicate, error)
}

type state struct {
	FirstUnsafeAt   *time.Time
	LastSeenUnsafe  *time.Time
	CurrentlyUnsafe bool
	AssetType       kernel.AssetType
}

// ComputeItems returns deterministic upcoming threshold items for
// currently-unsafe assets across evaluatable controls.
func ComputeItems(req Request) Items {
	if len(req.Snapshots) == 0 || len(req.Controls) == 0 {
		return nil
	}
	sorted := sortSnapshotsByCapturedAt(req.Snapshots)
	items := make([]Item, 0)
	for _, ctl := range req.Controls {
		if !isRiskControl(ctl) {
			continue
		}
		threshold := resolveMaxUnsafe(ctl, req.GlobalMaxUnsafe)
		states := computeStates(ctl, sorted, req.PredicateParser)
		items = append(items, itemsForControl(ctl, states, req.Now, threshold)...)
	}
	sortItems(items)
	return items
}

func sortSnapshotsByCapturedAt(snapshots []asset.Snapshot) []asset.Snapshot {
	sorted := append([]asset.Snapshot(nil), snapshots...)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].CapturedAt.Before(sorted[j].CapturedAt)
	})
	return sorted
}

func isRiskControl(ctl policy.ControlDefinition) bool {
	return ctl.Type == policy.TypeUnsafeDuration || ctl.Type == policy.TypeUnsafeState
}

func computeStates(ctl policy.ControlDefinition, snapshots []asset.Snapshot, predicateParser func(any) (*policy.UnsafePredicate, error)) map[asset.ID]*state {
	states := make(map[asset.ID]*state)
	for _, snap := range snapshots {
		for _, a := range snap.Assets {
			st := ensureState(states, a.ID, a.Type)
			ctx := policy.NewAssetEvalContextWithIdentities(a, policy.ControlParams(ctl.Params), snap.Identities)
			ctx.PredicateParser = predicateParser
			updateState(st, ctl.UnsafePredicate.EvaluateWithContext(ctx), snap.CapturedAt, a.Type)
		}
	}
	return states
}

func ensureState(
	states map[asset.ID]*state,
	id asset.ID,
	resourceType kernel.AssetType,
) *state {
	st, exists := states[id]
	if exists {
		return st
	}
	st = &state{AssetType: resourceType}
	states[id] = st
	return st
}

func updateState(
	st *state,
	isUnsafe bool,
	capturedAt time.Time,
	resourceType kernel.AssetType,
) {
	st.AssetType = resourceType
	if !isUnsafe {
		st.FirstUnsafeAt = nil
		st.LastSeenUnsafe = nil
		st.CurrentlyUnsafe = false
		return
	}
	if st.FirstUnsafeAt == nil {
		first := capturedAt
		st.FirstUnsafeAt = &first
	}
	last := capturedAt
	st.LastSeenUnsafe = &last
	st.CurrentlyUnsafe = true
}

func itemsForControl(
	ctl policy.ControlDefinition,
	states map[asset.ID]*state,
	now time.Time,
	threshold time.Duration,
) []Item {
	items := make([]Item, 0)
	for assetID, st := range states {
		if !st.CurrentlyUnsafe || st.FirstUnsafeAt == nil || st.LastSeenUnsafe == nil {
			continue
		}
		dueAt := st.FirstUnsafeAt.Add(threshold)
		items = append(items, Item{
			DueAt:          dueAt.UTC(),
			Status:         classifyStatus(now, dueAt),
			Remaining:      dueAt.Sub(now),
			ControlID:      ctl.ID,
			AssetID:        assetID,
			AssetType:      st.AssetType,
			FirstUnsafeAt:  st.FirstUnsafeAt.UTC(),
			LastSeenUnsafe: st.LastSeenUnsafe.UTC(),
			Threshold:      threshold,
		})
	}
	return items
}

func classifyStatus(now, dueAt time.Time) Status {
	if now.After(dueAt) {
		return Overdue
	}
	if now.Equal(dueAt) {
		return DueNow
	}
	return Upcoming
}

func sortItems(items []Item) {
	sort.Slice(items, func(i, j int) bool {
		if !items[i].DueAt.Equal(items[j].DueAt) {
			return items[i].DueAt.Before(items[j].DueAt)
		}
		if items[i].Status != items[j].Status {
			return items[i].Status < items[j].Status
		}
		if items[i].ControlID != items[j].ControlID {
			return items[i].ControlID < items[j].ControlID
		}
		if items[i].AssetID != items[j].AssetID {
			return items[i].AssetID < items[j].AssetID
		}
		return items[i].AssetType < items[j].AssetType
	})
}

func resolveMaxUnsafe(ctl policy.ControlDefinition, fallback time.Duration) time.Duration {
	return ctl.EffectiveMaxUnsafe(fallback)
}
