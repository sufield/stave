package findings

import (
	"time"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/kernel"
)

// ThresholdStatus represents urgency for when an unsafe threshold is due.
//
// Moved from internal/core/evaluation/risk/upcoming.go during the
// chain-engine untangle so report/ stops importing risk/. The query
// helpers Filter/Summarize move with the type (Go requires methods
// in the same package as their receiver) even though their producers
// stay in risk/. risk.ThresholdStatus + risk.ThresholdItem +
// risk.ThresholdItems + risk.ThresholdSummary + risk.ThresholdFilter
// remain as brief local aliases for the producer-side threshold
// pipeline in risk/upcoming.go; external consumers reach for
// findings.X directly.
type ThresholdStatus string

// StatusOverdue and related constants.
const (
	StatusOverdue  ThresholdStatus = "OVERDUE"
	StatusDueNow   ThresholdStatus = "DUE_NOW"
	StatusUpcoming ThresholdStatus = "UPCOMING"
)

// IsOverdue reports whether the status string identifies the
// OVERDUE bucket. Wraps the constant comparison so wire-decode
// callers (cmd/watch) can route through the typed predicate
// instead of comparing against the magic "OVERDUE" literal.
func (s ThresholdStatus) IsOverdue() bool {
	return s == StatusOverdue
}

// String returns the canonical wire-format label for the status
// (OVERDUE / DUE_NOW / UPCOMING). DTO mappers route through this
// instead of `string(item.Status)` so the conversion is named.
func (s ThresholdStatus) String() string {
	return string(s)
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
// threshold. Routes through ThresholdStatus.IsOverdue so the
// "OVERDUE" comparison lives on the status type, not the item
// wrapper.
func (t *ThresholdItem) IsOverdue() bool {
	return t != nil && t.Status.IsOverdue()
}

// IsDueNow reports whether this item is at the SLA boundary —
// the StatusDueNow bucket Summarize / renderers treat as a
// distinct urgency tier from Overdue and Upcoming.
func (t *ThresholdItem) IsDueNow() bool {
	return t != nil && t.Status == StatusDueNow
}

// IsDueSoon reports whether this upcoming item will reach its
// SLA boundary within `threshold`. Exclusive of items that have
// already breached (IsOverdue) or hit the boundary (IsDueNow);
// Summarize uses this to bin upcoming items into "due-soon" vs
// "later" without re-implementing the time-window math.
func (t *ThresholdItem) IsDueSoon(threshold time.Duration) bool {
	if t == nil || t.IsOverdue() || t.IsDueNow() {
		return false
	}
	return t.Remaining > 0 && t.Remaining <= threshold
}

// ThresholdItems is a collection of upcoming risk items.
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

// Summarize buckets items by urgency relative to a "due soon" threshold.
func (it ThresholdItems) Summarize(dueSoonThreshold time.Duration) ThresholdSummary {
	var s ThresholdSummary
	s.Total = len(it)
	for i := range it {
		threshold := &it[i]
		switch {
		case threshold.IsOverdue():
			s.Overdue++
		case threshold.IsDueNow():
			s.DueNow++
		case threshold.IsDueSoon(dueSoonThreshold):
			s.DueSoon++
		default:
			s.Later++
		}
	}
	return s
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
