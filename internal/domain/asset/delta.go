package asset

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/sufield/stave/internal/domain/kernel"
)

// ChangeType is the domain type for resource change classification.
type ChangeType string

const (
	// ChangeAdded indicates a resource appears in the newer snapshot only.
	ChangeAdded ChangeType = "added"
	// ChangeRemoved indicates a resource appears in the older snapshot only.
	ChangeRemoved ChangeType = "removed"
	// ChangeModified indicates a resource exists in both snapshots but changed.
	ChangeModified ChangeType = "modified"
)

// PropertyChange represents a single property-level change between snapshots.
type PropertyChange struct {
	Path string `json:"path"`
	From any    `json:"from,omitempty"`
	To   any    `json:"to,omitempty"`
}

// ResourceDiff represents the changes detected for a single resource.
type ResourceDiff struct {
	AssetID         ID               `json:"asset_id"`
	ChangeType      ChangeType       `json:"change_type"` // added|removed|modified
	FromType        string           `json:"from_type,omitempty"`
	ToType          string           `json:"to_type,omitempty"`
	PropertyChanges []PropertyChange `json:"property_changes,omitempty"`
}

// ObservationDeltaSummary provides aggregate counts by change type.
type ObservationDeltaSummary struct {
	added    int
	removed  int
	modified int
	total    int
}

// INVARIANT: Summary total must always equal the sum of Added, Removed, and Modified.
// Increment updates summary counters for a single change type.
func (s *ObservationDeltaSummary) Increment(changeType ChangeType) {
	switch changeType {
	case ChangeAdded:
		s.added++
	case ChangeRemoved:
		s.removed++
	case ChangeModified:
		s.modified++
	default:
		return
	}
	s.total++
}

func (s ObservationDeltaSummary) Added() int {
	return s.added
}

func (s ObservationDeltaSummary) Removed() int {
	return s.removed
}

func (s ObservationDeltaSummary) Modified() int {
	return s.modified
}

func (s ObservationDeltaSummary) Total() int {
	return s.total
}

func (s ObservationDeltaSummary) matchesChangeCount(changeCount int) bool {
	return s.total == s.added+s.removed+s.modified && s.total == changeCount
}

func (s ObservationDeltaSummary) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Added    int `json:"added"`
		Removed  int `json:"removed"`
		Modified int `json:"modified"`
		Total    int `json:"total"`
	}{
		Added:    s.added,
		Removed:  s.removed,
		Modified: s.modified,
		Total:    s.total,
	})
}

// ObservationDelta represents what changed in the observed infrastructure
// between two points in time. It is the diff.v0.1 output.
type ObservationDelta struct {
	SchemaVersion kernel.Schema           `json:"schema_version"`
	Kind          string                  `json:"kind"`
	FromCaptured  time.Time               `json:"from_captured_at"`
	ToCaptured    time.Time               `json:"to_captured_at"`
	Summary       ObservationDeltaSummary `json:"summary"`
	Changes       []ResourceDiff          `json:"changes"`
}

// LatestTwoSnapshots returns the two most recent snapshots by CapturedAt.
func LatestTwoSnapshots(snapshots []Snapshot) (prev Snapshot, curr Snapshot, err error) {
	// PRECONDITION: Requires at least 2 snapshots to establish a chronological delta.
	if len(snapshots) < 2 {
		return Snapshot{}, Snapshot{}, fmt.Errorf("insufficient snapshots: want 2, got %d", len(snapshots))
	}

	sorted := append([]Snapshot(nil), snapshots...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].CapturedAt.Equal(sorted[j].CapturedAt) {
			return i < j
		}
		return sorted[i].CapturedAt.Before(sorted[j].CapturedAt)
	})

	prev = sorted[len(sorted)-2]
	curr = sorted[len(sorted)-1]
	if curr.CapturedAt.Before(prev.CapturedAt) {
		return Snapshot{}, Snapshot{}, errors.New("snapshots are not chronologically ordered")
	}
	// POSTCONDITION: Snapshots are returned in strict ascending chronological order.
	return prev, curr, nil
}

// ComputeObservationDelta compares two snapshots and returns an ObservationDelta.
func ComputeObservationDelta(prev, curr Snapshot) ObservationDelta {
	prevByID := resourceMap(prev.Resources)
	currByID := resourceMap(curr.Resources)
	// O(N+M): Single pass to identify added, removed, and persisting resource IDs.
	ids := uniqueSortedResourceKeys(prevByID, currByID)

	delta := ObservationDelta{
		SchemaVersion: kernel.SchemaDiff,
		Kind:          "observation_delta",
		FromCaptured:  prev.CapturedAt.UTC(),
		ToCaptured:    curr.CapturedAt.UTC(),
		Changes:       make([]ResourceDiff, 0),
	}

	for _, id := range ids {
		pr, hasPrev := prevByID[id]
		cr, hasCurr := currByID[id]

		// TELL: Let the resource identify its own property-level differences.
		diff := diffResource(resourceDiffInput{
			ID:      id,
			Prev:    pr,
			HasPrev: hasPrev,
			Curr:    cr,
			HasCurr: hasCurr,
		})
		if diff == nil {
			continue
		}

		delta.Changes = append(delta.Changes, *diff)
		// TELL: Let the summary update its own counters based on the ChangeType.
		delta.Summary.Increment(diff.ChangeType)
	}

	if !delta.Summary.matchesChangeCount(len(delta.Changes)) {
		panic("structural invariant violation: summary total mismatch")
	}

	return delta
}

// SummarizeDeltaChanges computes summary counts from a list of resource diffs.
func SummarizeDeltaChanges(changes []ResourceDiff) ObservationDeltaSummary {
	s := ObservationDeltaSummary{}
	for _, change := range changes {
		s.Increment(change.ChangeType)
	}
	return s
}
