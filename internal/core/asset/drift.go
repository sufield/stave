package asset

import (
	"encoding/json"
	"fmt"
	"slices"
	"time"

	"github.com/sufield/stave/internal/core/kernel"
)

// DriftType classifies how an asset has evolved between two observation snapshots.
type DriftType string

const (
	// DriftProvisioned indicates a new cloud resource was discovered.
	DriftProvisioned DriftType = "PROVISIONED"
	// DriftDecommissioned indicates a resource was deleted or is no longer visible.
	DriftDecommissioned DriftType = "DECOMMISSIONED"
	// DriftReconfigured indicates an existing resource had a configuration change.
	DriftReconfigured DriftType = "RECONFIGURED"
)

// AllDriftTypes returns all valid DriftType values as strings.
func AllDriftTypes() []string {
	return []string{string(DriftProvisioned), string(DriftDecommissioned), string(DriftReconfigured)}
}

// IsValid reports whether dt is a recognized drift type.
func (dt DriftType) IsValid() bool {
	switch dt {
	case DriftProvisioned, DriftDecommissioned, DriftReconfigured:
		return true
	default:
		return false
	}
}

// ConfigurationDrift represents a change in a specific resource attribute.
type ConfigurationDrift struct {
	Attribute string `json:"attribute"`
	OldValue  any    `json:"old_value,omitempty"`
	NewValue  any    `json:"new_value,omitempty"`
}

// AssetChange represents the total delta for a single cloud resource.
type AssetChange struct {
	AssetID      ID                   `json:"asset_id"`
	Action       DriftType            `json:"action"`
	PreviousType kernel.AssetType     `json:"previous_type,omitempty"`
	CurrentType  kernel.AssetType     `json:"current_type,omitempty"`
	Drifts       []ConfigurationDrift `json:"drifts,omitempty"`
}

// DriftSummary provides aggregate counts of infrastructure changes.
type DriftSummary struct {
	provisioned    int
	decommissioned int
	reconfigured   int
	total          int
}

// Record updates summary counters based on the type of drift detected.
func (s *DriftSummary) Record(t DriftType) {
	switch t {
	case DriftProvisioned:
		s.provisioned++
	case DriftDecommissioned:
		s.decommissioned++
	case DriftReconfigured:
		s.reconfigured++
	default:
		return
	}
	s.total++
}

// Provisioned returns the count of provisioned assets.
func (s DriftSummary) Provisioned() int {
	return s.provisioned
}

// Decommissioned returns the count of decommissioned assets.
func (s DriftSummary) Decommissioned() int {
	return s.decommissioned
}

// Reconfigured returns the count of reconfigured assets.
func (s DriftSummary) Reconfigured() int {
	return s.reconfigured
}

// Total returns the total count of changed assets.
func (s DriftSummary) Total() int {
	return s.total
}

func (s DriftSummary) matchesChangeCount(changeCount int) bool {
	return s.total == s.provisioned+s.decommissioned+s.reconfigured && s.total == changeCount
}

// MarshalJSON implements json.Marshaler for the summary.
func (s DriftSummary) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Provisioned    int `json:"provisioned"`
		Decommissioned int `json:"decommissioned"`
		Reconfigured   int `json:"reconfigured"`
		Total          int `json:"total"`
	}{
		Provisioned:    s.provisioned,
		Decommissioned: s.decommissioned,
		Reconfigured:   s.reconfigured,
		Total:          s.total,
	})
}

// InfrastructureDrift represents the net change in a cloud environment between
// two snapshots. This is the primary output for drift detection operations.
type InfrastructureDrift struct {
	SchemaVersion kernel.Schema     `json:"schema_version"`
	Kind          kernel.OutputKind `json:"kind"`
	StartTime     time.Time         `json:"start_time"`
	EndTime       time.Time         `json:"end_time"`
	Summary       DriftSummary      `json:"summary"`
	Changes       []AssetChange     `json:"changes"`
}

// GetStateTransition returns the two most recent observation snapshots for comparison.
func GetStateTransition(snapshots []Snapshot) (prev Snapshot, curr Snapshot, err error) {
	if len(snapshots) < 2 {
		return Snapshot{}, Snapshot{}, fmt.Errorf("%w: need 2 states for drift analysis, got %d", ErrInsufficientSnapshots, len(snapshots))
	}

	sorted := slices.Clone(snapshots)
	slices.SortFunc(sorted, func(a, b Snapshot) int {
		return a.CapturedAt.Compare(b.CapturedAt)
	})

	prev = sorted[len(sorted)-2]
	curr = sorted[len(sorted)-1]
	if curr.CapturedAt.Before(prev.CapturedAt) {
		return Snapshot{}, Snapshot{}, ErrSnapshotsNotOrdered
	}
	return prev, curr, nil
}

// ComputeDrift compares two infrastructure states and identifies all asset-level changes.
func ComputeDrift(prev, curr Snapshot) InfrastructureDrift {
	prevByID := assetMap(prev.Assets)
	currByID := assetMap(curr.Assets)
	ids := uniqueSortedKeys(prevByID, currByID)

	drift := InfrastructureDrift{
		SchemaVersion: kernel.SchemaDiff,
		Kind:          kernel.KindObservationDelta,
		StartTime:     prev.CapturedAt.UTC(),
		EndTime:       curr.CapturedAt.UTC(),
		Changes:       make([]AssetChange, 0),
	}

	for _, id := range ids {
		pr, hasPrevious := prevByID[id]
		cr, hasCurrent := currByID[id]

		change := diffAsset(assetDiffInput{
			ID:          id,
			Prev:        pr,
			HasPrevious: hasPrevious,
			Curr:        cr,
			HasCurrent:  hasCurrent,
		})
		if change == nil {
			continue
		}

		drift.Changes = append(drift.Changes, *change)
		drift.Summary.Record(change.Action)
	}

	if !drift.Summary.matchesChangeCount(len(drift.Changes)) {
		panic("structural contract violation: summary total mismatch")
	}

	return drift
}

// SummarizeDrift computes summary counts from a list of asset changes.
func SummarizeDrift(changes []AssetChange) DriftSummary {
	s := DriftSummary{}
	for _, change := range changes {
		s.Record(change.Action)
	}
	return s
}
