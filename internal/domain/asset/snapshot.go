package asset

import (
	"time"

	"github.com/sufield/stave/internal/domain/kernel"
)

// Snapshot represents a point-in-time observation of infrastructure resources.
// Each snapshot captures the state of resources at a specific moment,
// identified by CapturedAt. Stave processes multiple snapshots to track
// how resource states change over time.
type Snapshot struct {
	SchemaVersion kernel.Schema   `json:"schema_version"`
	GeneratedBy   *GeneratedBy    `json:"generated_by,omitempty"`
	CapturedAt    time.Time       `json:"captured_at"`
	Resources     []Asset         `json:"resources"`
	Identities    []CloudIdentity `json:"identities,omitempty"`
}

// FindResource returns the resource with the given ID, or nil if not present.
func (s *Snapshot) FindResource(id string) *Asset {
	assetID := ID(id)
	for i := range s.Resources {
		if s.Resources[i].ID == assetID {
			return &s.Resources[i]
		}
	}
	return nil
}

// HasTimestamp reports whether the snapshot has a captured timestamp.
func (s Snapshot) HasTimestamp() bool {
	return !s.CapturedAt.IsZero()
}

// GeneratedBy describes the tool that generated this observation.
type GeneratedBy struct {
	SourceType      string `json:"source_type"`
	Tool            string `json:"tool,omitempty"`
	ToolVersion     string `json:"tool_version,omitempty"`
	Provider        string `json:"provider,omitempty"`
	ProviderVersion string `json:"provider_version,omitempty"`
}

// Snapshots is an ordered collection of observation snapshots.
type Snapshots []Snapshot

func (s Snapshots) IsEmpty() bool {
	return len(s) == 0
}

func (s Snapshots) IsSingle() bool {
	return len(s) == 1
}

func (s Snapshots) IsMultiSnapshot() bool {
	return len(s) > 1
}

type unsortedPair struct {
	snapshotAt  time.Time
	comesBefore time.Time
}

func (p unsortedPair) Evidence() map[string]string {
	return map[string]string{
		"snapshot_at":  p.snapshotAt.Format(time.RFC3339),
		"comes_before": p.comesBefore.Format(time.RFC3339),
	}
}

// FindFirstUnsortedPair finds the first snapshot pair that violates chronological order.
func (s Snapshots) FindFirstUnsortedPair() (unsortedPair, bool) {
	for i := 1; i < len(s); i++ {
		if s[i].CapturedAt.Before(s[i-1].CapturedAt) {
			return unsortedPair{
				snapshotAt:  s[i].CapturedAt,
				comesBefore: s[i-1].CapturedAt,
			}, true
		}
	}
	return unsortedPair{}, false
}
