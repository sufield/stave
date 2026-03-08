package asset

import (
	"time"

	"github.com/sufield/stave/internal/domain/kernel"
)

// Snapshot represents a point-in-time observation of infrastructure assets.
// Each snapshot captures the state of assets at a specific moment,
// identified by CapturedAt. Stave processes multiple snapshots to track
// how asset states change over time.
type Snapshot struct {
	SchemaVersion kernel.Schema   `json:"schema_version"`
	GeneratedBy   *GeneratedBy    `json:"generated_by,omitempty"`
	CapturedAt    time.Time       `json:"captured_at"`
	Assets        []Asset         `json:"assets"`
	Identities    []CloudIdentity `json:"identities,omitempty"`
}

// FindAsset returns the asset with the given ID, or nil if not present.
func (s *Snapshot) FindAsset(id string) *Asset {
	assetID := ID(id)
	for i := range s.Assets {
		if s.Assets[i].ID == assetID {
			return &s.Assets[i]
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

// LatestSnapshot returns the snapshot with the most recent CapturedAt.
// Panics if snapshots is empty.
func LatestSnapshot(snapshots []Snapshot) Snapshot {
	latest := snapshots[0]
	for _, s := range snapshots[1:] {
		if s.CapturedAt.After(latest.CapturedAt) {
			latest = s
		}
	}
	return latest
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

// CountUnprovablySafe counts assets whose safety cannot be proven
// (where the safety_provable property is explicitly false).
func CountUnprovablySafe(snapshots []Snapshot) int {
	count := 0
	for _, snap := range snapshots {
		for _, a := range snap.Assets {
			if provable, ok := a.Properties["safety_provable"].(bool); ok && !provable {
				count++
			}
		}
	}
	return count
}
