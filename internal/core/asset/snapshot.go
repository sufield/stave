package asset

import (
	"time"

	"github.com/sufield/stave/internal/core/kernel"
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

// FindAsset returns the asset with the given ID.
// Returns the asset and true if found, or a zero Asset and false if not present.
func (s *Snapshot) FindAsset(id string) (Asset, bool) {
	assetID := ID(id)
	for i := range s.Assets {
		if s.Assets[i].ID == assetID {
			return s.Assets[i], true
		}
	}
	return Asset{}, false
}

// HasTimestamp reports whether the snapshot has a captured timestamp.
func (s Snapshot) HasTimestamp() bool {
	return !s.CapturedAt.IsZero()
}

// GeneratedBy describes the tool that generated this observation.
type GeneratedBy struct {
	SourceType      kernel.ObservationSourceType `json:"source_type"`
	Tool            string                       `json:"tool,omitempty"`
	StaveVersion    string                       `json:"tool_version,omitempty"`
	Provider        string                       `json:"provider,omitempty"`
	ProviderVersion string                       `json:"provider_version,omitempty"`
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

// TemporalBounds returns the earliest and latest CapturedAt timestamps.
func (s Snapshots) TemporalBounds() (min, max time.Time) {
	if len(s) == 0 {
		return
	}
	min, max = s[0].CapturedAt, s[0].CapturedAt
	for _, snap := range s {
		if snap.CapturedAt.Before(min) {
			min = snap.CapturedAt
		}
		if snap.CapturedAt.After(max) {
			max = snap.CapturedAt
		}
	}
	return
}

// UniqueAssetCount returns the number of distinct asset IDs across all snapshots.
func (s Snapshots) UniqueAssetCount() int {
	if len(s) == 0 {
		return 0
	}
	unique := make(map[ID]struct{}, len(s[0].Assets))
	for _, snap := range s {
		for _, a := range snap.Assets {
			unique[a.ID] = struct{}{}
		}
	}
	return len(unique)
}

// CountUnprovablySafe counts assets whose safety cannot be proven.
func CountUnprovablySafe(snapshots []Snapshot) int {
	count := 0
	for _, snap := range snapshots {
		for _, a := range snap.Assets {
			if !a.IsProvablySafe() {
				count++
			}
		}
	}
	return count
}
