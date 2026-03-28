package domain

// --- Snapshot Diff ---

// SnapshotDiffRequest defines the inputs for comparing the latest two observation snapshots.
type SnapshotDiffRequest struct {
	ObservationsDir string   `json:"observations_dir"`
	ChangeTypes     []string `json:"change_types,omitempty"`
	AssetTypes      []string `json:"asset_types,omitempty"`
	AssetID         string   `json:"asset_id,omitempty"`
}

// SnapshotDiffResponse contains the result of comparing two observation snapshots.
type SnapshotDiffResponse struct {
	DeltaData any `json:"delta_data"`
}

// --- Snapshot Upcoming ---

// SnapshotUpcomingRequest defines the inputs for generating upcoming action items.
type SnapshotUpcomingRequest struct {
	// ControlsDir is the path to control definitions directory.
	// CLI flag: --controls
	ControlsDir string `json:"controls_dir"`

	// ObservationsDir is the path to observation snapshots directory.
	// CLI flag: --observations
	ObservationsDir string `json:"observations_dir"`

	// MaxUnsafeDuration is the threshold for unsafe duration.
	// CLI flag: --max-unsafe
	MaxUnsafeDuration string `json:"max_unsafe_duration,omitempty"`

	// Now overrides the current time.
	// CLI flag: --now
	Now string `json:"now,omitempty"`

	// DueSoon is the threshold for "due soon" reminders.
	// CLI flag: --due-soon (default: 24h)
	DueSoon string `json:"due_soon,omitempty"`

	// ControlIDs filters to specific control IDs.
	// CLI flag: --control-id (repeatable)
	ControlIDs []string `json:"control_ids,omitempty"`

	// AssetTypes filters to specific asset types.
	// CLI flag: --asset-type (repeatable)
	AssetTypes []string `json:"asset_types,omitempty"`

	// StatusFilter filters by status: OVERDUE, DUE_NOW, UPCOMING.
	// CLI flag: --status (repeatable)
	StatusFilter []string `json:"status_filter,omitempty"`

	// DueWithin filters to items due within a duration from now.
	// CLI flag: --due-within
	DueWithin string `json:"due_within,omitempty"`
}

// SnapshotUpcomingResponse contains the upcoming action items.
type SnapshotUpcomingResponse struct {
	// ItemsData holds the computed upcoming items, ready for rendering.
	ItemsData any `json:"items_data"`
}
