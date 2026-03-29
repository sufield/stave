// Package snapshot provides request/response types and use case orchestration
// for snapshot lifecycle operations: diff, upcoming, archive, cleanup,
// hygiene, quality, and plan. Port interfaces decouple use cases from
// infrastructure implementations.
package snapshot

// --- Diff ---

// DiffRequest defines the inputs for comparing the latest two observation snapshots.
type DiffRequest struct {
	ObservationsDir string   `json:"observations_dir"`
	ChangeTypes     []string `json:"change_types,omitempty"`
	AssetTypes      []string `json:"asset_types,omitempty"`
	AssetID         string   `json:"asset_id,omitempty"`
}

// DiffResponse contains the result of comparing two observation snapshots.
type DiffResponse struct {
	DeltaData any `json:"delta_data"`
}

// --- Upcoming ---

// UpcomingRequest defines the inputs for generating upcoming action items.
type UpcomingRequest struct {
	// ControlsDir is the path to control definitions directory.
	ControlsDir string `json:"controls_dir"`

	// ObservationsDir is the path to observation snapshots directory.
	ObservationsDir string `json:"observations_dir"`

	// MaxUnsafeDuration is the threshold for unsafe duration.
	MaxUnsafeDuration string `json:"max_unsafe_duration,omitempty"`

	// Now overrides the current time.
	Now string `json:"now,omitempty"`

	// DueSoon is the threshold for "due soon" reminders.
	DueSoon string `json:"due_soon,omitempty"`

	// ControlIDs filters to specific control IDs.
	ControlIDs []string `json:"control_ids,omitempty"`

	// AssetTypes filters to specific asset types.
	AssetTypes []string `json:"asset_types,omitempty"`

	// StatusFilter filters by status: OVERDUE, DUE_NOW, UPCOMING.
	StatusFilter []string `json:"status_filter,omitempty"`

	// DueWithin filters to items due within a duration from now.
	DueWithin string `json:"due_within,omitempty"`
}

// UpcomingResponse contains the upcoming action items.
type UpcomingResponse struct {
	// ItemsData holds the computed upcoming items, ready for rendering.
	ItemsData any `json:"items_data"`
}

// --- Archive ---

// ArchiveRequest defines the inputs for archiving stale snapshots.
type ArchiveRequest struct {
	// ObservationsDir is the path to active observation snapshots directory.
	ObservationsDir string `json:"observations_dir"`

	// ArchiveDir is the path to the archive directory.
	ArchiveDir string `json:"archive_dir,omitempty"`

	// OlderThan archives snapshots older than this age (e.g. "14d", "720h").
	OlderThan string `json:"older_than,omitempty"`

	// RetentionTier is the retention tier from project config.
	RetentionTier string `json:"retention_tier,omitempty"`

	// Now is the reference time (RFC3339) for age calculations.
	Now string `json:"now,omitempty"`

	// KeepMin is the minimum number of snapshots to keep.
	KeepMin int `json:"keep_min"`

	// DryRun previews operations without applying them.
	DryRun bool `json:"dry_run,omitempty"`

	// Format is the output format: text or json.
	Format string `json:"format,omitempty"`
}

// ArchiveResponse contains the result of archiving snapshots.
type ArchiveResponse struct {
	// ArchivedCount is the number of snapshots archived (or planned).
	ArchivedCount int `json:"archived_count"`

	// ArchiveDir is the directory where snapshots were moved.
	ArchiveDir string `json:"archive_dir"`

	// DryRun indicates whether this was a preview-only run.
	DryRun bool `json:"dry_run,omitempty"`
}

// --- Cleanup ---

// CleanupRequest defines the inputs for pruning stale snapshots.
type CleanupRequest struct {
	// ObservationsDir is the path to observation snapshots directory.
	ObservationsDir string `json:"observations_dir"`

	// OlderThan prunes snapshots older than this age (e.g. "14d", "720h").
	OlderThan string `json:"older_than,omitempty"`

	// RetentionTier is the retention tier from project config.
	RetentionTier string `json:"retention_tier,omitempty"`

	// Now is the reference time (RFC3339) for age calculations.
	Now string `json:"now,omitempty"`

	// KeepMin is the minimum number of snapshots to keep.
	KeepMin int `json:"keep_min"`

	// DryRun previews operations without applying them.
	DryRun bool `json:"dry_run,omitempty"`

	// Format is the output format: text or json.
	Format string `json:"format,omitempty"`
}

// CleanupResponse contains the result of pruning snapshots.
type CleanupResponse struct {
	// DeletedCount is the number of snapshots deleted (or planned).
	DeletedCount int `json:"deleted_count"`

	// DryRun indicates whether this was a preview-only run.
	DryRun bool `json:"dry_run,omitempty"`
}

// --- Hygiene ---

// HygieneRequest defines the inputs for generating a hygiene report.
type HygieneRequest struct {
	ControlsDir       string   `json:"controls_dir,omitempty"`
	ObservationsDir   string   `json:"observations_dir"`
	ArchiveDir        string   `json:"archive_dir,omitempty"`
	MaxUnsafeDuration string   `json:"max_unsafe_duration,omitempty"`
	DueSoon           string   `json:"due_soon,omitempty"`
	Lookback          string   `json:"lookback,omitempty"`
	OlderThan         string   `json:"older_than,omitempty"`
	RetentionTier     string   `json:"retention_tier,omitempty"`
	KeepMin           int      `json:"keep_min"`
	Now               string   `json:"now,omitempty"`
	Format            string   `json:"format,omitempty"`
	ControlIDs        []string `json:"control_ids,omitempty"`
	AssetTypes        []string `json:"asset_types,omitempty"`
	StatusFilter      []string `json:"status_filter,omitempty"`
	DueWithin         string   `json:"due_within,omitempty"`
}

// HygieneResponse contains the generated hygiene report.
type HygieneResponse struct {
	// ReportData holds the hygiene report, ready for rendering.
	ReportData any `json:"report_data"`
}

// --- Quality ---

// QualityRequest defines the inputs for checking snapshot quality.
type QualityRequest struct {
	ObservationsDir string   `json:"observations_dir"`
	MinSnapshots    int      `json:"min_snapshots"`
	MaxStaleness    string   `json:"max_staleness,omitempty"`
	MaxGap          string   `json:"max_gap,omitempty"`
	RequiredAssets  []string `json:"required_assets,omitempty"`
	Now             string   `json:"now,omitempty"`
	Format          string   `json:"format,omitempty"`
	Strict          bool     `json:"strict,omitempty"`
}

// QualityResponse contains the quality check results.
type QualityResponse struct {
	// CheckData holds the quality check results, ready for rendering.
	CheckData any `json:"check_data"`

	// Passed indicates whether all quality checks passed.
	Passed bool `json:"passed"`
}

// --- Plan ---

// PlanRequest defines the inputs for previewing or executing multi-tier retention.
type PlanRequest struct {
	ObservationsRoot string `json:"observations_root"`
	ArchiveDir       string `json:"archive_dir,omitempty"`
	Now              string `json:"now,omitempty"`
	Format           string `json:"format,omitempty"`
	Apply            bool   `json:"apply,omitempty"`
}

// PlanResponse contains the retention plan results.
type PlanResponse struct {
	// PlanData holds the retention plan entries, ready for rendering.
	PlanData any `json:"plan_data"`

	// Applied indicates whether the plan was executed.
	Applied bool `json:"applied,omitempty"`
}
