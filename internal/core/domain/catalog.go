package domain

// --- Controls List ---

// ControlsListRequest defines the inputs for listing controls.
type ControlsListRequest struct {
	// ControlsDir is the path to control definitions directory.
	// CLI flag: --controls (default from config)
	ControlsDir string `json:"controls_dir,omitempty"`

	// BuiltIn lists embedded controls instead of filesystem.
	// CLI flag: --built-in
	BuiltIn bool `json:"built_in,omitempty"`

	// Columns selects which columns to display.
	// CLI flag: --columns (default: "id,name,type")
	Columns string `json:"columns,omitempty"`

	// SortBy selects the column to sort by.
	// CLI flag: --sort (default: "id")
	SortBy string `json:"sort_by,omitempty"`

	// Filter selects controls by selector expression.
	// CLI flag: --filter (repeatable)
	Filter []string `json:"filter,omitempty"`
}

// ControlsListResponse contains the result of listing controls.
type ControlsListResponse struct {
	// Controls is the list of control rows.
	Controls []ControlRow `json:"controls"`
}

// ControlRow represents a single control in a listing.
type ControlRow struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Type     string `json:"type"`
	Severity string `json:"severity,omitempty"`
	Domain   string `json:"domain,omitempty"`
}

// --- Graph Coverage ---

// GraphCoverageRequest defines the inputs for generating a coverage graph.
type GraphCoverageRequest struct {
	// ControlsDir is the path to control definitions directory.
	// CLI flag: --controls
	ControlsDir string `json:"controls_dir"`

	// ObservationsDir is the path to observation snapshots directory.
	// CLI flag: --observations
	ObservationsDir string `json:"observations_dir"`
}

// GraphCoverageResponse contains the coverage graph data.
type GraphCoverageResponse struct {
	// GraphData holds the computed coverage result, ready for rendering.
	GraphData any `json:"graph_data"`
}
