package reporting

// --- Diagnose ---

type DiagnoseRequest struct {
	ControlsDir       string   `json:"controls_dir,omitempty"`
	ObservationsDir   string   `json:"observations_dir,omitempty"`
	PreviousOutput    string   `json:"previous_output,omitempty"`
	MaxUnsafeDuration string   `json:"max_unsafe_duration,omitempty"`
	Now               string   `json:"now,omitempty"`
	CaseFilter        []string `json:"case_filter,omitempty"`
	SignalContains    string   `json:"signal_contains,omitempty"`
	ControlID         string   `json:"control_id,omitempty"`
	AssetID           string   `json:"asset_id,omitempty"`
}

type DiagnoseResponse struct {
	ReportData   any  `json:"report_data"`
	IsDetailMode bool `json:"is_detail_mode,omitempty"`
}
