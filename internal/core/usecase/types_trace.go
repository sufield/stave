package usecase

// --- Trace ---

type TraceRequest struct {
	ControlID       string `json:"control_id"`
	ControlsDir     string `json:"controls_dir,omitempty"`
	ObservationPath string `json:"observation_path"`
	AssetID         string `json:"asset_id"`
}

type TraceResponse struct {
	TraceData any `json:"trace_data"`
}
