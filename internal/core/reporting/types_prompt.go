package reporting

// --- Prompt From Finding ---

type PromptFromFindingRequest struct {
	EvaluationFile  string `json:"evaluation_file"`
	AssetID         string `json:"asset_id"`
	ControlsDir     string `json:"controls_dir,omitempty"`
	ObservationsDir string `json:"observations_dir,omitempty"`
}

type PromptFromFindingResponse struct {
	Rendered   string   `json:"rendered"`
	FindingIDs []string `json:"finding_ids"`
	AssetID    string   `json:"asset_id"`
}
