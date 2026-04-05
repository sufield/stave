package setup

// --- Generate Control ---

type GenerateControlRequest struct {
	Name    string `json:"name"`
	OutPath string `json:"out_path,omitempty"`
}

type GenerateControlResponse struct {
	OutputPath string `json:"output_path"`
}

// --- Generate Observation ---

type GenerateObservationRequest struct {
	Name    string `json:"name"`
	OutPath string `json:"out_path,omitempty"`
}

type GenerateObservationResponse struct {
	OutputPath string `json:"output_path"`
}
