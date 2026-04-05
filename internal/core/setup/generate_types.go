package setup

// --- Generate Control ---

// GenerateControlRequest is the input for generating a control template.
type GenerateControlRequest struct {
	Name    string `json:"name"`
	OutPath string `json:"out_path,omitempty"`
}

// GenerateControlResponse is the output after generating a control template.
type GenerateControlResponse struct {
	OutputPath string `json:"output_path"`
}

// --- Generate Observation ---

// GenerateObservationRequest is the input for generating an observation template.
type GenerateObservationRequest struct {
	Name    string `json:"name"`
	OutPath string `json:"out_path,omitempty"`
}

// GenerateObservationResponse is the output after generating an observation template.
type GenerateObservationResponse struct {
	OutputPath string `json:"output_path"`
}
