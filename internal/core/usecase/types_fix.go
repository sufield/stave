package usecase

// --- Fix ---

type FixRequest struct {
	InputPath  string `json:"input_path"`
	FindingRef string `json:"finding_ref"`
}

type FixResponse struct {
	Data any `json:"data"`
}
