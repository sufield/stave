package reporting

// --- Enforce ---

type EnforceRequest struct {
	InputPath string `json:"input_path"`
	OutDir    string `json:"out_dir,omitempty"`
	Mode      string `json:"mode"`
	DryRun    bool   `json:"dry_run,omitempty"`
}

type EnforceResponse struct {
	OutputFile string   `json:"output_file"`
	Targets    []string `json:"targets"`
	DryRun     bool     `json:"dry_run,omitempty"`
}
