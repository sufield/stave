package usecase

// --- Apply ---

type ApplyRequest struct {
	ControlsDir        string   `json:"controls_dir,omitempty"`
	ObservationsDir    string   `json:"observations_dir,omitempty"`
	MaxUnsafeDuration  string   `json:"max_unsafe_duration,omitempty"`
	NowTime            string   `json:"now_time,omitempty"`
	Format             string   `json:"format,omitempty"`
	DryRun             bool     `json:"dry_run,omitempty"`
	AllowUnknownInput  bool     `json:"allow_unknown_input,omitempty"`
	ExemptionFile      string   `json:"exemption_file,omitempty"`
	IntegrityManifest  string   `json:"integrity_manifest,omitempty"`
	IntegrityPublicKey string   `json:"integrity_public_key,omitempty"`
	Profile            string   `json:"profile,omitempty"`
	InputFile          string   `json:"input_file,omitempty"`
	BucketAllowlist    []string `json:"bucket_allowlist,omitempty"`
	IncludeAll         bool     `json:"include_all,omitempty"`
}

type ApplyResponse struct {
	EvaluationData any      `json:"evaluation_data"`
	HasViolations  bool     `json:"has_violations"`
	Warnings       []string `json:"warnings,omitempty"`
}
