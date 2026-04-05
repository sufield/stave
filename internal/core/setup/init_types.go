package setup

// --- Init Project ---

type InitRequest struct {
	Dir               string `json:"dir,omitempty"`
	Profile           string `json:"profile,omitempty"`
	DryRun            bool   `json:"dry_run,omitempty"`
	WithGitHubActions bool   `json:"with_github_actions,omitempty"`
	CaptureCadence    string `json:"capture_cadence,omitempty"`
	Force             bool   `json:"force,omitempty"`
}

type InitResponse struct {
	BaseDir string   `json:"base_dir"`
	Dirs    []string `json:"dirs"`
	Created []string `json:"created"`
	Skipped []string `json:"skipped,omitempty"`
	DryRun  bool     `json:"dry_run,omitempty"`
}
