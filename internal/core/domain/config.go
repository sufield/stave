package domain

// --- Doctor ---

// DoctorRequest defines the inputs for running environment readiness checks.
type DoctorRequest struct {
	Cwd        string `json:"cwd,omitempty"`
	BinaryPath string `json:"binary_path,omitempty"`
	Format     string `json:"format,omitempty"`
}

// DoctorResponse contains the results of environment readiness checks.
type DoctorResponse struct {
	Checks    []DoctorCheck `json:"checks"`
	AllPassed bool          `json:"all_passed"`
}

// DoctorCheck represents a single environment diagnostic result.
type DoctorCheck struct {
	Name    string `json:"name"`
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
	Fix     string `json:"fix,omitempty"`
}

// --- Config Show ---

// ConfigShowRequest defines the inputs for showing effective configuration.
type ConfigShowRequest struct {
	// Format is the output format (text or json).
	// CLI flag: --format (default: text)
	Format string `json:"format,omitempty"`
}

// ConfigShowResponse contains the effective project configuration.
type ConfigShowResponse struct {
	// ConfigData holds the resolved effective configuration, ready for rendering.
	ConfigData any `json:"config_data"`
}

// --- Status ---

// StatusRequest defines the inputs for checking project status.
type StatusRequest struct {
	// Dir is the directory to inspect for project context.
	// CLI flag: --dir (default: ".")
	Dir string `json:"dir,omitempty"`
}

// StatusResponse contains the project status and recommended next action.
type StatusResponse struct {
	// StateData holds the scanned project state, ready for rendering.
	StateData any `json:"state_data"`

	// NextCommand is the recommended next CLI command.
	NextCommand string `json:"next_command,omitempty"`
}

// --- Generate Control ---

// GenerateControlRequest defines the inputs for scaffolding a control template.
type GenerateControlRequest struct {
	// Name is the human-readable control name.
	// CLI arg: <name> (required, positional)
	Name string `json:"name"`

	// OutPath is the output file path.
	// CLI flag: --out (optional, default derived from name)
	OutPath string `json:"out_path,omitempty"`
}

// GenerateControlResponse contains the result of generating a control template.
type GenerateControlResponse struct {
	// OutputPath is the path where the control template was written.
	OutputPath string `json:"output_path"`
}

// --- Bug Report ---

// BugReportRequest defines the inputs for generating a diagnostic bundle.
type BugReportRequest struct {
	// OutPath is the path for the output bundle zip.
	// CLI flag: --out (optional, default auto-generated)
	OutPath string `json:"out_path,omitempty"`

	// TailLines is the number of trailing log lines to include.
	// CLI flag: --tail-lines (default: 1000)
	TailLines int `json:"tail_lines"`

	// IncludeConfig controls whether sanitized project config is bundled.
	// CLI flag: --include-config (default: true)
	IncludeConfig bool `json:"include_config"`
}

// BugReportResponse contains the result of generating a diagnostic bundle.
type BugReportResponse struct {
	// BundlePath is the absolute path where the bundle was written.
	BundlePath string `json:"bundle_path"`

	// Warnings lists non-fatal issues encountered during collection.
	Warnings []string `json:"warnings,omitempty"`
}

// --- Init Project ---

// InitProjectRequest defines the inputs for initializing a Stave project.
type InitProjectRequest struct {
	// Dir is the directory where the scaffold is created.
	// CLI flag: --dir (default: ".")
	Dir string `json:"dir,omitempty"`

	// Profile is the optional scaffold profile.
	// CLI flag: --profile (supported: aws-s3)
	Profile string `json:"profile,omitempty"`

	// DryRun previews the scaffold without creating files.
	// CLI flag: --dry-run
	DryRun bool `json:"dry_run,omitempty"`

	// WithGitHubActions creates a starter GitHub Actions workflow.
	// CLI flag: --with-github-actions
	WithGitHubActions bool `json:"with_github_actions,omitempty"`

	// CaptureCadence is the snapshot capture cadence template.
	// CLI flag: --capture-cadence (default: "daily", supported: daily, hourly)
	CaptureCadence string `json:"capture_cadence,omitempty"`

	// Force allows overwriting existing files.
	// CLI flag: --force (global)
	Force bool `json:"force,omitempty"`
}

// InitProjectResponse contains the result of project initialization.
type InitProjectResponse struct {
	// BaseDir is the resolved directory where the project was scaffolded.
	BaseDir string `json:"base_dir"`

	// Dirs lists the directories created or verified.
	Dirs []string `json:"dirs"`

	// Created lists the files that were created.
	Created []string `json:"created"`

	// Skipped lists the files that were skipped (already exist).
	Skipped []string `json:"skipped,omitempty"`

	// DryRun indicates whether this was a preview-only run.
	DryRun bool `json:"dry_run,omitempty"`
}
