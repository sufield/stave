package domain

// --- Validate ---

// ValidateRequest defines the inputs for validating controls and observations.
type ValidateRequest struct {
	ControlsDir     string `json:"controls_dir,omitempty"`
	ObservationsDir string `json:"observations_dir,omitempty"`
	InputFile       string `json:"input_file,omitempty"`
	Kind            string `json:"kind,omitempty"`
	Strict          bool   `json:"strict,omitempty"`
}

// ValidateResponse contains the results of input validation.
type ValidateResponse struct {
	Valid    bool                 `json:"valid"`
	Errors   []ValidateDiagnostic `json:"errors,omitempty"`
	Warnings []ValidateDiagnostic `json:"warnings,omitempty"`
	Summary  ValidateSummary      `json:"summary"`
}

// ValidateDiagnostic represents a single validation issue.
type ValidateDiagnostic struct {
	Code    string `json:"code,omitempty"`
	Message string `json:"message"`
	Path    string `json:"path,omitempty"`
}

// ValidateSummary provides aggregate counts of checked artifacts.
type ValidateSummary struct {
	ControlsChecked     int `json:"controls_checked,omitempty"`
	ObservationsChecked int `json:"observations_checked,omitempty"`
}

// --- Lint ---

// LintRequest defines the inputs for linting control files.
type LintRequest struct {
	// Target is the path to a control file or directory to lint.
	// CLI arg: <path> (required, positional)
	Target string `json:"target"`
}

// LintResponse contains the results of linting control files.
type LintResponse struct {
	// Diagnostics is the list of lint findings.
	Diagnostics []LintDiagnostic `json:"diagnostics"`

	// ErrorCount is the number of error-severity diagnostics.
	ErrorCount int `json:"error_count"`
}

// LintDiagnostic represents a single lint finding.
type LintDiagnostic struct {
	Path     string `json:"path"`
	Line     int    `json:"line"`
	Col      int    `json:"col"`
	RuleID   string `json:"rule_id"`
	Message  string `json:"message"`
	Severity string `json:"severity"`
}

// --- Fmt ---

// FmtRequest defines the inputs for formatting control/observation files.
type FmtRequest struct {
	// Target is the path to a file or directory to format.
	// CLI arg: <path> (required, positional)
	Target string `json:"target"`

	// CheckOnly validates formatting without modifying files.
	// CLI flag: --check
	CheckOnly bool `json:"check_only,omitempty"`
}

// FmtResponse contains the results of formatting.
type FmtResponse struct {
	// FilesProcessed is the number of files examined.
	FilesProcessed int `json:"files_processed"`

	// FilesChanged is the number of files that were (or would be) reformatted.
	FilesChanged int `json:"files_changed"`
}
