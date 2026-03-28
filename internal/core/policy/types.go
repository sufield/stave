// Package policy provides domain types and use cases for policy validation,
// linting, formatting, and security inspection (ACL, risk, exposure,
// compliance, aliases).
package policy

// --- Validate ---

type ValidateRequest struct {
	ControlsDir     string `json:"controls_dir,omitempty"`
	ObservationsDir string `json:"observations_dir,omitempty"`
	InputFile       string `json:"input_file,omitempty"`
	Kind            string `json:"kind,omitempty"`
	Strict          bool   `json:"strict,omitempty"`
}

type ValidateResponse struct {
	Valid    bool                 `json:"valid"`
	Errors   []ValidateDiagnostic `json:"errors,omitempty"`
	Warnings []ValidateDiagnostic `json:"warnings,omitempty"`
	Summary  ValidateSummary      `json:"summary"`
}

type ValidateDiagnostic struct {
	Code    string `json:"code,omitempty"`
	Message string `json:"message"`
	Path    string `json:"path,omitempty"`
}

type ValidateSummary struct {
	ControlsChecked     int `json:"controls_checked,omitempty"`
	ObservationsChecked int `json:"observations_checked,omitempty"`
}

// --- Lint ---

type LintRequest struct {
	Target string `json:"target"`
}

type LintResponse struct {
	Diagnostics []LintDiagnostic `json:"diagnostics"`
	ErrorCount  int              `json:"error_count"`
}

type LintDiagnostic struct {
	Path     string `json:"path"`
	Line     int    `json:"line"`
	Col      int    `json:"col"`
	RuleID   string `json:"rule_id"`
	Message  string `json:"message"`
	Severity string `json:"severity"`
}

// --- Fmt ---

type FmtRequest struct {
	Target    string `json:"target"`
	CheckOnly bool   `json:"check_only,omitempty"`
}

type FmtResponse struct {
	FilesProcessed int `json:"files_processed"`
	FilesChanged   int `json:"files_changed"`
}

// --- Inspect Policy ---

type InspectPolicyRequest struct {
	FilePath  string `json:"file_path,omitempty"`
	InputData []byte `json:"input_data,omitempty"`
}

type InspectPolicyResponse struct {
	Assessment  any      `json:"assessment"`
	PrefixScope any      `json:"prefix_scope"`
	Risk        any      `json:"risk"`
	RequiredIAM []string `json:"required_iam_actions"`
}

// --- Inspect ACL ---

type InspectACLRequest struct {
	FilePath  string `json:"file_path,omitempty"`
	InputData []byte `json:"input_data,omitempty"`
}

type InspectACLResponse struct {
	Assessment   any `json:"assessment"`
	GrantDetails any `json:"grant_details"`
}

// --- Inspect Exposure ---

type InspectExposureRequest struct {
	FilePath  string `json:"file_path,omitempty"`
	InputData []byte `json:"input_data,omitempty"`
}

type InspectExposureResponse struct {
	Classifications any `json:"classifications"`
	BucketAccess    any `json:"bucket_access,omitempty"`
	Visibility      any `json:"visibility,omitempty"`
}

// --- Inspect Risk ---

type InspectRiskRequest struct {
	FilePath  string `json:"file_path,omitempty"`
	InputData []byte `json:"input_data,omitempty"`
}

type InspectRiskResponse struct {
	NormalizedActions []string `json:"normalized_actions"`
	Permissions       any      `json:"permissions"`
	PermissionCheck   any      `json:"permission_check"`
	StatementResult   any      `json:"statement_result"`
	Report            any      `json:"report"`
}

// --- Inspect Compliance ---

type InspectComplianceRequest struct {
	FilePath   string   `json:"file_path,omitempty"`
	InputData  []byte   `json:"input_data,omitempty"`
	Frameworks []string `json:"frameworks,omitempty"`
	CheckIDs   []string `json:"check_ids,omitempty"`
}

type InspectComplianceResponse struct {
	ResolutionJSON []byte `json:"resolution_json"`
}

// --- Inspect Aliases ---

type InspectAliasesRequest struct {
	Category string `json:"category,omitempty"`
}

type InspectAliasesResponse struct {
	Aliases            any      `json:"aliases"`
	SupportedOperators []string `json:"supported_operators"`
}
