package domain

// --- Security Audit ---

// SecurityAuditRequest defines the inputs for generating security posture evidence.
type SecurityAuditRequest struct {
	// Format is the report format: json, markdown, or sarif.
	// CLI flag: --format (default: json)
	Format string `json:"format,omitempty"`

	// OutFile is the main report output file path.
	// CLI flag: --out
	OutFile string `json:"out_file,omitempty"`

	// OutDir is the artifact bundle output directory.
	// CLI flag: --out-dir
	OutDir string `json:"out_dir,omitempty"`

	// Severities filters findings by severity levels.
	// CLI flag: --severity (default: CRITICAL,HIGH,MEDIUM,LOW)
	Severities []string `json:"severities,omitempty"`

	// FailOn is the gate threshold severity.
	// CLI flag: --fail-on (default: HIGH)
	FailOn string `json:"fail_on,omitempty"`

	// SBOMFormat is the SBOM output format: spdx or cyclonedx.
	// CLI flag: --sbom (default: spdx)
	SBOMFormat string `json:"sbom_format,omitempty"`

	// ComplianceFrameworks are compliance frameworks to include.
	// CLI flag: --compliance-framework (repeatable)
	ComplianceFrameworks []string `json:"compliance_frameworks,omitempty"`

	// VulnSource is the vulnerability evidence source: hybrid, local, or ci.
	// CLI flag: --vuln-source (default: hybrid)
	VulnSource string `json:"vuln_source,omitempty"`

	// LiveVulnCheck enables local govulncheck live check.
	// CLI flag: --live-vuln-check
	LiveVulnCheck bool `json:"live_vuln_check,omitempty"`

	// Now overrides the current time for deterministic output.
	// CLI flag: --now
	Now string `json:"now,omitempty"`
}

// SecurityAuditResponse contains the result of a security audit.
type SecurityAuditResponse struct {
	// ReportData holds the audit report, ready for rendering.
	ReportData any `json:"report_data"`

	// Summary contains the aggregate audit metrics.
	Summary SecurityAuditSummary `json:"summary"`

	// Gated indicates whether findings exceeded the fail-on threshold.
	Gated bool `json:"gated"`
}

// SecurityAuditSummary provides aggregate counts for the audit.
type SecurityAuditSummary struct {
	Total     int    `json:"total"`
	Pass      int    `json:"pass"`
	Warn      int    `json:"warn"`
	Fail      int    `json:"fail"`
	Threshold string `json:"threshold"`
}

// --- Inspect Policy ---

// InspectPolicyRequest defines the inputs for analyzing an S3 bucket policy.
type InspectPolicyRequest struct {
	// FilePath is the path to a policy JSON file.
	// CLI flag: --file (default: stdin)
	FilePath string `json:"file_path,omitempty"`

	// InputData is the raw policy JSON when read from stdin.
	// Populated by the CLI adapter when --file is not set.
	InputData []byte `json:"input_data,omitempty"`
}

// InspectPolicyResponse contains the S3 bucket policy analysis results.
type InspectPolicyResponse struct {
	// Assessment is the overall policy access assessment.
	Assessment any `json:"assessment"`

	// PrefixScope is the prefix scope analysis.
	PrefixScope any `json:"prefix_scope"`

	// Risk is the risk evaluation report.
	Risk any `json:"risk"`

	// RequiredIAM lists the minimum required S3 ingest IAM actions.
	RequiredIAM []string `json:"required_iam_actions"`
}

// --- Inspect ACL ---

// InspectACLRequest defines the inputs for analyzing S3 ACL grants.
type InspectACLRequest struct {
	// FilePath is the path to an ACL grants JSON file.
	// CLI flag: --file (default: stdin)
	FilePath string `json:"file_path,omitempty"`

	// InputData is the raw ACL grants JSON when read from stdin.
	// Populated by the CLI adapter when --file is not set.
	InputData []byte `json:"input_data,omitempty"`
}

// InspectACLResponse contains the S3 ACL grant analysis results.
type InspectACLResponse struct {
	// Assessment is the overall ACL security assessment.
	Assessment any `json:"assessment"`

	// GrantDetails contains per-grant analysis results.
	GrantDetails any `json:"grant_details"`
}
