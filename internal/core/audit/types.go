// Package audit provides request/response types and use case orchestration
// for security auditing, control catalog listing, coverage graphing,
// control explanation, and predicate alias management.
package audit

// --- Security Audit ---

type SecurityAuditRequest struct {
	Format               string   `json:"format,omitempty"`
	OutFile              string   `json:"out_file,omitempty"`
	OutDir               string   `json:"out_dir,omitempty"`
	Severities           []string `json:"severities,omitempty"`
	FailOn               string   `json:"fail_on,omitempty"`
	SBOMFormat           string   `json:"sbom_format,omitempty"`
	ComplianceFrameworks []string `json:"compliance_frameworks,omitempty"`
	VulnSource           string   `json:"vuln_source,omitempty"`
	LiveVulnCheck        bool     `json:"live_vuln_check,omitempty"`
	Now                  string   `json:"now,omitempty"`
}

type SecurityAuditResponse struct {
	ReportData any                  `json:"report_data"`
	Summary    SecurityAuditSummary `json:"summary"`
	Gated      bool                 `json:"gated"`
}

type SecurityAuditSummary struct {
	Total     int    `json:"total"`
	Pass      int    `json:"pass"`
	Warn      int    `json:"warn"`
	Fail      int    `json:"fail"`
	Threshold string `json:"threshold"`
}

// --- Controls List ---

type ControlsListRequest struct {
	ControlsDir string   `json:"controls_dir,omitempty"`
	BuiltIn     bool     `json:"built_in,omitempty"`
	Columns     string   `json:"columns,omitempty"`
	SortBy      string   `json:"sort_by,omitempty"`
	Filter      []string `json:"filter,omitempty"`
}

type ControlsListResponse struct {
	Controls []ControlRow `json:"controls"`
}

type ControlRow struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Type     string `json:"type"`
	Severity string `json:"severity,omitempty"`
	Domain   string `json:"domain,omitempty"`
}

// --- Graph Coverage ---

type GraphCoverageRequest struct {
	ControlsDir     string `json:"controls_dir"`
	ObservationsDir string `json:"observations_dir"`
}

type GraphCoverageResponse struct {
	GraphData any `json:"graph_data"`
}

// --- Explain ---

type ExplainRequest struct {
	ControlID   string `json:"control_id"`
	ControlsDir string `json:"controls_dir,omitempty"`
}

type ExplainResponse struct {
	ControlID          string        `json:"control_id"`
	Name               string        `json:"name"`
	Description        string        `json:"description,omitempty"`
	Type               string        `json:"type,omitempty"`
	MatchedFields      []string      `json:"matched_fields,omitempty"`
	Rules              []ExplainRule `json:"rules,omitempty"`
	MinimalObservation any           `json:"minimal_observation,omitempty"`
}

type ExplainRule struct {
	Path    string `json:"path"`
	Op      string `json:"op"`
	Value   any    `json:"value,omitempty"`
	From    string `json:"from,omitempty"`
	Comment string `json:"comment,omitempty"`
}

// --- Controls Aliases ---

type ControlsAliasesRequest struct {
	Category string `json:"category,omitempty"`
}

type ControlsAliasesResponse struct {
	Names []string `json:"names"`
}

type ControlsAliasExplainRequest struct {
	Alias string `json:"alias"`
}

type ControlsAliasExplainResponse struct {
	Alias    string `json:"alias"`
	Expanded any    `json:"expanded"`
}
