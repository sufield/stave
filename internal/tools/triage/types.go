package main

import "github.com/sufield/stave/internal/adapters/awsmeta"

// TriageReport is the full output of a triage run.
type TriageReport struct {
	ServiceName      string            `json:"service_name"`
	Available        bool              `json:"available"`
	Operations       []SecurityOp      `json:"security_operations"`
	ExistingControls []ExistingControl `json:"existing_controls,omitempty"`
	TotalSecFields   int               `json:"total_security_fields"`
	CoveredFields    []CoveredField    `json:"covered_fields,omitempty"`
	UncoveredFields  []UncoveredField  `json:"uncovered_fields,omitempty"`
	CoveragePct      float64           `json:"coverage_pct"`
	IAMAuth          *IAMAuthInfo      `json:"iam_auth,omitempty"`
}

// IAMAuthInfo holds IAM authorization reference data for the service.
type IAMAuthInfo struct {
	ServicePrefix string   `json:"service_prefix"`
	DisplayName   string   `json:"display_name"`
	TotalActions  int      `json:"total_actions"`
	ARNFormat     string   `json:"arn_format,omitempty"`
	ConditionKeys []string `json:"condition_keys,omitempty"`
	HasResource   bool     `json:"has_resource"`
}

// ExistingControl is a control that matches the target service.
type ExistingControl struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Categories []string `json:"categories"`
}

// CoveredField is a security-relevant API field that has a
// matching control in the catalog.
type CoveredField struct {
	Operation string        `json:"operation"`
	Field     awsmeta.Field `json:"field"`
}

// UncoveredField is a security-relevant API field with no
// matching control — a coverage gap.
type UncoveredField struct {
	Operation  string        `json:"operation"`
	Field      awsmeta.Field `json:"field"`
	Categories []string      `json:"suggested_categories,omitempty"`
}
