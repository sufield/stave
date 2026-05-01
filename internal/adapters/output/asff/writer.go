// Package asff maps Stave findings to the AWS Security Finding Format
// (ASFF v2018-10-08). This enables GRC tools that integrate via Security
// Hub to ingest Stave evidence without a custom connector.
package asff

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/evaluation/risk"
	"github.com/sufield/stave/internal/core/report"
)

// ASFFinding represents a single finding in AWS Security Finding Format.
type ASFFinding struct {
	SchemaVersion string            `json:"SchemaVersion"`
	ID            string            `json:"Id"`
	ProductARN    string            `json:"ProductArn"`
	GeneratorID   string            `json:"GeneratorId"`
	AWSAccountID  string            `json:"AwsAccountId"`
	Types         []string          `json:"Types"`
	CreatedAt     string            `json:"CreatedAt"`
	UpdatedAt     string            `json:"UpdatedAt"`
	Severity      ASFFSeverity      `json:"Severity"`
	Title         string            `json:"Title"`
	Description   string            `json:"Description"`
	Remediation   *ASFFRemediation  `json:"Remediation,omitempty"`
	ProductFields map[string]string `json:"ProductFields,omitempty"`
	Resources     []ASFFResource    `json:"Resources"`
}

// ASFFSeverity maps to ASFF severity levels.
type ASFFSeverity struct {
	Label      string `json:"Label"`
	Normalized int    `json:"Normalized"`
}

// ASFFRemediation provides fix guidance in ASFF format.
type ASFFRemediation struct {
	Recommendation ASFFRecommendation `json:"Recommendation"`
}

// ASFFRecommendation holds the remediation text.
type ASFFRecommendation struct {
	Text string `json:"Text"`
}

// ASFFResource identifies the affected resource.
type ASFFResource struct {
	Type string `json:"Type"`
	ID   string `json:"Id"`
}

// MapAssessment transforms a Stave assessment into ASFF findings.
// Returns an empty slice when assessment is nil so callers in the
// output dispatch can pass nil during error paths without an NPE
// at len(assessment.Findings).
func MapAssessment(assessment *report.Assessment) []ASFFinding {
	if assessment == nil {
		return []ASFFinding{}
	}
	now := time.Now().UTC().Format(time.RFC3339)
	findings := make([]ASFFinding, 0, len(assessment.Findings))

	for i := range assessment.Findings {
		f := &assessment.Findings[i]
		findings = append(findings, mapFinding(f, now))
	}

	return findings
}

func mapFinding(f *remediation.Finding, timestamp string) ASFFinding {
	sev := mapSeverity(f.ControlSeverity.String())

	af := ASFFinding{
		SchemaVersion: "2018-10-08",
		ID:            fmt.Sprintf("stave/%s/%s", f.ControlID, f.AssetID),
		ProductARN:    "arn:aws:securityhub:local:stave:product/stave/safety-engine",
		GeneratorID:   "stave-logic-engine",
		AWSAccountID:  "000000000000",
		Types:         []string{"Software and Configuration Checks/Vulnerabilities/Misconfiguration"},
		CreatedAt:     timestamp,
		UpdatedAt:     timestamp,
		Severity:      sev,
		Title:         f.ControlName,
		Description:   f.ControlDescription,
		Resources: []ASFFResource{{
			Type: string(f.AssetType),
			ID:   string(f.AssetID),
		}},
		ProductFields: buildProductFields(f),
	}

	if f.RemediationSpec.Action != "" {
		af.Remediation = &ASFFRemediation{
			Recommendation: ASFFRecommendation{
				Text: f.RemediationSpec.Action,
			},
		}
	}

	return af
}

// MapChainFindings adds compound chain findings as ASFF entries.
func MapChainFindings(chains []risk.CompoundFinding, timestamp string) []ASFFinding {
	findings := make([]ASFFinding, 0, len(chains))
	for i := range chains {
		cf := &chains[i]
		findings = append(findings, ASFFinding{
			SchemaVersion: "2018-10-08",
			ID:            "stave/chain/" + string(cf.ChainID),
			ProductARN:    "arn:aws:securityhub:local:stave:product/stave/safety-engine",
			GeneratorID:   "stave-logic-engine",
			AWSAccountID:  "000000000000",
			Types:         []string{"Software and Configuration Checks/Vulnerabilities/Compound Risk"},
			CreatedAt:     timestamp,
			UpdatedAt:     timestamp,
			Severity: ASFFSeverity{
				Label:      cf.Severity.String(),
				Normalized: severityToNormalized(cf.Severity.String()),
			},
			Title:       "Compound Risk: " + string(cf.ChainID),
			Description: cf.Narrative,
			Resources:   []ASFFResource{{Type: "Other", ID: string(cf.ChainID)}},
			ProductFields: map[string]string{
				"ChainId":       string(cf.ChainID),
				"CompoundScore": fmt.Sprintf("%.1f", cf.CompoundScore),
			},
		})
	}
	return findings
}

// MarshalASFF produces the complete ASFF JSON output.
// Returns an empty JSON array when assessment is nil rather than
// dereferencing assessment.ChainFindings.
func MarshalASFF(assessment *report.Assessment) ([]byte, error) {
	if assessment == nil {
		return []byte("[]"), nil
	}
	now := time.Now().UTC().Format(time.RFC3339)
	findings := MapAssessment(assessment)
	findings = append(findings, MapChainFindings(assessment.ChainFindings, now)...)
	return json.MarshalIndent(findings, "", "  ")
}

// buildProductFields creates ASFF ProductFields with all compliance
// citations from the finding's ComplianceMapping. GRC tools see the
// finding mapped to every relevant framework dashboard.
func buildProductFields(f *remediation.Finding) map[string]string {
	fields := map[string]string{
		"ControlId":     string(f.ControlID),
		"SecurityState": "NON_COMPLIANT",
		"DurationHours": fmt.Sprintf("%.1f", f.Evidence.UnsafeDurationHours),
		"StaveVersion":  "edge",
	}
	// Add all compliance citations as separate ProductFields.
	for fw, req := range f.ControlCompliance {
		fields["Compliance."+string(fw)] = req
	}
	return fields
}

func mapSeverity(sev string) ASFFSeverity {
	return ASFFSeverity{
		Label:      sev,
		Normalized: severityToNormalized(sev),
	}
}

func severityToNormalized(sev string) int {
	switch sev {
	case "critical":
		return 90
	case "high":
		return 70
	case "medium":
		return 40
	case "low":
		return 10
	default:
		return 0
	}
}
