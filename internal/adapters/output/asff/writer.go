// Package asff maps Stave findings to the AWS Security Finding Format
// (ASFF v2018-10-08). This enables GRC tools that integrate via Security
// Hub to ingest Stave evidence without a custom connector.
package asff

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/report"
	"github.com/sufield/stave/internal/platform/providers/aws/iam"
)

// unknownAWSAccountID is the placeholder ASFF AccountId emitted when
// the asset identifier doesn't carry an extractable AWS account ID.
// AWS Security Hub validates the field's shape (12 digits) but
// accepts the all-zero sentinel as the documented "unknown owner"
// marker, so downstream rules that pivot on AccountId still parse
// the row instead of rejecting it for a missing field.
const unknownAWSAccountID = "000000000000"

// extractAWSAccountID pulls the 12-digit AWS account from an asset
// identifier (typically an ARN). Returns the unknown-account
// sentinel when no account could be parsed so the ASFF AccountId
// field stays well-formed. Mirrors the graph builder's account-ID
// extraction so the two output paths agree on what "owns" each
// finding.
func extractAWSAccountID(assetID string) string {
	if id := iam.ExtractAccountID(assetID); id != "" {
		return id
	}
	return unknownAWSAccountID
}

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

// ASFFOptions configures the ASFF output.
type ASFFOptions struct {
	AccountID string // 12-digit AWS account for the ProductARN; empty uses "000000000000"
	Region    string // AWS region for the ProductARN; empty uses "us-east-1"
}

func (o ASFFOptions) productARN() string {
	acct := o.AccountID
	if acct == "" {
		acct = unknownAWSAccountID
	}
	region := o.Region
	if region == "" {
		region = "us-east-1"
	}
	return fmt.Sprintf("arn:aws:securityhub:%s:%s:product/%s/stave", region, acct, acct)
}

// MapAssessment transforms a Stave assessment into ASFF findings.
// Returns an empty slice when assessment is nil so callers in the
// output dispatch can pass nil during error paths without an NPE
// at len(assessment.Findings).
func MapAssessment(assessment *report.Assessment) []ASFFinding {
	return MapAssessmentWithOptions(assessment, ASFFOptions{})
}

// MapAssessmentWithOptions is MapAssessment with configurable output.
func MapAssessmentWithOptions(assessment *report.Assessment, opts ASFFOptions) []ASFFinding {
	if assessment == nil {
		return []ASFFinding{}
	}
	timestamp := evalTimestamp(assessment)
	version := assessment.Run.StaveVersion
	productARN := opts.productARN()
	findings := make([]ASFFinding, 0, len(assessment.Findings))

	for i := range assessment.Findings {
		f := &assessment.Findings[i]
		findings = append(findings, mapFinding(f, timestamp, version, productARN))
	}

	return findings
}

func mapFinding(f *remediation.Finding, timestamp, version, productARN string) ASFFinding {
	sev := mapSeverity(f.SeverityLabel())

	af := ASFFinding{
		SchemaVersion: "2018-10-08",
		ID:            fmt.Sprintf("stave/%s/%s", f.ControlID, f.AssetID),
		ProductARN:    productARN,
		GeneratorID:   "stave-logic-engine",
		AWSAccountID:  extractAWSAccountID(string(f.AssetID)),
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
		ProductFields: buildProductFields(f, version),
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

// mapChainFindings adds compound chain findings as ASFF entries.
// Reads cf.ChainID / .AssetID / .Severity.String() / .CompoundScore /
// .Narrative / .Description through range with `:=` so this file
// never names findings.CompoundFinding directly. The chain-description
// fallback (Narrative preferred, Description as fallback) is inlined
// here — it used to live in a separate helper that pulled the
// risk type into its signature.
func mapChainFindings(assessment *report.Assessment, timestamp, productARN string) []ASFFinding {
	if assessment == nil || len(assessment.ChainFindings) == 0 {
		return nil
	}
	findings := make([]ASFFinding, 0, len(assessment.ChainFindings))
	for i := range assessment.ChainFindings {
		cf := &assessment.ChainFindings[i]
		desc := strings.TrimSpace(cf.Narrative)
		if desc == "" {
			desc = strings.TrimSpace(cf.Description)
		}
		sev := asffSeverityLabel(cf.Severity.String())
		findings = append(findings, ASFFinding{
			SchemaVersion: "2018-10-08",
			ID:            fmt.Sprintf("stave/chain/%s/%s", cf.ChainID, cf.AssetID),
			ProductARN:    productARN,
			GeneratorID:   "stave-logic-engine",
			AWSAccountID:  extractAWSAccountID(string(cf.AssetID)),
			Types:         []string{"Software and Configuration Checks/Vulnerabilities/Compound Risk"},
			CreatedAt:     timestamp,
			UpdatedAt:     timestamp,
			Severity: ASFFSeverity{
				Label:      sev,
				Normalized: severityToNormalized(sev),
			},
			Title:       "Compound Risk: " + string(cf.ChainID),
			Description: desc,
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
	return MarshalASFFWithOptions(assessment, ASFFOptions{})
}

// MarshalASFFWithOptions is MarshalASFF with configurable output.
func MarshalASFFWithOptions(assessment *report.Assessment, opts ASFFOptions) ([]byte, error) {
	if assessment == nil {
		return []byte("[]"), nil
	}
	timestamp := evalTimestamp(assessment)
	productARN := opts.productARN()
	findings := MapAssessmentWithOptions(assessment, opts)
	findings = append(findings, mapChainFindings(assessment, timestamp, productARN)...)
	return json.MarshalIndent(findings, "", "  ")
}

// evalTimestamp returns the RFC3339 eval-time from the assessment's RunInfo,
// falling back to the current time only when RunInfo has no eval-time set.
func evalTimestamp(a *report.Assessment) string {
	if !a.Run.EvalTime.IsZero() {
		return a.Run.EvalTime.UTC().Format(time.RFC3339)
	}
	return time.Now().UTC().Format(time.RFC3339)
}

// buildProductFields creates ASFF ProductFields with all compliance
// citations and enrichment fields from the finding. Mirrors the
// properties bag built by the SARIF writer's buildFindingProperties.
func buildProductFields(f *remediation.Finding, version string) map[string]string {
	if version == "" {
		version = "unknown"
	}
	fields := map[string]string{
		"ControlId":     string(f.ControlID),
		"SecurityState": "NON_COMPLIANT",
		"DurationHours": fmt.Sprintf("%.1f", f.DwellHours()),
		"StaveVersion":  version,
	}
	if f.Exploitability != "" {
		fields["Exploitability"] = string(f.Exploitability)
	}
	if f.DecidingLayer != "" {
		fields["DecidingLayer"] = string(f.DecidingLayer)
	}
	if f.ExposureScore > 0 {
		fields["ExposureScore"] = fmt.Sprintf("%.2f", float64(f.ExposureScore))
	}
	if f.IsChainMember() {
		fields["ChainId"] = f.PrimaryChainID()
		fields["ChainSeverity"] = f.PrimaryChainSeverity()
	}
	if f.HasClassification() {
		fields["Classification"] = string(f.Classification)
	}
	if f.FindingID != "" {
		fields["FindingId"] = string(f.FindingID)
	}
	for fw, req := range f.ControlCompliance {
		fields["Compliance."+string(fw)] = string(req)
	}
	return fields
}

func mapSeverity(sev string) ASFFSeverity {
	label := asffSeverityLabel(sev)
	return ASFFSeverity{
		Label:      label,
		Normalized: severityToNormalized(label),
	}
}

// asffSeverityLabel maps a Stave severity string to the ASFF-required
// uppercase label. ASFF v2018-10-08 requires one of: CRITICAL, HIGH,
// MEDIUM, LOW, INFORMATIONAL. Stave's "info" maps to INFORMATIONAL.
func asffSeverityLabel(sev string) string {
	trimmed := strings.TrimSpace(sev)
	switch {
	case strings.EqualFold(trimmed, "critical"):
		return "CRITICAL"
	case strings.EqualFold(trimmed, "high"):
		return "HIGH"
	case strings.EqualFold(trimmed, "medium"):
		return "MEDIUM"
	case strings.EqualFold(trimmed, "low"):
		return "LOW"
	case strings.EqualFold(trimmed, "info"):
		return "INFORMATIONAL"
	default:
		return "INFORMATIONAL"
	}
}

func severityToNormalized(label string) int {
	switch label {
	case "CRITICAL":
		return 90
	case "HIGH":
		return 70
	case "MEDIUM":
		return 40
	case "LOW":
		return 10
	default:
		return 1
	}
}
