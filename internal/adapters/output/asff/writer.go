// Package asff maps Stave findings to the AWS Security Finding Format
// (ASFF v2018-10-08). This enables GRC tools that integrate via Security
// Hub to ingest Stave evidence without a custom connector.
package asff

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/report"
	"github.com/sufield/stave/internal/platform/providers/aws/iam"
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

// ASFFOptions configures the ASFF output.
type ASFFOptions struct {
	AccountID string // 12-digit AWS account for the ProductARN
	Region    string // AWS region for the ProductARN
}

// resolveProductARN builds the ProductARN from explicit options or
// observation ARNs. Returns an error when neither source provides
// account or region. Environment variable fallback belongs at the
// CLI boundary, not here.
func resolveProductARN(opts ASFFOptions, assessment *report.Assessment) (string, error) {
	acct := opts.AccountID
	region := opts.Region

	if (acct == "" || region == "") && assessment != nil {
		derivedAcct, derivedRegion := deriveFromFindings(assessment)
		if acct == "" {
			acct = derivedAcct
		}
		if region == "" {
			region = derivedRegion
		}
	}

	if acct == "" || region == "" {
		var missing []string
		if acct == "" {
			missing = append(missing, "account ID")
		}
		if region == "" {
			missing = append(missing, "region")
		}
		return "", fmt.Errorf("ASFF output requires %s; pass --asff-account/--asff-region or ensure observations contain ARNs with account information",
			strings.Join(missing, " and "))
	}

	return fmt.Sprintf("arn:aws:securityhub:%s:%s:product/%s/stave", region, acct, acct), nil
}

// deriveFromFindings extracts account ID and region from the first
// finding whose asset ID is a parseable ARN with those fields.
func deriveFromFindings(assessment *report.Assessment) (account, region string) {
	for i := range assessment.Findings {
		parsed := iam.ParseARN(string(assessment.Findings[i].AssetID))
		if account == "" && parsed.AccountID != "" {
			account = parsed.AccountID
		}
		if region == "" && parsed.Region != "" {
			region = parsed.Region
		}
		if account != "" && region != "" {
			return
		}
	}
	for i := range assessment.ChainFindings {
		parsed := iam.ParseARN(string(assessment.ChainFindings[i].AssetID))
		if account == "" && parsed.AccountID != "" {
			account = parsed.AccountID
		}
		if region == "" && parsed.Region != "" {
			region = parsed.Region
		}
		if account != "" && region != "" {
			return
		}
	}
	return
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

// extractAWSAccountID pulls the 12-digit AWS account from an asset
// identifier (typically an ARN). Returns "unknown" when no account
// could be parsed.
func extractAWSAccountID(assetID string) string {
	if id := iam.ExtractAccountID(assetID); id != "" {
		return id
	}
	return "unknown"
}

// mapChainFindings adds compound chain findings as ASFF entries.
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
// Returns an error when account ID or region cannot be determined.
func MarshalASFF(assessment *report.Assessment) ([]byte, error) {
	return MarshalASFFWithOptions(assessment, ASFFOptions{})
}

// MarshalASFFWithOptions is MarshalASFF with configurable output.
func MarshalASFFWithOptions(assessment *report.Assessment, opts ASFFOptions) ([]byte, error) {
	if assessment == nil {
		return []byte("[]"), nil
	}

	productARN, err := resolveProductARN(opts, assessment)
	if err != nil {
		return nil, err
	}

	timestamp := evalTimestamp(assessment)
	version := assessment.Run.StaveVersion
	all := make([]ASFFinding, 0, len(assessment.Findings)+len(assessment.ChainFindings))

	for i := range assessment.Findings {
		f := &assessment.Findings[i]
		all = append(all, mapFinding(f, timestamp, version, productARN))
	}
	all = append(all, mapChainFindings(assessment, timestamp, productARN)...)

	if len(all) == 0 {
		return []byte("[]"), nil
	}

	return json.MarshalIndent(all, "", "  ")
}

// ErrMissingIdentity is returned when the ASFF writer cannot determine
// account ID or region from any source.
var ErrMissingIdentity = errors.New("ASFF output requires account ID and region")

// evalTimestamp returns the RFC3339 eval-time from the assessment's RunInfo.
func evalTimestamp(a *report.Assessment) string {
	if a.Run.EvalTime.IsZero() {
		panic("ASFF: assessment has zero EvalTime — the upstream pipeline must set RunInfo.EvalTime")
	}
	return a.Run.EvalTime.UTC().Format(time.RFC3339)
}

// buildProductFields creates ASFF ProductFields with all compliance
// citations and enrichment fields from the finding.
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
