package report

import (
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/sufield/stave/internal/domain/evaluation/remediation"
	"github.com/sufield/stave/internal/safetyenvelope"
)

type reportOutput struct {
	GeneratedAt        string                           `json:"generated_at"`
	ToolVersion        string                           `json:"tool_version"`
	Run                reportRun                        `json:"run"`
	Summary            reportSummary                    `json:"summary"`
	FindingsBySeverity map[string]int                   `json:"findings_by_severity"`
	ComplianceSummary  map[string]reportComplianceEntry `json:"compliance_summary,omitempty"`
	Findings           []reportFinding                  `json:"findings"`
	Remediations       []reportRemediation              `json:"remediations"`
}

type reportComplianceEntry struct {
	TotalFindings      int            `json:"total_findings"`
	FindingsBySeverity map[string]int `json:"findings_by_severity"`
	Controls           []string       `json:"controls"`
}

type reportRun struct {
	EvaluationTime string `json:"evaluation_time"`
	MaxUnsafe      string `json:"max_unsafe"`
	Snapshots      int    `json:"snapshots"`
	Offline        bool   `json:"offline"`
}

type reportSummary struct {
	AssetsEvaluated int `json:"assets_evaluated"`
	AttackSurface   int `json:"attack_surface"`
	Violations      int `json:"violations"`
	Skipped         int `json:"skipped"`
}

type reportFinding struct {
	ControlID   string            `json:"control_id"`
	AssetID     string            `json:"asset_id"`
	AssetType   string            `json:"asset_type"`
	Vendor      string            `json:"vendor"`
	Severity    string            `json:"severity,omitempty"`
	Compliance  map[string]string `json:"compliance,omitempty"`
	DurationH   float64           `json:"duration_hours"`
	ThresholdH  float64           `json:"threshold_hours"`
	FirstUnsafe string            `json:"first_unsafe,omitempty"`
	LastUnsafe  string            `json:"last_unsafe,omitempty"`
}

type reportRemediation struct {
	ControlID   string `json:"control_id"`
	AssetID     string `json:"asset_id"`
	Description string `json:"description"`
	Action      string `json:"action"`
	Example     string `json:"example,omitempty"`
}

// RenderJSON serialises the evaluation as JSON and writes it to w unless quiet is true.
func RenderJSON(eval safetyenvelope.Evaluation, toolVersion string, w io.Writer, quiet bool) error {
	data := buildReportViewModel(eval, toolVersion)
	output, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal report JSON: %w", err)
	}
	output = append(output, '\n')
	if quiet {
		return nil
	}
	if _, err := w.Write(output); err != nil {
		return fmt.Errorf("write report: %w", err)
	}
	return nil
}

func buildReportViewModel(eval safetyenvelope.Evaluation, toolVersion string) reportOutput {
	out := newReportOutput(eval, toolVersion)
	complianceData := make(map[string]*reportComplianceEntry)
	for _, finding := range eval.Findings {
		appendReportFinding(&out, complianceData, finding)
	}

	out.Findings = sortReportFindings(out.Findings)
	finalizeReportComplianceSummary(&out, complianceData)
	return out
}

func newReportOutput(eval safetyenvelope.Evaluation, toolVersion string) reportOutput {
	generated := eval.Run.Now.UTC()
	return reportOutput{
		GeneratedAt: generated.Format(time.RFC3339),
		ToolVersion: toolVersion,
		Run: reportRun{
			EvaluationTime: eval.Run.Now.Format(time.RFC3339),
			MaxUnsafe:      eval.Run.MaxUnsafe.String(),
			Snapshots:      eval.Run.Snapshots,
			Offline:        eval.Run.Offline,
		},
		Summary: reportSummary{
			AssetsEvaluated: eval.Summary.AssetsEvaluated,
			AttackSurface:   eval.Summary.AttackSurface,
			Violations:      eval.Summary.Violations,
			Skipped:         len(eval.Skipped),
		},
		FindingsBySeverity: make(map[string]int),
		Findings:           make([]reportFinding, 0, len(eval.Findings)),
		Remediations:       make([]reportRemediation, 0, len(eval.Findings)),
	}
}

func appendReportFinding(
	out *reportOutput,
	complianceData map[string]*reportComplianceEntry,
	finding remediation.Finding,
) {
	out.Findings = append(out.Findings, toReportFinding(finding))
	out.Remediations = append(out.Remediations, toReportRemediation(finding))
	sev := normalizedSeverity(finding.ControlSeverity.String())
	out.FindingsBySeverity[sev]++
	updateComplianceData(complianceData, finding.ControlCompliance, sev)
}

func toReportFinding(finding remediation.Finding) reportFinding {
	out := reportFinding{
		ControlID:  string(finding.ControlID),
		AssetID:    string(finding.AssetID),
		AssetType:  string(finding.AssetType),
		Vendor:     string(finding.AssetVendor),
		Severity:   finding.ControlSeverity.String(),
		Compliance: finding.ControlCompliance,
		DurationH:  finding.Evidence.UnsafeDurationHours,
		ThresholdH: finding.Evidence.ThresholdHours,
	}
	if !finding.Evidence.FirstUnsafeAt.IsZero() {
		out.FirstUnsafe = finding.Evidence.FirstUnsafeAt.Format(time.RFC3339)
	}
	if !finding.Evidence.LastSeenUnsafeAt.IsZero() {
		out.LastUnsafe = finding.Evidence.LastSeenUnsafeAt.Format(time.RFC3339)
	}
	return out
}

func toReportRemediation(finding remediation.Finding) reportRemediation {
	return reportRemediation{
		ControlID:   string(finding.ControlID),
		AssetID:     string(finding.AssetID),
		Description: finding.RemediationSpec.Description,
		Action:      finding.RemediationSpec.Action,
		Example:     finding.RemediationSpec.Example,
	}
}

func updateComplianceData(complianceData map[string]*reportComplianceEntry, compliance map[string]string, severity string) {
	for framework, control := range compliance {
		entry := ensureComplianceEntry(complianceData, framework)
		entry.TotalFindings++
		entry.FindingsBySeverity[severity]++
		if !slices.Contains(entry.Controls, control) {
			entry.Controls = append(entry.Controls, control)
		}
	}
}

func ensureComplianceEntry(complianceData map[string]*reportComplianceEntry, framework string) *reportComplianceEntry {
	entry, ok := complianceData[framework]
	if ok {
		return entry
	}
	entry = &reportComplianceEntry{FindingsBySeverity: make(map[string]int)}
	complianceData[framework] = entry
	return entry
}

func finalizeReportComplianceSummary(out *reportOutput, complianceData map[string]*reportComplianceEntry) {
	if len(complianceData) == 0 {
		return
	}
	out.ComplianceSummary = make(map[string]reportComplianceEntry, len(complianceData))
	for framework, entry := range complianceData {
		slices.Sort(entry.Controls)
		out.ComplianceSummary[framework] = *entry
	}
}

func severityRank(s string) int {
	s = normalizedSeverity(s)
	switch s {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium":
		return 2
	case "low":
		return 3
	case "info":
		return 4
	default:
		return 5
	}
}

func normalizedSeverity(s string) string {
	v := strings.ToLower(strings.TrimSpace(s))
	if v == "" {
		return "unspecified"
	}
	return v
}

func sortReportFindings(in []reportFinding) []reportFinding {
	out := make([]reportFinding, len(in))
	copy(out, in)
	slices.SortFunc(out, func(a, b reportFinding) int {
		if ra, rb := severityRank(a.Severity), severityRank(b.Severity); ra != rb {
			return ra - rb
		}
		if c := strings.Compare(a.ControlID, b.ControlID); c != 0 {
			return c
		}
		return strings.Compare(a.AssetID, b.AssetID)
	})
	return out
}
