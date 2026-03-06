package securityaudit

import (
	"encoding/json"
	"fmt"

	domain "github.com/sufield/stave/internal/domain/securityaudit"
)

// MarshalSARIFReport renders the security-audit report in SARIF v2.1.0.
func MarshalSARIFReport(report domain.Report) ([]byte, error) {
	rules := make([]map[string]any, 0, len(report.Findings))
	ruleIndex := make(map[string]int, len(report.Findings))
	results := make([]map[string]any, 0, len(report.Findings))

	for _, finding := range report.Findings {
		if _, exists := ruleIndex[finding.ID]; !exists {
			ruleIndex[finding.ID] = len(rules)
			rules = append(rules, map[string]any{
				"id":   finding.ID,
				"name": finding.Title,
				"shortDescription": map[string]string{
					"text": finding.Title,
				},
				"help": map[string]string{
					"text": finding.Recommendation,
				},
			})
		}

		controls := make([]map[string]string, 0, len(finding.ControlRefs))
		for _, control := range finding.ControlRefs {
			controls = append(controls, map[string]string{
				"framework":  control.Framework,
				"control_id": control.ControlID,
				"rationale":  control.Rationale,
			})
		}

		results = append(results, map[string]any{
			"ruleId":    finding.ID,
			"ruleIndex": ruleIndex[finding.ID],
			"level":     sarifLevelFromSeverity(finding.Severity),
			"message": map[string]string{
				"text": fmt.Sprintf("%s. %s", finding.Details, finding.AuditorHint),
			},
			"properties": map[string]any{
				"pillar":         finding.Pillar,
				"status":         finding.Status,
				"severity":       finding.Severity,
				"controls":       controls,
				"recommendation": finding.Recommendation,
			},
		})
	}

	sarif := map[string]any{
		"version": "2.1.0",
		"$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/cos02/schemas/sarif-schema-2.1.0.json",
		"runs": []map[string]any{
			{
				"tool": map[string]any{
					"driver": map[string]any{
						"name":    "stave-security-audit",
						"version": report.ToolVersion,
						"rules":   rules,
					},
				},
				"results": results,
			},
		},
	}

	data, err := json.MarshalIndent(sarif, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal security audit sarif: %w", err)
	}
	return append(data, '\n'), nil
}

func sarifLevelFromSeverity(severity domain.Severity) string {
	switch severity {
	case domain.SeverityCritical, domain.SeverityHigh:
		return "error"
	case domain.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}
