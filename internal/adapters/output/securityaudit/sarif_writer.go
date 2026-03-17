package securityaudit

import (
	"encoding/json"
	"fmt"

	domain "github.com/sufield/stave/internal/domain/securityaudit"
)

// --- SARIF v2.1.0 typed structs ---

type sarifDocument struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name    string      `json:"name"`
	Version string      `json:"version"`
	Rules   []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string       `json:"id"`
	Name             string       `json:"name"`
	ShortDescription sarifMessage `json:"shortDescription"`
	Help             sarifMessage `json:"help"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID     string                `json:"ruleId"`
	RuleIndex  int                   `json:"ruleIndex"`
	Level      string                `json:"level"`
	Message    sarifMessage          `json:"message"`
	Properties sarifResultProperties `json:"properties"`
}

type sarifResultProperties struct {
	Pillar         domain.Pillar     `json:"pillar"`
	Status         domain.Status     `json:"status"`
	Severity       domain.Severity   `json:"severity"`
	Controls       []sarifControlRef `json:"controls"`
	Recommendation string            `json:"recommendation"`
}

type sarifControlRef struct {
	Framework string `json:"framework"`
	ControlID string `json:"control_id"`
	Rationale string `json:"rationale"`
}

// MarshalSARIFReport renders the security-audit report in SARIF v2.1.0.
func MarshalSARIFReport(report domain.Report) ([]byte, error) {
	rules := make([]sarifRule, 0, len(report.Findings))
	ruleIndex := make(map[string]int, len(report.Findings))
	results := make([]sarifResult, 0, len(report.Findings))

	for _, finding := range report.Findings {
		if _, exists := ruleIndex[finding.ID]; !exists {
			ruleIndex[finding.ID] = len(rules)
			rules = append(rules, sarifRule{
				ID:               finding.ID,
				Name:             finding.Title,
				ShortDescription: sarifMessage{Text: finding.Title},
				Help:             sarifMessage{Text: finding.Recommendation},
			})
		}

		controls := make([]sarifControlRef, 0, len(finding.ControlRefs))
		for _, control := range finding.ControlRefs {
			controls = append(controls, sarifControlRef{
				Framework: control.Framework,
				ControlID: control.ControlID,
				Rationale: control.Rationale,
			})
		}

		results = append(results, sarifResult{
			RuleID:    finding.ID,
			RuleIndex: ruleIndex[finding.ID],
			Level:     sarifLevelFromSeverity(finding.Severity),
			Message:   sarifMessage{Text: fmt.Sprintf("%s. %s", finding.Details, finding.AuditorHint)},
			Properties: sarifResultProperties{
				Pillar:         finding.Pillar,
				Status:         finding.Status,
				Severity:       finding.Severity,
				Controls:       controls,
				Recommendation: finding.Recommendation,
			},
		})
	}

	doc := sarifDocument{
		Version: "2.1.0",
		Schema:  "https://docs.oasis-open.org/sarif/sarif/v2.1.0/cos02/schemas/sarif-schema-2.1.0.json",
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:    "stave-security-audit",
						Version: report.ToolVersion,
						Rules:   rules,
					},
				},
				Results: results,
			},
		},
	}

	data, err := json.MarshalIndent(doc, "", "  ")
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
