// Package sarif provides SARIF v2.1.0 output for GitHub Code Scanning integration.
package sarif

import (
	"bytes"
	"encoding/json"
	"fmt"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/kernel"
)

// Option configures a FindingWriter.
type Option func(*FindingWriter)

// FindingWriter marshals findings as SARIF v2.1.0 JSON.
type FindingWriter struct {
	toolName string
}

var _ appcontracts.FindingMarshaler = (*FindingWriter)(nil)

// NewFindingWriter creates a new SARIF finding marshaler.
func NewFindingWriter(opts ...Option) *FindingWriter {
	w := &FindingWriter{
		toolName: "stave",
	}
	for _, opt := range opts {
		opt(w)
	}
	return w
}

// MarshalFindings transforms enriched findings into SARIF v2.1.0 JSON bytes
// without performing I/O.
func (w *FindingWriter) MarshalFindings(enriched appcontracts.EnrichedResult) ([]byte, error) {
	remFindings := toRemediationFindings(enriched.Findings)
	rules, ruleIndex := buildRules(remFindings)
	results := buildResults(remFindings, ruleIndex)

	report := sarifReport{
		Version: "2.1.0",
		Schema:  "https://docs.oasis-open.org/sarif/sarif/v2.1.0/cos02/schemas/sarif-schema-2.1.0.json",
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:    w.toolName,
						Version: enriched.Result.Run.StaveVersion,
						Rules:   rules,
					},
				},
				Results: results,
			},
		},
	}

	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(report); err != nil {
		return nil, fmt.Errorf("sarif encode: %w", err)
	}
	return buf.Bytes(), nil
}

// buildRules deduplicates control IDs and builds SARIF rule descriptors.
// Returns the rules slice and a map from control_id to rule index.
func buildRules(findings []remediation.Finding) ([]sarifRule, map[kernel.ControlID]int) {
	ruleIndex := make(map[kernel.ControlID]int, len(findings))
	rules := make([]sarifRule, 0, len(findings))

	for _, f := range findings {
		if _, exists := ruleIndex[f.ControlID]; exists {
			continue
		}
		ruleIndex[f.ControlID] = len(rules)
		rules = append(rules, sarifRule{
			ID:   f.ControlID,
			Name: f.ControlName,
			ShortDescription: sarifMessage{
				Text: f.ControlDescription,
			},
		})
	}

	return rules, ruleIndex
}

// mapSeverityToSarif converts a policy severity to a SARIF level string.
func mapSeverityToSarif(s policy.Severity) string {
	switch s {
	case policy.SeverityCritical, policy.SeverityHigh:
		return "error"
	case policy.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

// buildResults converts enriched findings to SARIF result objects.
func buildResults(findings []remediation.Finding, ruleIndex map[kernel.ControlID]int) []sarifResult {
	results := make([]sarifResult, 0, len(findings))

	for _, f := range findings {
		result := sarifResult{
			RuleID:    f.ControlID,
			RuleIndex: ruleIndex[f.ControlID],
			Level:     mapSeverityToSarif(f.ControlSeverity),
			Message: sarifMessage{
				Text: buildMessage(f),
			},
			Locations: buildLocations(f),
		}

		// Add fix suggestion from remediation
		if f.RemediationSpec.Action != "" {
			result.Suggestions = []sarifSuggestion{
				{
					Description: sarifMessage{
						Text: f.RemediationSpec.Action,
					},
				},
			}
		}

		results = append(results, result)
	}

	return results
}

func buildLocations(f remediation.Finding) []sarifLocation {
	if f.Source != nil {
		return []sarifLocation{
			{
				PhysicalLocation: &sarifPhysicalLocation{
					ArtifactLocation: sarifArtifactLocation{
						URI: f.Source.File,
					},
					Region: sarifRegion{
						StartLine: f.Source.Line,
					},
				},
			},
		}
	}

	return []sarifLocation{
		{
			LogicalLocations: []sarifLogicalLocation{
				{
					Name:               string(f.AssetID),
					FullyQualifiedName: string(f.AssetID),
					Kind:               "resource",
				},
			},
		},
	}
}

// buildMessage creates a human-readable message for a SARIF result.
func buildMessage(f remediation.Finding) string {
	msg := fmt.Sprintf("%s: %s on %s (%s)",
		f.ControlID, f.ControlName, f.AssetID, f.AssetType)
	if f.Evidence.WhyNow != "" {
		msg += ". " + f.Evidence.WhyNow
	}
	return msg
}

// toRemediationFindings converts port-boundary enriched findings to
// remediation.Finding for use by core formatting functions.
func toRemediationFindings(fs []appcontracts.EnrichedFinding) []remediation.Finding {
	out := make([]remediation.Finding, len(fs))
	for i, f := range fs {
		out[i] = remediation.Finding{
			Finding:         f.Finding,
			RemediationSpec: f.RemediationSpec,
			RemediationPlan: f.RemediationPlan,
		}
	}
	return out
}
