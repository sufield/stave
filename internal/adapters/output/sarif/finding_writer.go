// Package sarif provides SARIF v2.1.0 output for GitHub Code Scanning integration.
package sarif

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"

	"github.com/sufield/stave/internal/adapters/output"
	appcontracts "github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/internal/domain/evaluation"
	"github.com/sufield/stave/internal/domain/evaluation/remediation"
	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/domain/policy"
)

// FindingEnricher enriches raw evaluation findings with remediation guidance.
type FindingEnricher interface {
	EnrichFindings(evaluation.Result) []remediation.Finding
}

// Option configures a FindingWriter.
type Option func(*FindingWriter)

// FindingWriter writes findings as SARIF v2.1.0 JSON.
type FindingWriter struct {
	enricher  FindingEnricher
	sanitizer kernel.Sanitizer
	toolName  string
}

type sarifReport struct {
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
	ID               kernel.ControlID `json:"id"`
	Name             string           `json:"name"`
	ShortDescription sarifMessage     `json:"shortDescription"`
}

type sarifResult struct {
	RuleID    kernel.ControlID `json:"ruleId"`
	RuleIndex int              `json:"ruleIndex"`
	Level     string           `json:"level"`
	Message   sarifMessage     `json:"message"`
	Locations []sarifLocation  `json:"locations"`
	// Suggestions are rendered using SARIF's "fixes" field for compatibility.
	Suggestions []sarifSuggestion `json:"fixes,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation *sarifPhysicalLocation `json:"physicalLocation,omitempty"`
	LogicalLocations []sarifLogicalLocation `json:"logicalLocations,omitempty"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

type sarifLogicalLocation struct {
	Name               string `json:"name"`
	FullyQualifiedName string `json:"fullyQualifiedName"`
	Kind               string `json:"kind"`
}

type sarifSuggestion struct {
	Description sarifMessage `json:"description"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

var _ appcontracts.FindingWriter = (*FindingWriter)(nil)
var _ appcontracts.FindingMarshaler = (*FindingWriter)(nil)

// NewFindingWriter creates a new SARIF finding writer.
func NewFindingWriter(enricher FindingEnricher, sanitizer kernel.Sanitizer, opts ...Option) (*FindingWriter, error) {
	if enricher == nil {
		return nil, fmt.Errorf("enricher is required for sarif writer")
	}
	w := &FindingWriter{
		enricher:  enricher,
		sanitizer: sanitizer,
		toolName:  "stave",
	}
	for _, opt := range opts {
		opt(w)
	}
	return w, nil
}

// WriteFindings writes the evaluation result as SARIF v2.1.0 JSON.
func (w *FindingWriter) WriteFindings(out io.Writer, result evaluation.Result) error {
	enriched := output.Enrich(w.enricher, w.sanitizer, result)
	data, err := w.MarshalFindings(enriched)
	if err != nil {
		return err
	}
	_, err = out.Write(data)
	return err
}

// MarshalFindings transforms enriched findings into SARIF v2.1.0 JSON bytes
// without performing I/O.
func (w *FindingWriter) MarshalFindings(enriched appcontracts.EnrichedResult) ([]byte, error) {
	rules, ruleIndex := buildRules(enriched.Findings)
	results := buildResults(enriched.Findings, ruleIndex)

	report := sarifReport{
		Version: "2.1.0",
		Schema:  "https://docs.oasis-open.org/sarif/sarif/v2.1.0/cos02/schemas/sarif-schema-2.1.0.json",
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:    w.toolName,
						Version: enriched.Result.Run.ToolVersion,
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
