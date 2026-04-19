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
func (w *FindingWriter) MarshalFindings(enriched *appcontracts.EnrichedResult) ([]byte, error) {
	remFindings := toRemediationFindings(enriched.Findings)
	rules, ruleIndex := buildRules(remFindings)
	results := buildResults(remFindings, ruleIndex)

	// Annotate each SARIF result with its Issue fingerprint so
	// downstream consumers can reconstruct the consolidated view.
	// See docs/product/metrics.md § Metric 2.
	if len(enriched.Result.Issues) > 0 {
		fidToIssue := make(map[string]string, len(remFindings))
		for _, iss := range enriched.Result.Issues {
			for _, fid := range iss.MemberFindingIDs {
				fidToIssue[fid] = iss.IssueID
			}
		}
		for i := range results {
			if i >= len(remFindings) {
				break
			}
			if issueID, ok := fidToIssue[remFindings[i].FindingID]; ok {
				if results[i].PartialFingerprints == nil {
					results[i].PartialFingerprints = map[string]string{}
				}
				results[i].PartialFingerprints["stave/issue_id"] = issueID
			}
		}
	}

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

	for i := range findings {
		f := &findings[i]
		if _, exists := ruleIndex[f.ControlID]; exists {
			continue
		}
		ruleIndex[f.ControlID] = len(rules)
		rule := sarifRule{
			ID:   f.ControlID,
			Name: f.ControlName,
			ShortDescription: sarifMessage{
				Text: f.ControlDescription,
			},
		}
		if f.RemediationSpec.Action != "" {
			rule.Help = &sarifMessage{Text: f.RemediationSpec.Action}
		}
		tags := buildRuleTags(f)
		if len(tags) > 0 {
			rule.Properties = map[string]any{"tags": tags}
		}
		rules = append(rules, rule)
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

	for i := range findings {
		f := &findings[i]
		result := sarifResult{
			RuleID:    f.ControlID,
			RuleIndex: ruleIndex[f.ControlID],
			Level:     mapSeverityToSarif(f.ControlSeverity),
			Message: sarifMessage{
				Text: buildMessage(f),
			},
			Locations: buildLocations(f),
		}

		// Add fix suggestion from remediation.
		if f.RemediationSpec.Action != "" {
			result.Suggestions = []sarifSuggestion{
				{
					Description: sarifMessage{
						Text: f.RemediationSpec.Action,
					},
				},
			}
		}

		// Add chain context and reasoning trace to properties bag.
		// SARIF codeFlows is designed for source-code flow graphs; Stave's
		// compact predicate trace lives in the properties bag per SARIF
		// extension conventions.
		if len(f.ChainMembership) > 0 || len(f.ReasoningTrace) > 0 {
			result.Properties = map[string]any{}
			if len(f.ChainMembership) > 0 {
				cm := f.ChainMembership[0]
				result.Properties["chain_id"] = cm.ChainID
				result.Properties["chain_severity"] = cm.ChainSeverity
				result.Properties["stage_span"] = cm.StageSpan
				result.Properties["finding_id"] = f.FindingID
			}
			if len(f.ReasoningTrace) > 0 {
				trace := make([]map[string]any, len(f.ReasoningTrace))
				for i, mc := range f.ReasoningTrace {
					trace[i] = map[string]any{
						"predicate_expr":  mc.PredicateExpr,
						"observation_key": mc.ObservationKey,
						"operator":        mc.Operator,
						"expected_value":  mc.ExpectedValue,
						"observed_value":  mc.ObservedValue,
					}
				}
				result.Properties["reasoning_trace"] = trace
			}
		}

		results = append(results, result)
	}

	return results
}

func buildLocations(f *remediation.Finding) []sarifLocation {
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
// Chain-member findings get an [ATTACK PATH] prefix.
func buildMessage(f *remediation.Finding) string {
	var prefix string
	var suffix string
	if len(f.ChainMembership) > 0 {
		cm := f.ChainMembership[0]
		prefix = fmt.Sprintf("[ATTACK PATH: %s] ", cm.ChainID)
		suffix = ". This finding is part of a live attack path — chain severity: " + cm.ChainSeverity
	}
	msg := fmt.Sprintf("%s%s: %s on %s (%s)",
		prefix, f.ControlID, f.ControlName, f.AssetID, f.AssetType)
	if f.Evidence.TemporalRisk != "" {
		msg += ". " + f.Evidence.TemporalRisk
	}
	msg += suffix
	return msg
}

// buildRuleTags creates the tags array for a SARIF rule's properties.
func buildRuleTags(f *remediation.Finding) []string {
	var tags []string
	if f.ControlSeverity.String() != "" {
		tags = append(tags, "severity:"+f.ControlSeverity.String())
	}
	if f.Exposure != nil {
		tags = append(tags, "domain:"+string(f.Exposure.Type))
	}
	return tags
}

// toRemediationFindings converts port-boundary enriched findings to
// remediation.Finding for use by core formatting functions.
func toRemediationFindings(fs []appcontracts.EnrichedFinding) []remediation.Finding {
	out := make([]remediation.Finding, len(fs))
	for i := range fs {
		f := &fs[i]
		out[i] = remediation.Finding{
			Finding:         f.Finding,
			RemediationSpec: f.RemediationSpec,
			RemediationPlan: f.RemediationPlan,
		}
	}
	return out
}
