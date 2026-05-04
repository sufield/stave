// Package sarif provides SARIF v2.1.0 output for GitHub Code Scanning integration.
//
// TDA in adapters: this writer queries domain predicates
// (Finding.IsChainMember, HasEnrichedContext, IsOverdue, ...) to
// decide which SARIF properties to emit. That is acceptable Tell-
// Don't-Ask: the adapter is asking the domain "is this finding in
// state X?" so it can pick a representation. It is NOT acceptable
// for the adapter to reproduce domain logic inline (e.g. computing
// SLA breach from f.SLADeadlineHours and f.Evidence.UnsafeDuration
// here) — those checks must live on Finding so a single edit on the
// type updates every output adapter at once.
package sarif

import (
	"bytes"
	"encoding/json"
	"errors"
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
//
// Returns an error when enriched is nil rather than panicking on
// the .Findings access — the public marshaller is reachable from
// error paths where the upstream pipeline may legitimately yield
// no result and pass nil through.
func (w *FindingWriter) MarshalFindings(enriched *appcontracts.EnrichedResult) ([]byte, error) {
	if enriched == nil {
		return nil, errors.New("sarif: nil EnrichedResult")
	}
	remFindings := toRemediationFindings(enriched.Findings)
	rules, ruleIndex := buildRules(remFindings)
	results := buildResults(remFindings, ruleIndex)

	// Annotate each SARIF result with its Issue fingerprint so
	// downstream consumers can reconstruct the consolidated view.
	// See docs/product/metrics.md § Metric 2.
	if len(enriched.Result.Issues) > 0 {
		// Verify the architectural contract before walking the two
		// slices in lockstep — buildResults is required to preserve
		// per-finding order so issue-id metadata lands on the right
		// SARIF row. A future change that filters or reorders would
		// otherwise silently mis-attribute the annotations.
		verifyPositionalInvariant(results, remFindings)
		fidToIssue := make(map[string]string, len(remFindings))
		for _, iss := range enriched.Result.Issues {
			for _, fid := range iss.MemberFindingIDs {
				fidToIssue[string(fid)] = string(iss.IssueID)
			}
		}
		for i := range results {
			if issueID, ok := fidToIssue[string(remFindings[i].FindingID)]; ok {
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

// verifyPositionalInvariant ensures that the generated SARIF results
// maintain a strict 1-to-1 positional mapping with the source
// findings. The annotate-issue-id loop in MarshalFindings reads
// `results[i]` and `findings[i]` together, so any divergence in
// length means a future change to buildResults (filtering,
// reordering, deduplication) has broken the contract. Failing loud
// at the assertion point names the architectural rule that was
// violated; a silent mismatch would attribute issue-id metadata to
// the wrong SARIF row, sending operators to investigate the wrong
// finding.
func verifyPositionalInvariant(results []sarifResult, findings []remediation.Finding) {
	if len(results) != len(findings) {
		panic(fmt.Sprintf(
			"sarif: positional invariant violated (results: %d, findings: %d); "+
				"buildResults must preserve finding order so issue-id annotations land on the correct row",
			len(results), len(findings),
		))
	}
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
		alts := alternativesAsProperties(f.Alternatives)
		if len(tags) > 0 || len(alts) > 0 {
			rule.Properties = map[string]any{}
			if len(tags) > 0 {
				rule.Properties["tags"] = tags
			}
			if len(alts) > 0 {
				rule.Properties["alternatives"] = alts
			}
		}
		rules = append(rules, rule)
	}

	return rules, ruleIndex
}

// buildResults converts enriched findings to SARIF result objects.
func buildResults(findings []remediation.Finding, ruleIndex map[kernel.ControlID]int) []sarifResult {
	results := make([]sarifResult, 0, len(findings))

	for i := range findings {
		f := &findings[i]
		result := sarifResult{
			RuleID:    f.ControlID,
			RuleIndex: ruleIndex[f.ControlID],
			Level:     f.ControlSeverity.SARIFLevel(),
			Message: sarifMessage{
				Text: buildMessage(f),
			},
			Locations: buildLocations(f),
		}

		// Add fix suggestion from remediation. Prefer the asset-
		// parameterized Command (from RemediationPlan) when present;
		// fall back to the raw template Action on the spec. See
		// docs/product/metrics.md § Metric 4 (SARIF fix-object
		// completeness).
		fixText := f.RemediationSpec.Action
		if cmd, ok := f.RemediationCommand(); ok {
			fixText = cmd
		}
		if fixText != "" {
			result.Suggestions = []sarifSuggestion{
				{
					Description: sarifMessage{Text: fixText},
					// SARIF 2.1.0 §3.55 requires at least one entry in
					// changes for a valid fix object. Stave does not
					// know a source-file location to patch — findings
					// target cloud resources — so we emit a single
					// placeholder change pointing at the asset URI
					// with the remediation text as insertedContent.
					Changes: []sarifChange{
						{
							ArtifactLocation: sarifArtifactLocation{URI: string(f.AssetID)},
							Replacements: []sarifReplacement{
								{
									DeletedRegion: sarifRegion{
										StartLine:   1,
										StartColumn: 1,
										EndLine:     1,
										EndColumn:   1,
									},
									InsertedContent: sarifMessageString{Text: fixText},
								},
							},
						},
					},
				},
			}
		}

		// Add chain context, reasoning trace, alternative-tool
		// coverage, and semantic classification to properties bag.
		// SARIF codeFlows is designed for source-code flow graphs;
		// Stave's compact predicate trace, per-finding alternatives,
		// and semantic classification use the properties bag per
		// SARIF extension conventions.
		alts := alternativesAsProperties(f.Alternatives)
		// HasEnrichedContext folds the
		// (chain | trace | alts | class | scope_tags)
		// disjunction into one predicate on Finding so a future
		// enrichment field is one edit on the type — see
		// internal/core/evaluation/finding.go.
		if f.HasEnrichedContext() {
			result.Properties = map[string]any{}
			if f.HasClassification() {
				result.Properties["stave/classification"] = string(f.Classification)
			}
			if f.HasScopeTags() {
				tags := make([]string, len(f.ScopeTags))
				for i, t := range f.ScopeTags {
					tags[i] = string(t)
				}
				result.Properties["stave/scope_tags"] = tags
			}
			if f.IsChainMember() {
				result.Properties["chain_id"] = f.PrimaryChainID()
				result.Properties["chain_severity"] = f.PrimaryChainSeverity()
				result.Properties["stage_span"] = f.PrimaryChainStageSpan()
				result.Properties["finding_id"] = f.FindingID
			}
			if f.HasReasoningTrace() {
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
			if len(alts) > 0 {
				result.Properties["alternatives"] = alts
			}
		}

		results = append(results, result)
	}

	return results
}

func buildLocations(f *remediation.Finding) []sarifLocation {
	if f.HasSource() {
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
	if f.IsChainMember() {
		prefix = fmt.Sprintf("[ATTACK PATH: %s] ", f.PrimaryChainID())
		suffix = ". This finding is part of a live attack path — chain severity: " + f.PrimaryChainSeverity()
	}
	msg := fmt.Sprintf("%s%s: %s on %s (%s)",
		prefix, f.ControlID, f.ControlName, f.AssetID, f.AssetType)
	if risk := f.TemporalRiskMessage(); risk != "" {
		msg += ". " + risk
	}
	msg += suffix
	return msg
}

// alternativesAsProperties shapes a control's alternative-tool entries
// for the SARIF properties bag. Returns nil when there are no entries
// so callers can branch cleanly on len(alts) > 0.
func alternativesAsProperties(alts []policy.Alternative) []map[string]any {
	if len(alts) == 0 {
		return nil
	}
	out := make([]map[string]any, len(alts))
	for i, a := range alts {
		entry := map[string]any{
			"tool":     a.Tool,
			"check_id": a.CheckID,
			"coverage": string(a.Coverage),
		}
		if a.Note != "" {
			entry["note"] = a.Note
		}
		out[i] = entry
	}
	return out
}

// buildRuleTags creates the tags array for a SARIF rule's properties.
func buildRuleTags(f *remediation.Finding) []string {
	var tags []string
	if f.ControlSeverity.IsSet() {
		tags = append(tags, "severity:"+f.SeverityLabel())
	}
	if f.HasExposure() {
		tags = append(tags, "domain:"+f.ExposureType())
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
