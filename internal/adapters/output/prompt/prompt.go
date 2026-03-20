package prompt

import (
	"bytes"
	"fmt"
	"strings"
	"time"

	"github.com/samber/lo"
	"github.com/sufield/stave/pkg/alpha/domain/asset"
	"github.com/sufield/stave/pkg/alpha/domain/evaluation"
	"github.com/sufield/stave/pkg/alpha/domain/kernel"
	"github.com/sufield/stave/pkg/alpha/domain/policy"
	"gopkg.in/yaml.v3"
)

// FindingData holds data for a single finding in the rendered prompt.
type FindingData struct {
	ControlID    kernel.ControlID
	ControlName  string
	Description  string
	AssetID      asset.ID
	AssetType    kernel.AssetType
	Evidence     string
	MatchedProps string
	RootCauses   string
	ControlYAML  string
	Guidance     string
}

// PromptData holds all data for the prompt rendering.
type PromptData struct {
	FindingCount    int
	AssetID         string
	Findings        []FindingData
	AssetProperties string
}

// PromptBuilder coordinates assembly of LLM-ready prompt data.
type PromptBuilder struct {
	AssetID        string
	ControlsByID   map[kernel.ControlID]*policy.ControlDefinition
	AssetPropsJSON string
}

// Build creates prompt data from matched findings.
func (b *PromptBuilder) Build(matched []evaluation.Finding) PromptData {
	findings := make([]FindingData, 0, len(matched))

	for _, v := range matched {
		fd := FindingData{
			ControlID:    v.ControlID,
			ControlName:  v.ControlName,
			Description:  v.ControlDescription,
			AssetID:      v.AssetID,
			AssetType:    v.AssetType,
			Evidence:     BuildEvidenceSummary(v.Evidence),
			MatchedProps: summarizeMisconfigurations(v.Evidence.Misconfigurations),
			RootCauses:   BuildRootCausesSummary(v.Evidence.RootCauses),
		}

		if ctl, ok := b.ControlsByID[v.ControlID]; ok {
			fd.ControlYAML = marshalControl(ctl)
			if ctl.Remediation != nil {
				remediation := policy.RemediationSpec{
					Description: ctl.Remediation.Description,
					Action:      ctl.Remediation.Action,
					Example:     ctl.Remediation.Example,
				}
				fd.Guidance = BuildGuidanceSummary(&remediation)
			}
		}
		findings = append(findings, fd)
	}

	return PromptData{
		FindingCount:    len(findings),
		AssetID:         b.AssetID,
		Findings:        findings,
		AssetProperties: b.AssetPropsJSON,
	}
}

func summarizeMisconfigurations(misconfigs []policy.Misconfiguration) string {
	if len(misconfigs) == 0 {
		return ""
	}
	var sb strings.Builder
	for _, mc := range misconfigs {
		sb.WriteString("- ")
		sb.WriteString(mc.String())
		sb.WriteString("\n")
	}
	return strings.TrimSpace(sb.String())
}

func marshalControl(ctl *policy.ControlDefinition) string {
	yamlBytes, err := yaml.Marshal(ctl)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(yamlBytes))
}

// BuildEvidenceSummary creates a human-readable summary of violation evidence.
func BuildEvidenceSummary(ev evaluation.Evidence) string {
	var lines []string

	if !ev.FirstUnsafeAt.IsZero() {
		lines = append(lines, fmt.Sprintf("- First unsafe: %s", ev.FirstUnsafeAt.Format(time.RFC3339)))
	}
	if !ev.LastSeenUnsafeAt.IsZero() {
		lines = append(lines, fmt.Sprintf("- Last seen unsafe: %s", ev.LastSeenUnsafeAt.Format(time.RFC3339)))
	}
	if ev.UnsafeDurationHours > 0 {
		lines = append(lines, fmt.Sprintf("- Unsafe duration: %.1f hours", ev.UnsafeDurationHours))
	}
	if ev.ThresholdHours > 0 {
		lines = append(lines, fmt.Sprintf("- Threshold: %.1f hours", ev.ThresholdHours))
	}
	if ev.EpisodeCount > 0 {
		lines = append(lines, fmt.Sprintf("- Episodes: %d", ev.EpisodeCount))
	}
	if ev.WindowDays > 0 {
		lines = append(lines, fmt.Sprintf("- Window: %d days", ev.WindowDays))
	}
	if ev.RecurrenceLimit > 0 {
		lines = append(lines, fmt.Sprintf("- Recurrence limit: %d", ev.RecurrenceLimit))
	}
	if ev.WhyNow != "" {
		lines = append(lines, fmt.Sprintf("- Why now: %s", ev.WhyNow))
	}

	if len(lines) == 0 {
		return "No evidence details available."
	}
	return strings.Join(lines, "\n")
}

// BuildRootCausesSummary creates a comma-separated root causes string.
func BuildRootCausesSummary(causes []evaluation.RootCause) string {
	if len(causes) == 0 {
		return ""
	}
	return strings.Join(lo.Map(causes, func(c evaluation.RootCause, _ int) string { return string(c) }), ", ")
}

// BuildGuidanceSummary creates readable action guidance from control metadata.
func BuildGuidanceSummary(m *policy.RemediationSpec) string {
	var parts []string
	if m.Description != "" {
		parts = append(parts, strings.TrimSpace(m.Description))
	}
	if m.Action != "" {
		parts = append(parts, "**Action:** "+strings.TrimSpace(m.Action))
	}
	if m.Example != "" {
		parts = append(parts, "**Example:**\n```\n"+strings.TrimSpace(m.Example)+"\n```")
	}
	return strings.Join(parts, "\n\n")
}

// RenderPrompt builds the Markdown prompt from assembled data.
func RenderPrompt(data PromptData) string {
	var b bytes.Buffer

	fmt.Fprintf(&b, "# Stave Finding Analysis\n\n")
	fmt.Fprintf(&b, "I am using **Stave**, an offline configuration safety evaluator, to detect infrastructure misconfigurations. ")
	fmt.Fprintf(&b, "Stave found **%d finding(s)** for asset `%s` that I need help analyzing and correcting.\n", data.FindingCount, data.AssetID)

	for _, f := range data.Findings {
		fmt.Fprintf(&b, "\n---\n\n")
		fmt.Fprintf(&b, "## Finding: %s\n\n", f.ControlID)
		fmt.Fprintf(&b, "| Field | Value |\n")
		fmt.Fprintf(&b, "|-------|-------|\n")
		fmt.Fprintf(&b, "| Control | %s |\n", f.ControlID)
		fmt.Fprintf(&b, "| Name | %s |\n", f.ControlName)
		fmt.Fprintf(&b, "| Description | %s |\n", strings.TrimSpace(f.Description))
		fmt.Fprintf(&b, "| Asset | %s |\n", f.AssetID)
		fmt.Fprintf(&b, "| Asset Type | %s |\n", f.AssetType)

		fmt.Fprintf(&b, "\n### Evidence\n\n%s\n", f.Evidence)

		if f.MatchedProps != "" {
			fmt.Fprintf(&b, "\n### Misconfigurations\n\n%s\n", f.MatchedProps)
		}

		if f.RootCauses != "" {
			fmt.Fprintf(&b, "\n### Root Causes\n\n%s\n", f.RootCauses)
		}

		if f.ControlYAML != "" {
			fmt.Fprintf(&b, "\n### Control Definition (YAML)\n\n```yaml\n%s\n```\n", f.ControlYAML)
		}

		if f.Guidance != "" {
			fmt.Fprintf(&b, "\n### Control Guidance\n\n%s\n", f.Guidance)
		}
	}

	if data.AssetProperties != "" {
		fmt.Fprintf(&b, "\n## Asset Properties (Latest Snapshot)\n\n```json\n%s\n```\n", data.AssetProperties)
	}

	fmt.Fprintf(&b, "\n## What I Need\n\n")
	fmt.Fprintf(&b, "Based on the findings above, please provide:\n\n")
	fmt.Fprintf(&b, "1. **Root cause analysis** — Why is this asset in an unsafe state?\n")
	fmt.Fprintf(&b, "2. **Corrective changes** — Specific, actionable changes to address each finding.\n")
	fmt.Fprintf(&b, "3. **Verification** — How to confirm the fix is applied correctly.\n")
	fmt.Fprintf(&b, "4. **Prevention** — What controls or automation would prevent recurrence?\n")

	return b.String()
}
