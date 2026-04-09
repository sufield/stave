package prompt

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/trace"
	"gopkg.in/yaml.v3"
)

//go:embed templates/prompt_default.tmpl
var DefaultTemplate string

// TraceStepData holds a single reasoning step from the logic trace.
type TraceStepData struct {
	Name   string
	Input  string
	Result string
}

// TraceData holds the logic trace assessment for a single finding.
type TraceData struct {
	Verdict    string
	Confidence string
	Steps      []TraceStepData
}

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
	Trace        *TraceData
}

// Data holds all data for the prompt rendering.
type Data struct {
	FindingCount    int
	AssetID         string
	Findings        []FindingData
	AssetProperties string
}

// Builder coordinates assembly of LLM-ready prompt data.
type Builder struct {
	AssetID          string
	ControlsByID     map[kernel.ControlID]*policy.ControlDefinition
	AssetPropsJSON   string
	TraceAssessments []trace.Assessment
}

// Build creates prompt data from matched findings.
func (b *Builder) Build(matched []evaluation.Finding) Data {
	findings := make([]FindingData, 0, len(matched))

	for i := range matched {
		v := &matched[i]
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
		fd.Trace = b.matchTrace(v.ControlID, v.AssetID)
		findings = append(findings, fd)
	}

	return Data{
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
		lines = append(lines, "- First unsafe: "+ev.FirstUnsafeAt.Format(time.RFC3339))
	}
	if !ev.LastSeenUnsafeAt.IsZero() {
		lines = append(lines, "- Last seen unsafe: "+ev.LastSeenUnsafeAt.Format(time.RFC3339))
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
	if ev.TemporalRisk != "" {
		lines = append(lines, "- Why now: "+ev.TemporalRisk)
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
	strs := make([]string, len(causes))
	for i, c := range causes {
		strs[i] = string(c)
	}
	return strings.Join(strs, ", ")
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

// matchTrace finds the trace assessment matching a control×asset pair and
// converts it to template-ready data.
func (b *Builder) matchTrace(ctlID kernel.ControlID, astID asset.ID) *TraceData {
	for i := range b.TraceAssessments {
		a := &b.TraceAssessments[i]
		if a.PolicyID == string(ctlID) && a.ResourceID == string(astID) {
			steps := make([]TraceStepData, len(a.Steps))
			for j := range a.Steps {
				steps[j] = TraceStepData{
					Name:   a.Steps[j].Name,
					Input:  compactJSON(a.Steps[j].Input),
					Result: compactJSON(a.Steps[j].Result),
				}
			}
			return &TraceData{
				Verdict:    a.Verdict,
				Confidence: a.Confidence,
				Steps:      steps,
			}
		}
	}
	return nil
}

func compactJSON(v any) string {
	if v == nil {
		return ""
	}
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprintf("%v", v)
	}
	return string(b)
}

// RenderPrompt builds the Markdown prompt by executing a Go text/template
// against the assembled data. Pass DefaultTemplate for the built-in prompt,
// or a custom template string for team-specific personas.
func RenderPrompt(data Data, tmpl string) (string, error) {
	var b bytes.Buffer
	if err := ui.ExecuteTemplate(&b, tmpl, data); err != nil {
		return "", fmt.Errorf("render prompt template: %w", err)
	}
	return b.String(), nil
}
