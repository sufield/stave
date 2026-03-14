package text

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/sufield/stave/internal/domain/evaluation"
	"github.com/sufield/stave/internal/domain/kernel"
)

const sectionWidth = 72

// WriteFindingDetail writes a human-readable diagnosis for a single finding.
func WriteFindingDetail(w io.Writer, detail *evaluation.FindingDetail) error {
	d := &drawer{w: w}

	writeFindingDetailHeader(d, detail)
	writeMetadataLine(d, detail)
	writeControlSection(d, detail)
	writeResourceSection(d, detail)
	writeEvidenceSection(d, &detail.Evidence)
	if detail.Trace != nil {
		writeTraceSection(d, detail.Trace)
	}
	writeRemediationSection(d, detail)
	writeNextStepsSection(d, detail.NextSteps)

	return d.err
}

func writeFindingDetailHeader(d *drawer, detail *evaluation.FindingDetail) {
	d.f("Diagnosis for Violation: %s on %s\n", detail.Control.ID, detail.Asset.ID)
	d.f("%s\n", strings.Repeat("-", sectionWidth))
}

func writeMetadataLine(d *drawer, detail *evaluation.FindingDetail) {
	var parts []string
	if detail.Control.Severity != 0 {
		parts = append(parts, "Severity: "+titleCase(detail.Control.Severity.String()))
	}
	if len(detail.Control.Compliance) > 0 {
		var refs []string
		for framework, ref := range detail.Control.Compliance {
			refs = append(refs, framework+" "+ref)
		}
		parts = append(parts, "Compliance: "+strings.Join(refs, ", "))
	}
	if len(parts) > 0 {
		d.f("%s\n", strings.Join(parts, "   "))
	}
}

func writeControlSection(d *drawer, detail *evaluation.FindingDetail) {
	d.f("\nControl (%s): %s\n", detail.Control.ID, detail.Control.Name)
	writeField(d, "Description", detail.Control.Description)
	writeField(d, "Type", detail.Control.Type)
	writeField(d, "Domain", detail.Control.Domain)

	if detail.Control.Exposure != nil {
		d.f("  Exposure: %s (scope: %s)\n",
			detail.Control.Exposure.Type,
			detail.Control.Exposure.PrincipalScope.String())
	}
	if detail.PostureDrift != nil {
		d.f("  Posture drift: %s (%d episode(s))\n",
			detail.PostureDrift.Pattern,
			detail.PostureDrift.EpisodeCount)
	}
}

func writeResourceSection(d *drawer, detail *evaluation.FindingDetail) {
	d.f("\nAsset: %s (Type: %s", detail.Asset.ID, detail.Asset.Type)
	if detail.Asset.Vendor != "" {
		d.f(", Vendor: %s", detail.Asset.Vendor)
	}
	d.ln(")")

	if !detail.Asset.ObservedAt.IsZero() {
		d.f("  Observed at: %s\n", detail.Asset.ObservedAt.Format(time.RFC3339))
	}
}

func writeEvidenceSection(d *drawer, ev *evaluation.Evidence) {
	writeSectionHeader(d, "Evidence")
	writeEvidenceTimeline(d, ev)
	writeEvidenceMisconfigurations(d, ev)
	writeEvidenceSourceDetails(d, ev)
}

func writeEvidenceTimeline(d *drawer, ev *evaluation.Evidence) {
	writeOptionalTimeField(d, "  First unsafe at:    %s\n", ev.FirstUnsafeAt)
	writeOptionalTimeField(d, "  Last seen unsafe:   %s\n", ev.LastSeenUnsafeAt)
	writeOptionalFloatField(d, "  Unsafe duration:    %.1fh\n", ev.UnsafeDurationHours)
	writeOptionalFloatField(d, "  Threshold:          %.1fh\n", ev.ThresholdHours)
	writeOptionalStringField(d, "  Why now:            %s\n", ev.WhyNow)
}

func writeOptionalTimeField(d *drawer, format string, value time.Time) {
	if value.IsZero() {
		return
	}
	d.f(format, value.Format(time.RFC3339))
}

func writeOptionalFloatField(d *drawer, format string, value float64) {
	if value <= 0 {
		return
	}
	d.f(format, value)
}

func writeOptionalStringField(d *drawer, format, value string) {
	if value == "" {
		return
	}
	d.f(format, value)
}

func writeEvidenceMisconfigurations(d *drawer, ev *evaluation.Evidence) {
	if len(ev.Misconfigurations) > 0 {
		d.ln("  Misconfigurations:")
		for _, mc := range ev.Misconfigurations {
			d.f("    - %s\n", mc.String())
		}
	}
	if len(ev.RootCauses) > 0 {
		d.f("  Root causes:        %s\n", strings.Join(ev.RootCauseStrings(), ", "))
	}
}

func writeEvidenceSourceDetails(d *drawer, ev *evaluation.Evidence) {
	if ev.SourceEvidence == nil {
		return
	}
	if len(ev.SourceEvidence.IdentityStatements) > 0 {
		d.f("  Identity statements: %s\n", strings.Join(kernel.StringsFrom(ev.SourceEvidence.IdentityStatements), ", "))
	}
	if len(ev.SourceEvidence.ResourceGrantees) > 0 {
		d.f("  Resource grantees:  %s\n", strings.Join(kernel.StringsFrom(ev.SourceEvidence.ResourceGrantees), ", "))
	}
}

func writeTraceSection(d *drawer, ft *evaluation.FindingTrace) {
	writeSectionHeader(d, "Predicate Evaluation Trace")
	if d.err != nil {
		return
	}

	if ft.Raw == nil {
		d.ln("  (trace data unavailable)")
		return
	}

	d.setErr(ft.Raw.RenderText(d.w))
}

func writeRemediationSection(d *drawer, detail *evaluation.FindingDetail) {
	if detail.Remediation == nil {
		return
	}

	writeSectionHeader(d, "Remediation Guidance")
	writeField(d, "", detail.Remediation.Description)
	if detail.Remediation.Action != "" {
		d.f("\n  Action: %s\n", strings.TrimSpace(detail.Remediation.Action))
	}
	writeRemediationExample(d, detail.Remediation.Example)
	writeRemediationPlan(d, detail.RemediationPlan)
}

func writeRemediationExample(d *drawer, example string) {
	if example == "" {
		return
	}
	d.f("\n  Example configuration:\n")
	for line := range strings.SplitSeq(strings.TrimSpace(example), "\n") {
		d.f("    %s\n", line)
	}
}

func writeRemediationPlan(d *drawer, plan *evaluation.RemediationPlan) {
	if plan == nil {
		return
	}
	d.f("\n  Fix plan (%s):\n", plan.ID)
	writeRemediationPreconditions(d, plan.Preconditions)
	writeRemediationActions(d, plan.Actions)
	if plan.ExpectedEffect != "" {
		d.f("    Expected effect: %s\n", plan.ExpectedEffect)
	}
}

func writeRemediationPreconditions(d *drawer, preconditions []string) {
	if len(preconditions) == 0 {
		return
	}
	d.ln("    Preconditions:")
	for _, p := range preconditions {
		d.f("      - %s\n", p)
	}
}

func writeRemediationActions(d *drawer, actions []evaluation.RemediationAction) {
	if len(actions) == 0 {
		return
	}
	d.ln("    Actions:")
	for _, a := range actions {
		d.f("      - %s %s = %v\n", a.ActionType, a.Path, a.Value)
	}
}

func writeNextStepsSection(d *drawer, nextSteps []string) {
	if len(nextSteps) == 0 {
		return
	}
	writeSectionHeader(d, "Next Steps")
	for i, step := range nextSteps {
		d.f("  %d. %s\n", i+1, step)
	}
}

func writeSectionHeader(d *drawer, title string) {
	d.f("\n%s\n%s\n", title, strings.Repeat("-", sectionWidth))
}

func writeField(d *drawer, label, value string) {
	value = strings.TrimSpace(value)
	if value == "" {
		return
	}
	if strings.TrimSpace(label) == "" {
		d.f("  %s\n", value)
		return
	}
	d.f("  %s: %s\n", label, value)
}

func titleCase(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

type drawer struct {
	w   io.Writer
	err error
}

func (d *drawer) f(format string, args ...any) {
	if d.err != nil {
		return
	}
	_, d.err = fmt.Fprintf(d.w, format, args...)
}

func (d *drawer) ln(args ...any) {
	if d.err != nil {
		return
	}
	_, d.err = fmt.Fprintln(d.w, args...)
}

func (d *drawer) setErr(err error) {
	if d.err == nil {
		d.err = err
	}
}
