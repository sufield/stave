package securityaudit

import (
	"slices"
	"sort"
	"time"

	"github.com/sufield/stave/internal/app/securityaudit/evidence"
	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/domain/securityaudit"
)

func assembleReport(req SecurityAuditRequest, findings []securityaudit.Finding, ev evidence.Bundle, artifacts securityaudit.ArtifactManifest) securityaudit.Report {
	report := securityaudit.Report{
		SchemaVersion: kernel.SchemaSecurityAudit,
		GeneratedAt:   req.Now.UTC().Format(time.RFC3339),
		ToolVersion:   req.ToolVersion,
		Summary: securityaudit.Summary{
			BySeverity:        map[securityaudit.Severity]int{},
			FailOn:            req.FailOn,
			VulnSourceUsed:    ev.Vuln.SourceUsed,
			EvidenceFreshness: ev.Vuln.Freshness,
		},
		Findings: findings,
	}

	for i := range report.Findings {
		refs := ev.Crosswalk.ByCheck[report.Findings[i].ID]
		report.Findings[i].ControlRefs = slices.Clone(refs)
	}

	report.EvidenceIndex = make([]securityaudit.EvidenceRef, 0, len(artifacts.Files))
	for _, file := range artifacts.Files {
		report.EvidenceIndex = append(report.EvidenceIndex, securityaudit.EvidenceRef{
			ID:     file.Path,
			Path:   file.Path,
			SHA256: file.SHA256,
		})
	}

	for i := range report.Findings {
		report.Findings[i].EvidenceRefs = mapEvidenceRefs(report.Findings[i].ID)
	}

	report.Normalize()
	report = report.FilterBySeverity(req.SeverityFilter)
	report.Controls = collectUniqueControls(report.Findings)
	report.Summary.FailOn = req.FailOn
	report.RecomputeSummary()
	report.Summary.VulnSourceUsed = ev.Vuln.SourceUsed
	report.Summary.EvidenceFreshness = ev.Vuln.Freshness
	report.Normalize()

	return report
}

func collectUniqueControls(findings []securityaudit.Finding) []securityaudit.ControlRef {
	set := map[string]securityaudit.ControlRef{}
	for _, finding := range findings {
		for _, ref := range finding.ControlRefs {
			key := ref.Framework + "|" + ref.ControlID + "|" + ref.Rationale
			set[key] = ref
		}
	}
	out := make([]securityaudit.ControlRef, 0, len(set))
	for _, ref := range set {
		out = append(out, ref)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Framework != out[j].Framework {
			return out[i].Framework < out[j].Framework
		}
		if out[i].ControlID != out[j].ControlID {
			return out[i].ControlID < out[j].ControlID
		}
		return out[i].Rationale < out[j].Rationale
	})
	return out
}
