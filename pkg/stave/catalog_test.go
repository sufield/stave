package stave

import (
	"bytes"
	"strings"
	"testing"

	appcaps "github.com/sufield/stave/internal/app/capabilities"
	policy "github.com/sufield/stave/internal/core/controldef"
)

// These exercise the catalog view renderers that moved here from
// cmd/catalog. End-to-end coverage that loads catalogs from disk lives in
// the txtar suite.

func catalogSampleReport(mode catalogViewMode) catalogReport {
	return catalogReport{
		summary: appcaps.Summary{
			Controls: 10, Services: 2, Chains: 3, Operational: 4,
			SeverityHist: map[policy.Severity]int{policy.SeverityCritical: 5, policy.SeverityHigh: 5},
		},
		services: []appcaps.ServiceRow{
			{Service: "iam", Caps: 1, Controls: 4, MaxSev: policy.SeverityHigh,
				Sev: map[policy.Severity]int{policy.SeverityHigh: 4}},
			{Service: "s3", Caps: 2, Controls: 6, MaxSev: policy.SeverityCritical,
				Sev: map[policy.Severity]int{policy.SeverityCritical: 5, policy.SeverityHigh: 1}},
		},
		mode: mode,
	}
}

func catalogRender(t *testing.T, rep catalogReport) string {
	t.Helper()
	var buf bytes.Buffer
	if err := renderCatalogView(&buf, rep); err != nil {
		t.Fatalf("renderCatalogView: %v", err)
	}
	return buf.String()
}

func TestCatalogSummaryView_HeaderAndPerServiceRows(t *testing.T) {
	out := catalogRender(t, catalogSampleReport(catalogViewSummary))
	for _, want := range []string{
		"Stave: 10 controls · 2 services · 3 chains · 4 operational",
		"5 CRITICAL", "5 HIGH",
		"control groups only; 3 chains, 4 operational not rated",
		"SERVICE", "MAX SEVERITY", "IAM", "S3",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("summary view missing %q\n---\n%s", want, out)
		}
	}
	if strings.Contains(out, "SEVERITIES") {
		t.Errorf("non-wide summary should not show SEVERITIES column:\n%s", out)
	}
}

func TestCatalogSummaryView_WideAddsSeverityColumn(t *testing.T) {
	rep := catalogSampleReport(catalogViewSummary)
	rep.wide = true
	out := catalogRender(t, rep)
	if !strings.Contains(out, "SEVERITIES") {
		t.Errorf("wide summary should show SEVERITIES column:\n%s", out)
	}
	if !strings.Contains(out, "crit:5") || !strings.Contains(out, "high:4") {
		t.Errorf("wide summary should show per-service breakdown:\n%s", out)
	}
}

func TestCatalogLeafView_SeverityFilterShowsHonestyNote(t *testing.T) {
	rep := catalogReport{
		mode:       catalogViewLeaf,
		sevFilter:  "critical",
		serviceArg: "s3",
		leafs: []appcaps.LeafControl{
			{ID: "CTL.S3.PUBLIC.002", Name: "No Public Read", Service: "s3", Category: "public", Severity: policy.SeverityCritical},
		},
	}
	out := catalogRender(t, rep)
	for _, want := range []string{
		"Leaf controls — S3, severity CRITICAL (1)",
		"chains and operational features are not severity-rated and are excluded",
		"CTL.S3.PUBLIC.002",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("leaf view missing %q\n---\n%s", want, out)
		}
	}
}

func TestCatalogLeafView_NoSeverityFilterOmitsNote(t *testing.T) {
	rep := catalogReport{
		mode: catalogViewLeaf, serviceArg: "s3",
		leafs: []appcaps.LeafControl{{ID: "CTL.S3.ACL.001", Severity: policy.SeverityHigh}},
	}
	out := catalogRender(t, rep)
	if strings.Contains(out, "not severity-rated") {
		t.Errorf("leaf view without --severity must not print the severity-exclusion note:\n%s", out)
	}
}

func TestCatalogLeafView_CategoryInHeading(t *testing.T) {
	rep := catalogReport{
		mode: catalogViewLeaf, serviceArg: "s3", categoryArg: "public",
		leafs: []appcaps.LeafControl{{ID: "CTL.S3.PUBLIC.002", Service: "s3", Category: "public", Severity: policy.SeverityCritical}},
	}
	out := catalogRender(t, rep)
	if !strings.Contains(out, "S3/public") {
		t.Errorf("leaf heading should reflect the --category filter (S3/public):\n%s", out)
	}
}

func TestCatalogKindView_ServiceFilterEmitsHonestyNote(t *testing.T) {
	rep := catalogReport{mode: catalogViewKind, serviceArg: "s3", Capabilities: nil}
	out := catalogRender(t, rep)
	if !strings.Contains(out, "not service-scoped") {
		t.Errorf("kind view with a service filter must explain the empty result:\n%s", out)
	}
	plain := catalogRender(t, catalogReport{mode: catalogViewKind})
	if strings.Contains(plain, "not service-scoped") {
		t.Errorf("unfiltered kind view must not print the service-scope note:\n%s", plain)
	}
}
