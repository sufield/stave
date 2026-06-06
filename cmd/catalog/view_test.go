package catalog

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/sufield/stave/internal/cli/ui"

	appcaps "github.com/sufield/stave/internal/app/capabilities"
	policy "github.com/sufield/stave/internal/core/controldef"
)

func sampleReport(mode viewMode) catalogReport {
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

func render(t *testing.T, r Renderer, rep catalogReport) string {
	t.Helper()
	var buf bytes.Buffer
	if err := r.Render(&buf, rep); err != nil {
		t.Fatalf("Render: %v", err)
	}
	return buf.String()
}

func TestSummaryView_HeaderAndPerServiceRows(t *testing.T) {
	out := render(t, TextRenderer{}, sampleReport(viewSummary))
	for _, want := range []string{
		"Stave: 10 controls · 2 services · 3 chains · 4 operational",
		"5 CRITICAL", "5 HIGH",
		"control groups only; 3 chains, 4 operational not rated",
		"SERVICE", "MAX SEVERITY",
		"IAM", "S3",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("summary view missing %q\n---\n%s", want, out)
		}
	}
	// Default (non-wide) summary must NOT carry the SEVERITIES column.
	if strings.Contains(out, "SEVERITIES") {
		t.Errorf("non-wide summary should not show SEVERITIES column:\n%s", out)
	}
}

func TestSummaryView_WideAddsSeverityColumn(t *testing.T) {
	out := render(t, WideRenderer{}, sampleReport(viewSummary))
	if !strings.Contains(out, "SEVERITIES") {
		t.Errorf("wide summary should show SEVERITIES column:\n%s", out)
	}
	if !strings.Contains(out, "crit:5") || !strings.Contains(out, "high:4") {
		t.Errorf("wide summary should show per-service breakdown:\n%s", out)
	}
}

func TestLeafView_SeverityFilterShowsHonestyNote(t *testing.T) {
	rep := catalogReport{
		mode:       viewLeaf,
		sevFilter:  "critical",
		serviceArg: "s3",
		leafs: []appcaps.LeafControl{
			{ID: "CTL.S3.PUBLIC.002", Name: "No Public Read", Service: "s3", Category: "public", Severity: policy.SeverityCritical},
		},
	}
	out := render(t, TextRenderer{}, rep)
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

func TestLeafView_NoSeverityFilterOmitsNote(t *testing.T) {
	rep := catalogReport{
		mode: viewLeaf, serviceArg: "s3",
		leafs: []appcaps.LeafControl{{ID: "CTL.S3.ACL.001", Severity: policy.SeverityHigh}},
	}
	out := render(t, TextRenderer{}, rep)
	if strings.Contains(out, "not severity-rated") {
		t.Errorf("leaf view without --severity must not print the severity-exclusion note:\n%s", out)
	}
}

func TestLeafView_CategoryInHeading(t *testing.T) {
	rep := catalogReport{
		mode: viewLeaf, serviceArg: "s3", categoryArg: "public",
		leafs: []appcaps.LeafControl{{ID: "CTL.S3.PUBLIC.002", Service: "s3", Category: "public", Severity: policy.SeverityCritical}},
	}
	out := render(t, TextRenderer{}, rep)
	if !strings.Contains(out, "S3/public") {
		t.Errorf("leaf heading should reflect the --category filter (S3/public):\n%s", out)
	}
}

// Fix 3: a service/category filter excludes all chains/operational (they are
// not service-scoped); the kind view must say so, not silently show "0".
func TestKindView_ServiceFilterEmitsHonestyNote(t *testing.T) {
	rep := catalogReport{mode: viewKind, serviceArg: "s3", Capabilities: nil}
	out := render(t, TextRenderer{}, rep)
	if !strings.Contains(out, "not service-scoped") {
		t.Errorf("kind view with a service filter must explain the empty result:\n%s", out)
	}
	// Without a service/category filter, no such note.
	plain := render(t, TextRenderer{}, catalogReport{mode: viewKind})
	if strings.Contains(plain, "not service-scoped") {
		t.Errorf("unfiltered kind view must not print the service-scope note:\n%s", plain)
	}
}

// Fix 1: a surplus positional argument is invalid input (exit 2), not an
// internal error (exit 4). The wrapped Args validator must return a
// *ui.UserError so the executor maps it to ExitInputError.
func TestArgs_SurplusPositionalIsUserError(t *testing.T) {
	cmd := NewCmd(Deps{}) // RunE is never reached: Args fails first
	cmd.SetArgs([]string{"s3", "iam"})
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected an error for two positional args")
	}
	var userErr *ui.UserError
	if !errors.As(err, &userErr) {
		t.Errorf("surplus-arg error must be *ui.UserError (-> exit 2), got %T: %v", err, err)
	}
}
