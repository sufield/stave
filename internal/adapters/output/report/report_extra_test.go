package report

import (
	"bytes"
	"io"
	"strings"
	"testing"
	"time"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/safetyenvelope"
)

func TestToReportFinding(t *testing.T) {
	f := remediation.Finding{
		Finding: evaluation.Finding{
			ControlID:       "CTL.S3.PUBLIC.001",
			AssetID:         "bucket-1",
			AssetType:       "storage_bucket",
			ControlSeverity: policy.SeverityHigh,
			Evidence: evaluation.Evidence{
				UnsafeDurationHours: 48.0,
				ThresholdHours:      24.0,
				FirstUnsafeAt:       time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
				LastSeenUnsafeAt:    time.Date(2026, 1, 3, 0, 0, 0, 0, time.UTC),
			},
		},
	}
	rf := toReportFinding(f)
	if rf.ControlID != "CTL.S3.PUBLIC.001" {
		t.Fatalf("ControlID = %q", rf.ControlID)
	}
	if rf.Severity != "high" {
		t.Fatalf("Severity = %q", rf.Severity)
	}
	if rf.DurationH != 48.0 {
		t.Fatalf("DurationH = %f", rf.DurationH)
	}
	if rf.FirstUnsafe == "" {
		t.Fatal("FirstUnsafe should not be empty")
	}
}

func TestToReportRemediation(t *testing.T) {
	f := remediation.Finding{
		Finding: evaluation.Finding{
			ControlID: "CTL.S3.PUBLIC.001",
			AssetID:   "bucket-1",
		},
		RemediationSpec: policy.RemediationSpec{
			Description: "desc",
			Action:      "action",
			Example:     "example",
		},
	}
	r := toReportRemediation(f)
	if r.ControlID != "CTL.S3.PUBLIC.001" {
		t.Fatalf("ControlID = %q", r.ControlID)
	}
	if r.Description != "desc" {
		t.Fatalf("Description = %q", r.Description)
	}
}

func TestSortReportFindings(t *testing.T) {
	findings := []reportFinding{
		{ControlID: "CTL.B", AssetID: "b", sevRank: 2},
		{ControlID: "CTL.A", AssetID: "a", sevRank: 0},
		{ControlID: "CTL.A", AssetID: "b", sevRank: 0},
	}
	sortReportFindings(findings)
	if findings[0].ControlID != "CTL.A" || findings[0].AssetID != "a" {
		t.Fatalf("[0] = %s@%s", findings[0].ControlID, findings[0].AssetID)
	}
	if findings[2].sevRank != 2 {
		t.Fatalf("[2].sevRank = %d", findings[2].sevRank)
	}
}

func TestEnsureComplianceEntry(t *testing.T) {
	data := make(map[string]*reportComplianceEntry)
	entry := ensureComplianceEntry(data, "soc2")
	if entry == nil {
		t.Fatal("expected non-nil entry")
	}
	// Same framework returns same entry
	entry2 := ensureComplianceEntry(data, "soc2")
	if entry2 != entry {
		t.Fatal("expected same entry")
	}
}

func TestUpdateComplianceData(t *testing.T) {
	data := make(map[string]*reportComplianceEntry)
	compliance := map[string]string{"soc2": "CC6.1", "hipaa": "164.312"}
	updateComplianceData(data, compliance, "high")
	if len(data) != 2 {
		t.Fatalf("len = %d", len(data))
	}
	if data["soc2"].TotalFindings != 1 {
		t.Fatalf("soc2 findings = %d", data["soc2"].TotalFindings)
	}
}

func TestFinalizeReportComplianceSummary_Empty(t *testing.T) {
	out := &reportOutput{}
	finalizeReportComplianceSummary(out, map[string]*reportComplianceEntry{})
	if out.ComplianceSummary != nil {
		t.Fatal("expected nil for empty compliance data")
	}
}

func TestFinalizeReportComplianceSummary_WithData(t *testing.T) {
	out := &reportOutput{}
	data := map[string]*reportComplianceEntry{
		"soc2": {
			TotalFindings:      2,
			FindingsBySeverity: map[string]int{"high": 2},
			controlSet:         map[string]struct{}{"CC6.1": {}, "CC7.1": {}},
		},
	}
	finalizeReportComplianceSummary(out, data)
	if out.ComplianceSummary == nil {
		t.Fatal("expected non-nil compliance summary")
	}
	entry := out.ComplianceSummary["soc2"]
	if len(entry.Controls) != 2 {
		t.Fatalf("Controls len = %d", len(entry.Controls))
	}
	// Should be sorted
	if entry.Controls[0] != "CC6.1" {
		t.Fatalf("Controls[0] = %q", entry.Controls[0])
	}
}

func TestTplGroupBySeverity(t *testing.T) {
	findings := []reportFinding{
		{sevRank: 0}, // critical
		{sevRank: 0}, // critical
		{sevRank: 2}, // medium
	}
	groups := tplGroupBySeverity(findings)
	if len(groups) != 2 {
		t.Fatalf("groups = %d", len(groups))
	}
	if groups[0].Severity != "critical" || groups[0].Count != 2 {
		t.Fatalf("[0] = %+v", groups[0])
	}
}

func TestTplGroupBySeverity_OutOfRange(t *testing.T) {
	findings := []reportFinding{
		{sevRank: 99}, // out of range -> clamped to "unspecified"
	}
	groups := tplGroupBySeverity(findings)
	if len(groups) != 1 || groups[0].Severity != "unspecified" {
		t.Fatalf("groups = %+v", groups)
	}
}

func TestExtractTemplateMetadata_NilExtensions(t *testing.T) {
	run := reportRun{Snapshots: 5}
	meta := extractTemplateMetadata(run, nil)
	if meta.Snapshots != 5 {
		t.Fatalf("Snapshots = %d", meta.Snapshots)
	}
	if meta.ContextName != "" {
		t.Fatal("expected empty ContextName")
	}
}

func TestExtractTemplateMetadata_WithGit(t *testing.T) {
	run := reportRun{}
	ext := &evaluation.Extensions{
		ContextName: "test-ctx",
		Git: &evaluation.GitMetadata{
			RepoRoot: "/repo",
			Head:     "abc123",
			Dirty:    true,
			Modified: []string{"file.go"},
		},
	}
	meta := extractTemplateMetadata(run, ext)
	if meta.ContextName != "test-ctx" {
		t.Fatalf("ContextName = %q", meta.ContextName)
	}
	if meta.GitHeadCommit != "abc123" {
		t.Fatalf("GitHeadCommit = %q", meta.GitHeadCommit)
	}
	if !meta.GitDirty {
		t.Fatal("expected GitDirty")
	}
	if meta.GitPathsDirty != "file.go" {
		t.Fatalf("GitPathsDirty = %q", meta.GitPathsDirty)
	}
}

func TestRenderJSON_Quiet(t *testing.T) {
	eval := safetyenvelope.Evaluation{
		Run: evaluation.RunInfo{
			Now:               time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
			MaxUnsafeDuration: kernel.Duration(24 * time.Hour),
		},
	}
	// Quiet mode: caller passes io.Discard.
	err := RenderJSON(eval, "v1.0.0", io.Discard)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
}

func TestRenderJSON_NotQuiet(t *testing.T) {
	eval := safetyenvelope.Evaluation{
		Run: evaluation.RunInfo{
			Now:               time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
			MaxUnsafeDuration: kernel.Duration(24 * time.Hour),
		},
	}
	var buf bytes.Buffer
	err := RenderJSON(eval, "v1.0.0", &buf)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "generated_at") {
		t.Fatal("missing generated_at in JSON output")
	}
	if !strings.Contains(out, "v1.0.0") {
		t.Fatal("missing tool version")
	}
}
