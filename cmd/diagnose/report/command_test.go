package report

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sufield/stave/internal/domain/evaluation"
	"github.com/sufield/stave/internal/domain/evaluation/remediation"
	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/domain/policy"
	reportrender "github.com/sufield/stave/internal/report"
	"github.com/sufield/stave/internal/safetyenvelope"
)

func sampleEvaluation() safetyenvelope.Evaluation {
	now := time.Date(2026, 2, 1, 10, 0, 0, 0, time.UTC)
	first := now.Add(-48 * time.Hour)
	last := now.Add(-2 * time.Hour)
	return safetyenvelope.Evaluation{
		SchemaVersion: "out.v0.1",
		Kind:          safetyenvelope.KindEvaluation,
		Run:           evaluation.RunInfo{Now: now, MaxUnsafe: kernel.Duration(24 * time.Hour), Snapshots: 2, Offline: true},
		Summary:       evaluation.Summary{AssetsEvaluated: 10, AttackSurface: 2, Violations: 2},
		Findings: []remediation.Finding{
			{
				Finding: evaluation.Finding{
					ControlID:       "CTL.S3.PUBLIC.002",
					AssetID:         "bucket-b",
					AssetType:       "bucket",
					AssetVendor:     "aws",
					ControlSeverity: policy.SeverityHigh,
					Evidence:        evaluation.Evidence{UnsafeDurationHours: 30, ThresholdHours: 24, FirstUnsafeAt: first, LastSeenUnsafeAt: last},
				},
				RemediationSpec: policy.RemediationSpec{Description: "d", Action: "a"},
			},
			{
				Finding: evaluation.Finding{
					ControlID:       "CTL.S3.PUBLIC.001",
					AssetID:         "bucket-a",
					AssetType:       "bucket",
					AssetVendor:     "aws",
					ControlSeverity: policy.SeverityCritical,
					Evidence:        evaluation.Evidence{UnsafeDurationHours: 72, ThresholdHours: 24, FirstUnsafeAt: first, LastSeenUnsafeAt: last},
				},
				RemediationSpec: policy.RemediationSpec{Description: "d2", Action: "a2"},
			},
		},
		Extensions: &evaluation.Extensions{
			ContextName: "prod-aws",
			Git: &evaluation.GitMetadata{
				RepoRoot: "/repo",
				Head:     "abc123def456",
				Dirty:    true,
				Modified: []string{"controls/CTL.S3.PUBLIC.901.yaml", "stave.yaml"},
			},
		},
	}
}

func TestOutputReportTextDefaultTemplate(t *testing.T) {
	eval := sampleEvaluation()
	var buf bytes.Buffer
	if err := reportrender.RenderText(eval, "test-version", defaultReportTemplate, "", &buf, false); err != nil {
		t.Fatalf("render template: %v", err)
	}
	out := buf.String()

	if !strings.Contains(out, "context: prod-aws") {
		t.Fatalf("missing context in report: %s", out)
	}
	if !strings.Contains(out, "git_head_commit: abc123def456") {
		t.Fatalf("missing git commit in report: %s", out)
	}
	if !strings.Contains(out, "git_dirty: true") {
		t.Fatalf("missing git dirty state in report: %s", out)
	}
	if strings.Index(out, "CTL.S3.PUBLIC.001") > strings.Index(out, "CTL.S3.PUBLIC.002") {
		t.Fatalf("findings not sorted by severity/control/resource: %s", out)
	}
}

func TestOutputReportTextCustomTemplate(t *testing.T) {
	eval := sampleEvaluation()

	customTpl := `violations={{ .Summary.Violations }}
{{range .Findings}}{{ .ControlID }}{{ "\n" }}{{end}}`
	var buf bytes.Buffer
	if err := reportrender.RenderText(eval, "test-version", customTpl, "", &buf, false); err != nil {
		t.Fatalf("render custom template: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "violations=2") || !strings.Contains(out, "CTL.S3.PUBLIC.001") {
		t.Fatalf("unexpected custom output: %s", out)
	}
}

func TestOutputReportTextInvalidTemplate(t *testing.T) {
	dir := t.TempDir()
	tpl := filepath.Join(dir, "bad.tmpl")
	if err := os.WriteFile(tpl, []byte(`{{ if }}`), 0o644); err != nil {
		t.Fatalf("write bad template: %v", err)
	}

	eval := sampleEvaluation()
	err := reportrender.RenderText(eval, "test-version", defaultReportTemplate, tpl, &bytes.Buffer{}, false)
	if err == nil {
		t.Fatal("expected template parse error")
	}
	if !strings.Contains(err.Error(), "render report template") {
		t.Fatalf("unexpected error: %v", err)
	}
}
