package text

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/sufield/stave/internal/domain/kernel"

	"github.com/sufield/stave/internal/domain/asset"

	"github.com/sufield/stave/internal/domain/evaluation"
	"github.com/sufield/stave/internal/domain/evaluation/remediation"
	"github.com/sufield/stave/internal/sanitize"
)

func TestFindingWriter_NoViolations(t *testing.T) {
	w := NewFindingWriter(remediation.NewMapper(), nil)
	result := evaluation.Result{
		Run: evaluation.RunInfo{
			ToolVersion: "test",
			Offline:     true,
			Now:         time.Date(2026, 2, 1, 12, 0, 0, 0, time.UTC),
			MaxUnsafe:   kernel.Duration(24 * time.Hour),
			Snapshots:   2,
		},
		Summary: evaluation.Summary{
			AssetsEvaluated: 2,
			AttackSurface:   0,
			Violations:      0,
		},
	}

	var buf bytes.Buffer
	if err := w.WriteFindings(&buf, result); err != nil {
		t.Fatalf("WriteFindings() error = %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "No violations found.") {
		t.Fatalf("expected no-violations message, got:\n%s", out)
	}
	if !strings.Contains(out, "run `stave verify`") {
		t.Fatalf("expected verify next-step hint, got:\n%s", out)
	}
}

func TestFindingWriter_ViolationsWithSections(t *testing.T) {
	w := NewFindingWriter(remediation.NewMapper(), sanitize.New())
	now := time.Date(2026, 2, 1, 12, 0, 0, 0, time.UTC)
	result := evaluation.Result{
		Run: evaluation.RunInfo{
			ToolVersion: "test",
			Offline:     true,
			Now:         now,
			MaxUnsafe:   kernel.Duration(24 * time.Hour),
			Snapshots:   3,
		},
		Summary: evaluation.Summary{
			AssetsEvaluated: 3,
			AttackSurface:   1,
			Violations:      2,
		},
		Findings: []evaluation.Finding{
			{
				ControlID:          "CTL.S3.PUBLIC.001",
				ControlName:        "No Public Bucket Access",
				ControlDescription: "Bucket must not be public",
				AssetID:            "res-secret",
				AssetType:          kernel.TypeStorageBucket,
				AssetVendor:        kernel.VendorAWS,
				Source:             &asset.SourceRef{File: "/tmp/infra/main.tf", Line: 42},
				Evidence: evaluation.Evidence{
					FirstUnsafeAt:       now.Add(-48 * time.Hour),
					LastSeenUnsafeAt:    now.Add(-1 * time.Hour),
					UnsafeDurationHours: 47,
					ThresholdHours:      24,
					EpisodeCount:        3,
					WindowDays:          30,
					RecurrenceLimit:     2,
					WhyNow:              "Threshold exceeded",
				},
			},
			{
				ControlID:          "CTL.S3.PUBLIC.002",
				ControlName:        "No Public Bucket Listing",
				ControlDescription: "Bucket list must not be public",
				AssetID:            "res-secret",
				AssetType:          kernel.TypeStorageBucket,
				AssetVendor:        kernel.VendorAWS,
				Evidence:           evaluation.Evidence{},
			},
		},
		Skipped: []evaluation.SkippedControl{
			{ControlID: "CTL.SKIP.001", ControlName: "Skipped", Reason: "missing resource type"},
		},
		SkippedAssets: []asset.SkippedAsset{
			{ID: "skip-secret", Pattern: "*", Reason: "scoped out"},
		},
		SuppressedFindings: []evaluation.SuppressedFinding{
			{ControlID: "CTL.SUP.001", AssetID: "supp-res", Reason: "approved", Expires: "2027-01-01"},
		},
	}

	var buf bytes.Buffer
	if err := w.WriteFindings(&buf, result); err != nil {
		t.Fatalf("WriteFindings() error = %v", err)
	}
	out := buf.String()

	contains := []string{
		"Evaluation Results",
		"Violations",
		"Remediation Groups",
		"Skipped Controls: 1",
		"Skipped Assets: 1",
		"Suppressed Findings: 1",
		"run `stave diagnose --controls <dir> --observations <dir>`",
	}
	for _, want := range contains {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in output:\n%s", want, out)
		}
	}

	if strings.Contains(out, "res-secret") {
		t.Fatalf("expected resource ID to be sanitized, got:\n%s", out)
	}
	if strings.Contains(out, "skip-secret") {
		t.Fatalf("expected skipped resource ID to be sanitized, got:\n%s", out)
	}
}

func TestFindingWriter_ViolationDomainSummary(t *testing.T) {
	w := NewFindingWriter(remediation.NewMapper(), nil)
	now := time.Date(2026, 2, 1, 12, 0, 0, 0, time.UTC)

	result := evaluation.Result{
		Run: evaluation.RunInfo{
			ToolVersion: "test",
			Offline:     true,
			Now:         now,
			MaxUnsafe:   kernel.Duration(24 * time.Hour),
			Snapshots:   2,
		},
		Summary: evaluation.Summary{
			AssetsEvaluated: 2,
			AttackSurface:   2,
			Violations:      2,
		},
		Findings: []evaluation.Finding{
			{
				ControlID:          "CTL.S3.PUBLIC.001",
				ControlName:        "No Public Bucket Access",
				ControlDescription: "Bucket must not be public",
				AssetID:            "res-1",
				AssetType:          kernel.TypeStorageBucket,
				AssetVendor:        kernel.VendorAWS,
			},
			{
				ControlID:          "CTL.UNKNOWN.001",
				ControlName:        "Unknown Domain Rule",
				ControlDescription: "Test unknown domain fallback",
				AssetID:            "res-2",
				AssetType:          kernel.AssetType(""),
				AssetVendor:        kernel.VendorAWS,
			},
		},
		Rows: []evaluation.Row{
			{
				ControlID:   "CTL.S3.PUBLIC.001",
				AssetID:     "res-1",
				AssetType:   kernel.TypeStorageBucket,
				AssetDomain: "aws_s3",
				Decision:    evaluation.DecisionViolation,
			},
			{
				ControlID:   "CTL.UNKNOWN.001",
				AssetID:     "res-2",
				AssetType:   kernel.AssetType(""),
				AssetDomain: "",
				Decision:    evaluation.DecisionViolation,
			},
		},
	}

	var buf bytes.Buffer
	if err := w.WriteFindings(&buf, result); err != nil {
		t.Fatalf("WriteFindings() error = %v", err)
	}

	out := buf.String()
	for _, want := range []string{"By domain:", "- aws_s3: 1", "- unknown: 1"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in output:\n%s", want, out)
		}
	}
}
