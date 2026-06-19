package text

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/kernel"

	"github.com/sufield/stave/internal/core/asset"

	appeval "github.com/sufield/stave/internal/app/eval"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/sanitize"
)

func TestFindingWriter_NoViolations(t *testing.T) {
	w := &FindingWriter{Verbose: true}
	enricher := remediation.NewPlanner()
	result := evaluation.ComplianceReport{
		Run: evaluation.RunInfo{
			StaveVersion:      "test",
			Offline:           true,
			Now:               time.Date(2026, 2, 1, 12, 0, 0, 0, time.UTC),
			MaxUnsafeDuration: kernel.Duration(24 * time.Hour),
			Snapshots:         2,
			EvaluatedState:    "deployed",
		},
		Summary: evaluation.ComplianceSummary{
			TotalAssets:      2,
			ExposedResources: 0,
			Violations:       0,
		},
	}

	enriched, err := appeval.Enrich(enricher, nil, &result)
	if err != nil {
		t.Fatal(err)
	}
	data, err := w.MarshalFindings(&enriched)
	if err != nil {
		t.Fatalf("MarshalFindings() error = %v", err)
	}

	var buf bytes.Buffer
	buf.Write(data)

	out := buf.String()
	if !strings.Contains(out, "No violations found.") {
		t.Fatalf("expected no-violations message, got:\n%s", out)
	}
	if !strings.Contains(out, "run `stave verify`") {
		t.Fatalf("expected verify next-step hint, got:\n%s", out)
	}
}

func TestFindingWriter_ViolationsWithSections(t *testing.T) {
	w := &FindingWriter{Verbose: true}
	enricher := remediation.NewPlanner()
	sanitizer := sanitize.New(sanitize.WithIDSanitization(true))
	now := time.Date(2026, 2, 1, 12, 0, 0, 0, time.UTC)
	result := evaluation.ComplianceReport{
		Run: evaluation.RunInfo{
			StaveVersion:      "test",
			Offline:           true,
			Now:               now,
			MaxUnsafeDuration: kernel.Duration(24 * time.Hour),
			Snapshots:         3,
			EvaluatedState:    "deployed",
		},
		Summary: evaluation.ComplianceSummary{
			TotalAssets:      3,
			ExposedResources: 1,
			Violations:       2,
		},
		Findings: []evaluation.Finding{
			{
				ControlID:          "CTL.S3.PUBLIC.001",
				ControlName:        "No Public Bucket Access",
				ControlDescription: "Bucket must not be public",
				AssetID:            "res-secret",
				AssetType:          kernel.AssetType("storage_bucket"),
				AssetVendor:        kernel.Vendor("aws"),
				Source:             &asset.SourceRef{File: "/tmp/infra/main.tf", Line: 42},
				Evidence: evaluation.Evidence{
					FirstUnsafeAt:       now.Add(-48 * time.Hour),
					LastSeenUnsafeAt:    now.Add(-1 * time.Hour),
					UnsafeDurationHours: 47,
					ThresholdHours:      24,
					ExposureWindowCount: 3,
					WindowDays:          30,
					RecurrenceThreshold: 2,
					TemporalRisk:        "Threshold exceeded",
				},
			},
			{
				ControlID:          "CTL.S3.PUBLIC.002",
				ControlName:        "No Public Bucket Listing",
				ControlDescription: "Bucket list must not be public",
				AssetID:            "res-secret",
				AssetType:          kernel.AssetType("storage_bucket"),
				AssetVendor:        kernel.Vendor("aws"),
				Evidence:           evaluation.Evidence{},
			},
		},
		SkippedControls: []evaluation.SkippedControl{
			{ControlID: "CTL.SKIP.001", ControlName: "Skipped", Reason: "missing resource type"},
		},
		ExemptedAssets: []asset.ExemptedAsset{
			{ID: "skip-secret", Pattern: "*", Reason: "scoped out"},
		},
		ExceptedFindings: []evaluation.ExceptedFinding{
			{ControlID: "CTL.SUP.001", AssetID: "supp-res", Reason: "approved", Expires: mustParseExpiry("2027-01-01")},
		},
	}

	enriched, err := appeval.Enrich(enricher, sanitizer, &result)
	if err != nil {
		t.Fatal(err)
	}
	data, err := w.MarshalFindings(&enriched)
	if err != nil {
		t.Fatalf("MarshalFindings() error = %v", err)
	}
	out := string(data)

	contains := []string{
		"Evaluation Results",
		"Violations",
		"Remediation Groups",
		"Skipped Controls: 1",
		"Exempted Assets: 1",
		"Excepted Findings: 1",
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
	w := &FindingWriter{Verbose: true}
	enricher := remediation.NewPlanner()
	now := time.Date(2026, 2, 1, 12, 0, 0, 0, time.UTC)

	result := evaluation.ComplianceReport{
		Run: evaluation.RunInfo{
			StaveVersion:      "test",
			Offline:           true,
			Now:               now,
			MaxUnsafeDuration: kernel.Duration(24 * time.Hour),
			Snapshots:         2,
			EvaluatedState:    "deployed",
		},
		Summary: evaluation.ComplianceSummary{
			TotalAssets:      2,
			ExposedResources: 2,
			Violations:       2,
		},
		Findings: []evaluation.Finding{
			{
				ControlID:          "CTL.S3.PUBLIC.001",
				ControlName:        "No Public Bucket Access",
				ControlDescription: "Bucket must not be public",
				AssetID:            "res-1",
				AssetType:          kernel.AssetType("storage_bucket"),
				AssetVendor:        kernel.Vendor("aws"),
			},
			{
				ControlID:          "CTL.UNKNOWN.001",
				ControlName:        "Unknown Domain Rule",
				ControlDescription: "Test unknown domain fallback",
				AssetID:            "res-2",
				AssetType:          kernel.AssetType(""),
				AssetVendor:        kernel.Vendor("aws"),
			},
		},
		Checks: []evaluation.ResourceCheck{
			{
				ControlID:   "CTL.S3.PUBLIC.001",
				AssetID:     "res-1",
				AssetType:   kernel.AssetType("storage_bucket"),
				AssetDomain: "aws_s3",
				Verdict:     evaluation.VerdictViolation,
			},
			{
				ControlID:   "CTL.UNKNOWN.001",
				AssetID:     "res-2",
				AssetType:   kernel.AssetType(""),
				AssetDomain: "",
				Verdict:     evaluation.VerdictViolation,
			},
		},
	}

	enriched, err := appeval.Enrich(enricher, nil, &result)
	if err != nil {
		t.Fatal(err)
	}
	data, err := w.MarshalFindings(&enriched)
	if err != nil {
		t.Fatalf("MarshalFindings() error = %v", err)
	}

	out := string(data)
	for _, want := range []string{"By domain:", "- aws_s3: 1", "- unknown: 1"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in output:\n%s", want, out)
		}
	}
}

func mustParseExpiry(s string) policy.ExpiryDate {
	d, err := policy.ParseExpiryDate(s)
	if err != nil {
		panic(err)
	}
	return d
}
