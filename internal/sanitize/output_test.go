package sanitize_test

import (
	"strings"
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/predicate"

	"github.com/sufield/stave/internal/core/asset"

	outjson "github.com/sufield/stave/internal/adapters/output/json"
	outtext "github.com/sufield/stave/internal/adapters/output/text"
	appeval "github.com/sufield/stave/internal/app/eval"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/sanitize"
)

// sensitiveValues are strings that must never appear in share-safe output.
var sensitiveValues = []string{
	"my-phi-bucket",
	"arn:aws:s3:::my-phi-bucket",
	"AllowPublicRead",
	"http://acs.amazonaws.com/",
	"/home/user/ctl/public.yaml",
	"/home/user/obs/snap1.json",
}

func makeTestResult() evaluation.Audit {
	t1 := time.Date(2026, 1, 14, 0, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)
	return evaluation.Audit{
		Run: evaluation.RunInfo{
			Now:               t2,
			Offline:           true,
			MaxUnsafeDuration: 0,
			Snapshots:         2,
			StaveVersion:      "test",
			InputHashes: &evaluation.InputHashes{
				Overall: "abc123",
				Files: map[evaluation.FilePath]kernel.Digest{
					"/home/user/obs/snap1.json": "hash1",
				},
			},
		},
		Summary: evaluation.Summary{
			AssetsEvaluated: 1,
			Violations:      1,
			AttackSurface:   1,
		},
		Findings: []evaluation.Finding{
			{
				ControlID:   "CTL.S3.PUBLIC.001",
				ControlName: "S3 Public Read",
				AssetID:     "my-phi-bucket",
				AssetType:   kernel.AssetType("storage_bucket"),
				AssetVendor: kernel.Vendor("aws"),
				Source: &asset.SourceRef{
					File: "/home/user/ctl/public.yaml",
					Line: 10,
				},
				Evidence: evaluation.Evidence{
					FirstUnsafeAt:       t1,
					LastSeenUnsafeAt:    t2,
					UnsafeDurationHours: 24,
					ThresholdHours:      0,
					Misconfigurations: []policy.Misconfiguration{
						{Property: predicate.NewFieldPath("properties.public_read"), ActualValue: true, Operator: predicate.OpEq, UnsafeValue: true},
					},
					SourceEvidence: &evaluation.SourceEvidence{
						IdentityStatements: []kernel.StatementID{"AllowPublicRead"},
						ResourceGrantees:   []kernel.GranteeID{"http://acs.amazonaws.com/groups/global/AllUsers"},
					},
					WhyNow: "Unsafe for 24h, threshold is 0h",
				},
			},
		},
		ExemptedAssets: []asset.ExemptedAsset{
			{ID: "my-phi-bucket", Pattern: "*", Reason: "test"},
		},
	}
}

func assertNoSensitive(t *testing.T, label, output string) {
	t.Helper()
	for _, v := range sensitiveValues {
		if strings.Contains(output, v) {
			t.Errorf("[%s] sanitized output contains sensitive value %q", label, v)
		}
	}
}

// --- JSON FindingWriter tests ---

func TestJSONWriter_WriteFindings_NoRedact(t *testing.T) {
	w := outjson.NewFindingWriter(true)
	enricher := remediation.NewPlanner()
	enriched, err := appeval.Enrich(enricher, nil, makeTestResult())
	if err != nil {
		t.Fatal(err)
	}
	data, err := w.MarshalFindings(enriched)
	if err != nil {
		t.Fatal(err)
	}
	out := string(data)
	// Without sanitization, sensitive values should appear
	if !strings.Contains(out, "my-phi-bucket") {
		t.Error("expected bucket name in unredacted output")
	}
}

func TestJSONWriter_WriteFindings_WithRedact(t *testing.T) {
	r := sanitize.New(sanitize.WithIDSanitization(true))
	w := outjson.NewFindingWriter(true)
	enricher := remediation.NewPlanner()
	enriched, err := appeval.Enrich(enricher, r, makeTestResult())
	if err != nil {
		t.Fatal(err)
	}
	data, err := w.MarshalFindings(enriched)
	if err != nil {
		t.Fatal(err)
	}
	out := string(data)
	assertNoSensitive(t, "JSON WriteFindings --sanitize", out)
	// Should contain SANITIZED tokens
	if !strings.Contains(out, "SANITIZED_") {
		t.Error("expected SANITIZED_ tokens in output")
	}
	// Structure should remain valid JSON
	if !strings.Contains(out, `"schema_version"`) {
		t.Error("JSON structure missing schema_version")
	}
}

// --- Text FindingWriter tests ---

func TestTextWriter_WriteFindings_WithRedact(t *testing.T) {
	r := sanitize.New(sanitize.WithIDSanitization(true))
	w := &outtext.FindingWriter{}
	enricher := remediation.NewPlanner()
	enriched, err := appeval.Enrich(enricher, r, makeTestResult())
	if err != nil {
		t.Fatal(err)
	}
	data, err := w.MarshalFindings(enriched)
	if err != nil {
		t.Fatal(err)
	}
	out := string(data)
	assertNoSensitive(t, "Text WriteFindings --sanitize", out)
	if !strings.Contains(out, "SANITIZED_") {
		t.Error("expected SANITIZED_ tokens in output")
	}
}
