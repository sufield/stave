package sanitize_test

import (
	"strings"
	"testing"
	"time"

	"github.com/sufield/stave/internal/domain/kernel"

	"github.com/sufield/stave/internal/domain/asset"

	output "github.com/sufield/stave/internal/adapters/output"
	outjson "github.com/sufield/stave/internal/adapters/output/json"
	outtext "github.com/sufield/stave/internal/adapters/output/text"
	"github.com/sufield/stave/internal/domain/evaluation"
	"github.com/sufield/stave/internal/domain/evaluation/remediation"
	"github.com/sufield/stave/internal/domain/policy"
	"github.com/sufield/stave/internal/platform/crypto"
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

func makeTestResult() evaluation.Result {
	t1 := time.Date(2026, 1, 14, 0, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)
	return evaluation.Result{
		Run: evaluation.RunInfo{
			Now:         t2,
			Offline:     true,
			MaxUnsafe:   0,
			Snapshots:   2,
			ToolVersion: "test",
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
						{Property: "properties.public_read", ActualValue: true, Operator: "eq", UnsafeValue: true},
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
	enricher := remediation.NewMapper(crypto.NewHasher())
	enriched := output.Enrich(enricher, nil, makeTestResult())
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
	r := sanitize.New()
	w := outjson.NewFindingWriter(true)
	enricher := remediation.NewMapper(crypto.NewHasher())
	enriched := output.Enrich(enricher, r, makeTestResult())
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
	r := sanitize.New()
	w := outtext.NewFindingWriter()
	enricher := remediation.NewMapper(crypto.NewHasher())
	enriched := output.Enrich(enricher, r, makeTestResult())
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
