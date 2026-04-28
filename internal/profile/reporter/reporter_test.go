package reporter

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sufield/stave/internal/core/compliance"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/profile"
	"github.com/sufield/stave/internal/testutil"
)

func fixtureMeta() ReportMeta {
	return ReportMeta{
		BucketName: "phi-data-bucket",
		AccountID:  "123456789012",
		Timestamp:  "2026-01-15T00:00:00Z",
	}
}

func fixtureReport() profile.Report {
	return profile.Report{
		ProfileID:   "hipaa",
		ProfileName: "HIPAA Security Rule",
		Pass:        false,
		Results: []profile.Result{
			{
				Outcome: compliance.Outcome{
					Pass:           false,
					ControlID:      "CONTROLS.001.STRICT",
					Severity:       policy.SeverityCritical,
					Finding:        "Bucket phi-data-bucket: encryption algorithm is \"AES256\", not aws:kms — SSE-KMS with CMK is required for HIPAA",
					Remediation:    "Change the default encryption to SSE-KMS (aws:kms) with a customer-managed CMK.",
					ComplianceRefs: map[string]string{"hipaa": "§164.312(a)(2)(iv)"},
				},
				ComplianceRef: "§164.312(a)(2)(iv)",
				Rationale:     "CMK required for key revocation during breach response",
			},
			{
				Outcome: compliance.Outcome{
					Pass:           false,
					ControlID:      "AUDIT.001",
					Severity:       policy.SeverityCritical,
					Finding:        "Bucket phi-data-bucket: server access logging is not enabled. Logs cannot be obtained retroactively from AWS — if a security incident occurs without logging enabled, no forensic evidence exists",
					Remediation:    "Enable server access logging on the bucket. Set a target bucket in a separate account or with write-only permissions to prevent log tampering.",
					ComplianceRefs: map[string]string{"hipaa": "§164.312(b)"},
				},
				ComplianceRef: "§164.312(b)",
				Rationale:     "All PHI access must be logged — logs cannot be obtained retroactively",
			},
			{
				Outcome: compliance.Outcome{
					Pass:           false,
					ControlID:      "ACCESS.002",
					Severity:       policy.SeverityHigh,
					Finding:        "Bucket phi-data-bucket: policy statement \"(unnamed)\" grants Allow with wildcard action s3:*",
					Remediation:    "Replace s3:* with the minimum required actions. For sync patterns use: s3:GetObject, s3:PutObject, s3:DeleteObject, s3:ListBucket, s3:GetBucketLocation",
					ComplianceRefs: map[string]string{"hipaa": "§164.312(a)(2)(i)"},
				},
				ComplianceRef: "§164.312(a)(2)(i)",
				Rationale:     "Least privilege — no wildcard actions",
			},
			{
				Outcome: compliance.Outcome{
					Pass:      true,
					ControlID: "CONTROLS.002",
					Severity:  policy.SeverityMedium,
				},
				ComplianceRef: "§164.312(c)(1)",
				Rationale:     "Integrity — versioning protects against accidental deletion",
			},
		},
		Counts: map[policy.Severity]int{
			policy.SeverityCritical: 2,
			policy.SeverityHigh:     1,
			policy.SeverityMedium:   1,
		},
		FailCounts: map[policy.Severity]int{
			policy.SeverityCritical: 2,
			policy.SeverityHigh:     1,
		},
	}
}

func TestTextReporter_Golden(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	err := TextReporter{}.Write(&buf, fixtureReport(), fixtureMeta())
	if err != nil {
		t.Fatalf("write: %v", err)
	}

	got := buf.String()
	golden := filepath.Join("testdata", "reports", "hipaa_golden.txt")
	testutil.AssertGoldenString(t, golden, got)
}

func TestJSONReporter(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	err := JSONReporter{}.Write(&buf, fixtureReport(), fixtureMeta())
	if err != nil {
		t.Fatalf("write: %v", err)
	}

	// Verify it's valid JSON.
	var parsed map[string]any
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	// Check key fields are present.
	meta, ok := parsed["meta"].(map[string]any)
	if !ok {
		t.Fatal("missing meta")
	}
	if meta["bucket_name"] != "phi-data-bucket" {
		t.Errorf("bucket_name: got %v", meta["bucket_name"])
	}

	report, ok := parsed["report"].(map[string]any)
	if !ok {
		t.Fatal("missing report")
	}
	if report["pass"] != false {
		t.Error("expected pass=false")
	}

	disc, _ := parsed["disclaimer"].(string)
	if !strings.Contains(disc, "BAA") {
		t.Error("disclaimer should mention BAA")
	}
}

func TestTextReporter_Disclaimer(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	_ = TextReporter{}.Write(&buf, fixtureReport(), fixtureMeta())
	if !strings.Contains(buf.String(), "BAA with AWS") {
		t.Error("text output should contain BAA disclaimer")
	}
}
