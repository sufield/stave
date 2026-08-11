package asff

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/findings"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/report"
)

// TestMarshalASFF_NilAssessment covers the empty-input shortcut.
func TestMarshalASFF_NilAssessment(t *testing.T) {
	got, err := MarshalASFF(nil)
	if err != nil {
		t.Fatalf("MarshalASFF(nil) err = %v", err)
	}
	if string(got) != "[]" {
		t.Errorf("nil assessment output = %q, want []", string(got))
	}
}

// TestMarshalASFF_ChainFindings exercises the chain-mapping branch.
func TestMarshalASFF_ChainFindings(t *testing.T) {
	assessment := &report.Assessment{
		Run: evaluation.RunInfo{
			EvalTime: time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC),
		},
		ChainFindings: []findings.CompoundFinding{
			{
				ChainID:       kernel.ChainID("chain.capital-one"),
				AssetID:       asset.ID("arn:aws:ec2:us-east-1:123456789012:instance/i-abc123"),
				Severity:      policy.SeverityCritical,
				CompoundScore: 95.5,
				Narrative:     "Public bucket policy + role assumption path + logging disabled",
				Description:   "Falls back when Narrative empty",
			},
			{
				ChainID:       kernel.ChainID("chain.fallback"),
				AssetID:       asset.ID("arn:aws:ec2:us-west-2:123456789012:instance/i-def456"),
				Severity:      policy.SeverityHigh,
				CompoundScore: 70.0,
				Narrative:     "",
				Description:   "Static chain definition text",
			},
		},
	}

	data, err := MarshalASFF(assessment)
	if err != nil {
		t.Fatalf("MarshalASFF err = %v", err)
	}

	var got []ASFFinding
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal output: %v\n%s", err, string(data))
	}
	if len(got) != 2 {
		t.Fatalf("findings = %d, want 2 (chain entries only — no Findings supplied)", len(got))
	}

	byID := map[string]ASFFinding{}
	for _, f := range got {
		byID[f.ID] = f
	}

	cap1 := byID["stave/chain/chain.capital-one/arn:aws:ec2:us-east-1:123456789012:instance/i-abc123"]
	if !strings.Contains(cap1.Description, "Public bucket policy") {
		t.Errorf("capital-one Description = %q, want Narrative text", cap1.Description)
	}
	if cap1.Severity.Label != "CRITICAL" || cap1.Severity.Normalized != 90 {
		t.Errorf("capital-one severity = %+v, want CRITICAL/90", cap1.Severity)
	}
	if cap1.ProductFields["ChainId"] != "chain.capital-one" {
		t.Errorf("capital-one ChainId field = %q", cap1.ProductFields["ChainId"])
	}
	if cap1.ProductFields["CompoundScore"] != "95.5" {
		t.Errorf("capital-one CompoundScore field = %q, want 95.5", cap1.ProductFields["CompoundScore"])
	}
	if cap1.AWSAccountID != "123456789012" {
		t.Errorf("capital-one AWSAccountID = %q, want 123456789012", cap1.AWSAccountID)
	}

	fb := byID["stave/chain/chain.fallback/arn:aws:ec2:us-west-2:123456789012:instance/i-def456"]
	if fb.Description != "Static chain definition text" {
		t.Errorf("fallback Description = %q, want Description-text fallback", fb.Description)
	}
	if fb.Severity.Label != "HIGH" || fb.Severity.Normalized != 70 {
		t.Errorf("fallback severity = %+v, want HIGH/70", fb.Severity)
	}
}

func TestMarshalASFF_NoZerosInProductARN(t *testing.T) {
	assessment := &report.Assessment{
		Run: evaluation.RunInfo{
			EvalTime: time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC),
		},
		ChainFindings: []findings.CompoundFinding{
			{
				ChainID:       kernel.ChainID("chain.test"),
				AssetID:       asset.ID("arn:aws:ec2:eu-west-1:987654321098:instance/i-test"),
				Severity:      policy.SeverityMedium,
				CompoundScore: 50.0,
				Description:   "test",
			},
		},
	}

	data, err := MarshalASFF(assessment)
	if err != nil {
		t.Fatalf("MarshalASFF err = %v", err)
	}

	if strings.Contains(string(data), "000000000000") {
		t.Error("output contains 000000000000 — ProductARN should derive from findings")
	}

	var got []ASFFinding
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	want := "arn:aws:securityhub:eu-west-1:987654321098:product/987654321098/stave"
	if got[0].ProductARN != want {
		t.Errorf("ProductARN = %q, want %q", got[0].ProductARN, want)
	}
}

func TestMarshalASFF_ExplicitOptionsOverrideARN(t *testing.T) {
	assessment := &report.Assessment{
		Run: evaluation.RunInfo{
			EvalTime: time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC),
		},
		ChainFindings: []findings.CompoundFinding{
			{
				ChainID:       kernel.ChainID("chain.test"),
				AssetID:       asset.ID("arn:aws:ec2:us-east-1:111111111111:instance/i-test"),
				Severity:      policy.SeverityLow,
				CompoundScore: 10.0,
				Description:   "test",
			},
		},
	}

	data, err := MarshalASFFWithOptions(assessment, ASFFOptions{
		AccountID: "999888777666",
		Region:    "ap-southeast-1",
	})
	if err != nil {
		t.Fatalf("err = %v", err)
	}

	var got []ASFFinding
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	want := "arn:aws:securityhub:ap-southeast-1:999888777666:product/999888777666/stave"
	if got[0].ProductARN != want {
		t.Errorf("ProductARN = %q, want %q", got[0].ProductARN, want)
	}
}

func TestMarshalASFF_NoARNsReturnsError(t *testing.T) {
	assessment := &report.Assessment{
		Run: evaluation.RunInfo{
			EvalTime: time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC),
		},
		ChainFindings: []findings.CompoundFinding{
			{
				ChainID:       kernel.ChainID("chain.test"),
				AssetID:       asset.ID("not-an-arn"),
				Severity:      policy.SeverityLow,
				CompoundScore: 10.0,
				Description:   "test",
			},
		},
	}

	_, err := MarshalASFF(assessment)
	if err == nil {
		t.Fatal("expected error when no account/region derivable, got nil")
	}
	if !strings.Contains(err.Error(), "account ID") && !strings.Contains(err.Error(), "ASFF output requires") {
		t.Errorf("error = %q, want mention of account ID or ASFF requirement", err)
	}
}

func TestExtractAWSAccountID_NoARN(t *testing.T) {
	got := extractAWSAccountID("not-an-arn")
	if got != "unknown" {
		t.Errorf("extractAWSAccountID(non-ARN) = %q, want unknown", got)
	}
}
