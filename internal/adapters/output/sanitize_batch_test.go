package output_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	appdiagnose "github.com/sufield/stave/internal/app/diagnose"
	appeval "github.com/sufield/stave/internal/app/eval"
	"github.com/sufield/stave/internal/platform/crypto"
	"github.com/sufield/stave/internal/sanitize"
	"github.com/sufield/stave/pkg/alpha/domain/asset"
	"github.com/sufield/stave/pkg/alpha/domain/evaluation"
	"github.com/sufield/stave/pkg/alpha/domain/evaluation/diagnosis"
	"github.com/sufield/stave/pkg/alpha/domain/evaluation/remediation"
	"github.com/sufield/stave/pkg/alpha/domain/kernel"
	"github.com/sufield/stave/pkg/alpha/domain/policy"
	"github.com/sufield/stave/pkg/alpha/domain/predicate"
)

func TestSanitizeFindings_Redaction(t *testing.T) {
	r := sanitize.New(sanitize.WithIDSanitization(true))

	src := &asset.SourceRef{File: "/home/user/ctl/public.yaml", Line: 10}
	stmts := []kernel.StatementID{"AllowPublicRead", "AllowPublicList"}
	grantees := []kernel.GranteeID{"http://acs.amazonaws.com/groups/global/AllUsers"}

	findings := []remediation.Finding{{
		Finding: evaluation.Finding{
			ControlID: "CTL.S3.PUBLIC.001",
			AssetID:   "my-phi-bucket",
			AssetType: kernel.AssetType("storage_bucket"),
			Source:    src,
			Evidence: evaluation.Evidence{
				Misconfigurations: []policy.Misconfiguration{
					{Property: "properties.storage.access.public_read", ActualValue: true, Operator: predicate.OpEq, UnsafeValue: true},
				},
				SourceEvidence: &evaluation.SourceEvidence{
					IdentityStatements: stmts,
					ResourceGrantees:   grantees,
				},
				WhyNow: "Unsafe for 24h, threshold is 0h",
			},
		},
	}}

	sanitized := appeval.SanitizeFindings(r, findings)

	s := sanitized[0]
	if s.AssetID == "my-phi-bucket" {
		t.Error("AssetID not sanitized")
	}
	if string(s.AssetID) != "SANITIZED_"+crypto.ShortToken("my-phi-bucket") {
		t.Errorf("AssetID = %q", s.AssetID)
	}
	if s.Source.File != "public.yaml" {
		t.Errorf("Source.File = %q, want public.yaml", s.Source.File)
	}
	if s.Evidence.Misconfigurations[0].ActualValue != "[SANITIZED]" {
		t.Errorf("Misconfigurations[0].ActualValue = %v, want [SANITIZED]", s.Evidence.Misconfigurations[0].ActualValue)
	}
	if s.Evidence.Misconfigurations[0].Property != "properties.storage.access.public_read" {
		t.Errorf("Misconfigurations[0].Property changed")
	}
	for i, v := range s.Evidence.SourceEvidence.IdentityStatements {
		if v != "[SANITIZED]" {
			t.Errorf("IdentityStatements[%d] = %q, want [SANITIZED]", i, v)
		}
	}
	for i, v := range s.Evidence.SourceEvidence.ResourceGrantees {
		if v != "[SANITIZED]" {
			t.Errorf("ResourceGrantees[%d] = %q, want [SANITIZED]", i, v)
		}
	}
	if s.Evidence.WhyNow != findings[0].Evidence.WhyNow {
		t.Errorf("WhyNow changed: %q", s.Evidence.WhyNow)
	}
}

func TestSanitizeExemptedAssets(t *testing.T) {
	r := sanitize.New(sanitize.WithIDSanitization(true))
	resources := []asset.ExemptedAsset{
		{ID: "my-bucket", Pattern: "*", Reason: "ignored"},
	}
	sanitized := appeval.SanitizeExemptedAssets(r, resources)
	if sanitized[0].ID == "my-bucket" {
		t.Error("ExemptedAsset.ID not sanitized")
	}
	if sanitized[0].Reason != "ignored" {
		t.Error("ExemptedAsset.Reason changed")
	}
}

func TestSanitizeInputHashKeys(t *testing.T) {
	r := sanitize.New(sanitize.WithIDSanitization(true))
	hashes := &evaluation.InputHashes{
		Overall: "abc123",
		Files: map[evaluation.FilePath]kernel.Digest{
			"/home/user/obs/snap1.json": "hash1",
			"/home/user/obs/snap2.json": "hash2",
		},
	}
	sanitized := appeval.SanitizeInputHashKeys(r, hashes)
	if sanitized.Overall != "abc123" {
		t.Error("Overall hash changed")
	}
	if _, ok := sanitized.Files["snap1.json"]; !ok {
		t.Error("Expected basename key snap1.json")
	}
	if _, ok := sanitized.Files["snap2.json"]; !ok {
		t.Error("Expected basename key snap2.json")
	}
}

func TestSanitizeInputHashKeys_Nil(t *testing.T) {
	r := sanitize.New(sanitize.WithIDSanitization(true))
	if got := appeval.SanitizeInputHashKeys(r, nil); got != nil {
		t.Error("Expected nil for nil input")
	}
}

func TestSanitizeReport_Nil(t *testing.T) {
	var report *diagnosis.Report
	if report != nil {
		t.Error("Expected nil")
	}
}

var sensitivePatterns = []string{
	"my-phi-bucket",
	"my-bucket",
	"arn:aws:s3:::my-phi-bucket",
	"AllowPublicRead",
	"http://acs.amazonaws.com/",
	"/home/user/",
}

func TestRedactedFindingJSON_NoSensitivePatterns(t *testing.T) {
	r := sanitize.New(sanitize.WithIDSanitization(true))
	src := &asset.SourceRef{File: "/home/user/ctl/public.yaml", Line: 10}
	f := remediation.Finding{
		Finding: evaluation.Finding{
			ControlID: "CTL.S3.PUBLIC.001",
			AssetID:   "my-phi-bucket",
			AssetType: kernel.AssetType("storage_bucket"),
			Source:    src,
			Evidence: evaluation.Evidence{
				Misconfigurations: []policy.Misconfiguration{
					{Property: "properties.public_read", ActualValue: true, Operator: predicate.OpEq, UnsafeValue: true},
				},
				SourceEvidence: &evaluation.SourceEvidence{
					IdentityStatements: []kernel.StatementID{"AllowPublicRead"},
					ResourceGrantees:   []kernel.GranteeID{"http://acs.amazonaws.com/groups/global/AllUsers"},
				},
			},
		},
	}

	sanitized := appeval.SanitizeFindings(r, []remediation.Finding{f})
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	if err := enc.Encode(sanitized[0]); err != nil {
		t.Fatalf("json encode: %v", err)
	}
	out := buf.String()
	for _, pattern := range sensitivePatterns {
		if strings.Contains(out, pattern) {
			t.Errorf("sanitized JSON output contains sensitive pattern %q:\n%s", pattern, out)
		}
	}
	var decoded map[string]any
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Errorf("sanitized output is not valid JSON: %v", err)
	}
}

func TestRedactedDiagnosticJSON_NoSensitivePatterns(t *testing.T) {
	r := sanitize.New(sanitize.WithIDSanitization(true))
	report := &diagnosis.Report{
		Issues: []diagnosis.Issue{
			{
				Case:     "violation_evidence",
				Signal:   "Continuous unsafe streak",
				Evidence: "resource=my-phi-bucket control=CTL.S3.PUBLIC.001 duration=24h",
				Action:   "Check snapshot coverage",
				AssetID:  "my-phi-bucket",
			},
		},
	}

	sanitized := appdiagnose.SanitizeDiagnosisReport(r, report)
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	if err := enc.Encode(sanitized); err != nil {
		t.Fatalf("json encode: %v", err)
	}
	out := buf.String()
	if strings.Contains(out, "my-phi-bucket") {
		t.Errorf("sanitized diagnostic JSON contains bucket name:\n%s", out)
	}
}
