package evidence

import (
	"testing"
	"time"
)

var testTime = time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)

func baseCfg() BuilderConfig {
	return BuilderConfig{
		SnapshotID:  "snap-001",
		EvaluatedAt: testTime,
		IsSensitive: neverSensitive,
	}
}

func TestBuild_SingleFailFinding_OneCitation(t *testing.T) {
	inputs := []FindingInput{{
		ControlID:      "CTL.S3.PUBLIC.001",
		ControlName:    "S3 bucket must not be publicly accessible",
		ResourceARN:    "arn:aws:s3:::my-bucket",
		Verdict:        "VIOLATION",
		Severity:       "critical",
		Compliance:     map[string]string{"hipaa": "164.312(a)(1)"},
		FindingMessage: "Bucket is publicly accessible",
		InvariantText:  "S3 bucket must not be publicly accessible",
	}}

	pkg := Build(baseCfg(), inputs)

	if pkg.TotalRecords() != 1 {
		t.Fatalf("TotalRecords = %d, want 1", pkg.TotalRecords())
	}
	if pkg.FailCount != 1 {
		t.Errorf("FailCount = %d, want 1", pkg.FailCount)
	}

	r := pkg.Records[0]
	if r.Verdict != VerdictFail {
		t.Errorf("Verdict = %v, want VerdictFail", r.Verdict)
	}
	if r.ControlID != "CTL.S3.PUBLIC.001" {
		t.Errorf("ControlID = %q", r.ControlID)
	}
	if r.ResourceARN != "arn:aws:s3:::my-bucket" {
		t.Errorf("ResourceARN = %q", r.ResourceARN)
	}
	if r.Severity != "critical" {
		t.Errorf("Severity = %q", r.Severity)
	}
	if len(r.Citations) != 1 {
		t.Fatalf("len(Citations) = %d, want 1", len(r.Citations))
	}
	if r.Citations[0].Framework != "hipaa" || r.Citations[0].Requirement != "164.312(a)(1)" {
		t.Errorf("Citation = %+v", r.Citations[0])
	}
	if r.ReasoningTrace.FindingMessage != "Bucket is publicly accessible" {
		t.Errorf("FindingMessage = %q", r.ReasoningTrace.FindingMessage)
	}
	if r.ReasoningTrace.InvariantEvaluated != "S3 bucket must not be publicly accessible" {
		t.Errorf("InvariantEvaluated = %q", r.ReasoningTrace.InvariantEvaluated)
	}
}

func TestBuild_SingleFinding_TwoCitations(t *testing.T) {
	inputs := []FindingInput{{
		ControlID:   "CTL.S3.ENCRYPT.001",
		ControlName: "S3 encryption required",
		ResourceARN: "arn:aws:s3:::data",
		Verdict:     "VIOLATION",
		Severity:    "high",
		Compliance: map[string]string{
			"hipaa": "164.312(a)(2)(iv)",
			"soc2":  "CC6.7",
		},
		FindingMessage: "Bucket not encrypted",
	}}

	pkg := Build(baseCfg(), inputs)

	if pkg.TotalRecords() != 2 {
		t.Fatalf("TotalRecords = %d, want 2", pkg.TotalRecords())
	}
	if pkg.FailCount != 2 {
		t.Errorf("FailCount = %d, want 2", pkg.FailCount)
	}

	// Records sorted by framework
	frameworks := make(map[string]struct{})
	for _, r := range pkg.Records {
		if len(r.Citations) != 1 {
			t.Errorf("expected 1 citation per record, got %d", len(r.Citations))
		}
		frameworks[r.Citations[0].Framework] = struct{}{}
	}
	_, okHipaa := frameworks["hipaa"]
	_, okSoc2 := frameworks["soc2"]
	if !okHipaa || !okSoc2 {
		t.Errorf("expected hipaa and soc2 frameworks, got %v", frameworks)
	}
}

func TestBuild_PassVerdict(t *testing.T) {
	inputs := []FindingInput{{
		ControlID:   "CTL.S3.ENCRYPT.001",
		ControlName: "S3 encryption required",
		ResourceARN: "arn:aws:s3:::secure",
		Verdict:     "PASS",
		Severity:    "high",
		Compliance:  map[string]string{"soc2": "CC6.7"},
	}}

	pkg := Build(baseCfg(), inputs)

	if pkg.TotalRecords() != 1 {
		t.Fatalf("TotalRecords = %d, want 1", pkg.TotalRecords())
	}
	if pkg.PassCount != 1 {
		t.Errorf("PassCount = %d, want 1", pkg.PassCount)
	}
	if pkg.Records[0].Verdict != VerdictPass {
		t.Errorf("Verdict = %v, want VerdictPass", pkg.Records[0].Verdict)
	}
}

func TestBuild_NoCompliance_NoRecords(t *testing.T) {
	inputs := []FindingInput{{
		ControlID:   "CTL.CUSTOM.001",
		ControlName: "Custom check",
		ResourceARN: "arn:aws:s3:::test",
		Verdict:     "VIOLATION",
		Compliance:  nil,
	}}

	pkg := Build(baseCfg(), inputs)

	if pkg.TotalRecords() != 0 {
		t.Errorf("TotalRecords = %d, want 0 for no compliance mapping", pkg.TotalRecords())
	}
}

func TestBuild_MixedInputs(t *testing.T) {
	inputs := []FindingInput{
		{
			ControlID:   "CTL.S3.PUBLIC.001",
			ControlName: "No public",
			ResourceARN: "arn:aws:s3:::bucket-a",
			Verdict:     "VIOLATION",
			Severity:    "critical",
			Compliance: map[string]string{
				"hipaa": "164.312(a)(1)",
				"soc2":  "CC6.1",
			},
			FindingMessage: "Public bucket",
		},
		{
			ControlID:   "CTL.S3.ENCRYPT.001",
			ControlName: "Encrypted",
			ResourceARN: "arn:aws:s3:::bucket-b",
			Verdict:     "PASS",
			Severity:    "high",
			Compliance:  map[string]string{"soc2": "CC6.7"},
		},
	}

	pkg := Build(baseCfg(), inputs)

	// 2 fail records (hipaa + soc2) + 1 pass record = 3
	if pkg.TotalRecords() != 3 {
		t.Fatalf("TotalRecords = %d, want 3", pkg.TotalRecords())
	}
	if pkg.FailCount != 2 {
		t.Errorf("FailCount = %d, want 2", pkg.FailCount)
	}
	if pkg.PassCount != 1 {
		t.Errorf("PassCount = %d, want 1", pkg.PassCount)
	}
}

func TestBuild_ObservationFieldsPopulated(t *testing.T) {
	inputs := []FindingInput{{
		ControlID:   "CTL.S3.PUBLIC.001",
		ControlName: "No public",
		ResourceARN: "arn:aws:s3:::bucket",
		Verdict:     "VIOLATION",
		Severity:    "critical",
		Compliance:  map[string]string{"hipaa": "164.312(a)(1)"},
		ObservationFields: []string{
			"public_access_block.block_public_acls",
			"public_access_block.block_public_policy",
		},
		AssetProperties: map[string]any{
			"public_access_block": map[string]any{
				"block_public_acls":   false,
				"block_public_policy": false,
			},
		},
	}}

	pkg := Build(baseCfg(), inputs)

	if pkg.TotalRecords() != 1 {
		t.Fatalf("TotalRecords = %d, want 1", pkg.TotalRecords())
	}
	obs := pkg.Records[0].ReasoningTrace.ObservationProperties
	if len(obs) != 2 {
		t.Fatalf("len(ObservationProperties) = %d, want 2", len(obs))
	}
}

func TestBuild_NoObservationFields_FallbackToMessage(t *testing.T) {
	inputs := []FindingInput{{
		ControlID:      "CTL.S3.PUBLIC.001",
		ControlName:    "No public",
		ResourceARN:    "arn:aws:s3:::bucket",
		Verdict:        "VIOLATION",
		Severity:       "critical",
		Compliance:     map[string]string{"hipaa": "164.312(a)(1)"},
		FindingMessage: "Bucket publicly accessible for 48h",
	}}

	pkg := Build(baseCfg(), inputs)

	r := pkg.Records[0]
	if r.ReasoningTrace.FindingMessage != "Bucket publicly accessible for 48h" {
		t.Errorf("FindingMessage = %q", r.ReasoningTrace.FindingMessage)
	}
	if len(r.ReasoningTrace.ObservationProperties) != 0 {
		t.Errorf("expected no observation properties without fields, got %d",
			len(r.ReasoningTrace.ObservationProperties))
	}
}

func TestBuild_SensitiveFieldRedacted(t *testing.T) {
	cfg := baseCfg()
	cfg.IsSensitive = sensitiveTokens

	inputs := []FindingInput{{
		ControlID:         "CTL.LAMBDA.ENV.001",
		ControlName:       "No secrets in env",
		ResourceARN:       "arn:aws:lambda:us-east-1:123:function:f",
		Verdict:           "VIOLATION",
		Severity:          "critical",
		Compliance:        map[string]string{"hipaa": "164.312(a)(2)(iv)"},
		ObservationFields: []string{"db_password", "region"},
		AssetProperties:   map[string]any{"db_password": "hunter2", "region": "us-east-1"},
	}}

	pkg := Build(cfg, inputs)

	obs := pkg.Records[0].ReasoningTrace.ObservationProperties
	if len(obs) != 2 {
		t.Fatalf("len = %d, want 2", len(obs))
	}
	for _, o := range obs {
		if o.Field == "db_password" && o.Value != RedactedValue {
			t.Errorf("expected redacted db_password, got %q", o.Value)
		}
	}
}

func TestBuild_EmptyInput(t *testing.T) {
	pkg := Build(baseCfg(), nil)

	if pkg.TotalRecords() != 0 {
		t.Errorf("TotalRecords = %d, want 0", pkg.TotalRecords())
	}
	if pkg.SnapshotID != "snap-001" {
		t.Errorf("SnapshotID = %q", pkg.SnapshotID)
	}
}

func TestBuild_DeterministicOrdering(t *testing.T) {
	inputs := []FindingInput{
		{
			ControlID: "CTL.Z.001", ControlName: "Z", ResourceARN: "arn:z",
			Verdict: "VIOLATION", Compliance: map[string]string{"soc2": "CC1"},
		},
		{
			ControlID: "CTL.A.001", ControlName: "A", ResourceARN: "arn:a",
			Verdict: "VIOLATION", Compliance: map[string]string{"soc2": "CC2", "hipaa": "164"},
		},
	}

	pkg := Build(baseCfg(), inputs)

	if pkg.TotalRecords() != 3 {
		t.Fatalf("TotalRecords = %d, want 3", pkg.TotalRecords())
	}

	// Expect sorted: CTL.A.001 records first (2), then CTL.Z.001 (1)
	if pkg.Records[0].ControlID != "CTL.A.001" {
		t.Errorf("Records[0].ControlID = %q, want CTL.A.001", pkg.Records[0].ControlID)
	}
	if pkg.Records[2].ControlID != "CTL.Z.001" {
		t.Errorf("Records[2].ControlID = %q, want CTL.Z.001", pkg.Records[2].ControlID)
	}
}
