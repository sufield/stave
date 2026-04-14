package compliance

import (
	"bytes"
	"strings"
	"testing"
)

func testExport() *EvidenceExport {
	return &EvidenceExport{
		ExportedAt:   testTime,
		StaveVersion: "dev",
		SnapshotID:   "snap-001",
		Profile:      ProfileSummary{ID: "hipaa", Name: "HIPAA Security Rule", Version: "2013"},
		Score: ScoreExport{
			RequirementsTotal:   3,
			RequirementsMet:     1,
			RequirementsNotMet:  1,
			RequirementsNotEval: 1,
		},
		Requirements: []RequirementExport{
			{
				ID: "R1", Description: "Access control", Status: "met",
				Controls: []ControlSummary{{ID: "CTL.A", PassCount: 2}},
			},
			{
				ID: "R2", Description: "Encryption", Status: "not_met",
				Controls: []ControlSummary{{ID: "CTL.B", FailCount: 1}},
				Gaps: []GapExport{{
					ControlID: "CTL.B", ResourceARN: "arn:aws:s3:::bucket",
					Severity: "critical", Message: "Bucket not encrypted",
				}},
			},
			{
				ID: "R3", Description: "Audit logging", Status: "not_evaluated",
				Controls: []ControlSummary{},
			},
		},
		Evidence: []EvidenceRecordExport{{
			ControlID: "CTL.B", ResourceARN: "arn:aws:s3:::bucket",
			Verdict: "fail", Severity: "critical",
			ReasoningTrace: TraceExport{
				InvariantEvaluated: "S3 buckets must be encrypted",
				FindingMessage:     "Bucket not encrypted",
				Observations: []ObservationExp{
					{Field: "storage.encryption.enabled", Value: "false"},
				},
			},
		}},
	}
}

func TestRenderTable_ContainsHeader(t *testing.T) {
	var buf bytes.Buffer
	if err := renderTable(&buf, testExport(), false); err != nil {
		t.Fatal(err)
	}
	out := buf.String()

	if !strings.Contains(out, "HIPAA SECURITY RULE") {
		t.Error("missing profile name in header")
	}
	if !strings.Contains(out, "snap-001") {
		t.Error("missing snapshot ID")
	}
	if !strings.Contains(out, "Stave: dev") {
		t.Error("missing stave version")
	}
}

func TestRenderTable_ScoreBar(t *testing.T) {
	var buf bytes.Buffer
	if err := renderTable(&buf, testExport(), false); err != nil {
		t.Fatal(err)
	}
	out := buf.String()

	if !strings.Contains(out, "OVERALL POSTURE") {
		t.Error("missing overall posture section")
	}
	if !strings.Contains(out, "1/3") {
		t.Error("missing score counts")
	}
}

func TestRenderTable_RequirementsSection(t *testing.T) {
	var buf bytes.Buffer
	if err := renderTable(&buf, testExport(), false); err != nil {
		t.Fatal(err)
	}
	out := buf.String()

	if !strings.Contains(out, "REQUIREMENTS") {
		t.Error("missing requirements section")
	}
	if !strings.Contains(out, "SATISFIED") {
		t.Error("missing SATISFIED status")
	}
	if !strings.Contains(out, "NOT MET") {
		t.Error("missing NOT MET status")
	}
	if !strings.Contains(out, "NOT EVAL") {
		t.Error("missing NOT EVAL status")
	}
}

func TestRenderTable_GapsSection(t *testing.T) {
	var buf bytes.Buffer
	if err := renderTable(&buf, testExport(), false); err != nil {
		t.Fatal(err)
	}
	out := buf.String()

	if !strings.Contains(out, "GAPS") {
		t.Error("missing gaps section")
	}
	if !strings.Contains(out, "CTL.B") {
		t.Error("missing gap control ID")
	}
	if !strings.Contains(out, "Bucket not encrypted") {
		t.Error("missing gap message")
	}
}

func TestRenderTable_VerboseAddsTrace(t *testing.T) {
	var buf bytes.Buffer
	if err := renderTable(&buf, testExport(), true); err != nil {
		t.Fatal(err)
	}
	out := buf.String()

	if !strings.Contains(out, "Reasoning trace:") {
		t.Error("verbose mode should include reasoning trace")
	}
	if !strings.Contains(out, "S3 buckets must be encrypted") {
		t.Error("verbose mode should include invariant text")
	}
	if !strings.Contains(out, "storage.encryption.enabled = false") {
		t.Error("verbose mode should include observations")
	}
}

func TestRenderTable_NoVerboseNoTrace(t *testing.T) {
	var buf bytes.Buffer
	if err := renderTable(&buf, testExport(), false); err != nil {
		t.Fatal(err)
	}
	out := buf.String()

	if strings.Contains(out, "Reasoning trace:") {
		t.Error("non-verbose mode should not include reasoning trace")
	}
}
