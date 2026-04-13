package remediation

import (
	"strings"
	"testing"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/kernel"
)

func makeTestFinding(controlID, assetID string) Finding {
	return Finding{
		Finding: evaluation.Finding{
			ControlID: kernel.ControlID(controlID),
			AssetID:   asset.ID(assetID),
		},
	}
}

func TestFindingKey(t *testing.T) {
	f := makeTestFinding("CTL.S3.001", "my-bucket")
	got := FindingKey(f)
	want := "CTL.S3.001@my-bucket"
	if got != want {
		t.Errorf("FindingKey() = %q, want %q", got, want)
	}
}

func TestFindingKey_EmptyFields(t *testing.T) {
	f := makeTestFinding("", "")
	got := FindingKey(f)
	if got != "@" {
		t.Errorf("FindingKey with empty fields = %q, want @", got)
	}
}

func TestSelectFinding_Found(t *testing.T) {
	findings := []Finding{
		makeTestFinding("CTL.S3.001", "bucket-a"),
		makeTestFinding("CTL.IAM.001", "role-x"),
		makeTestFinding("CTL.S3.001", "bucket-b"),
	}
	got, err := SelectFinding(findings, "CTL.IAM.001@role-x")
	if err != nil {
		t.Fatalf("SelectFinding error: %v", err)
	}
	if string(got.ControlID) != "CTL.IAM.001" {
		t.Errorf("ControlID = %q, want CTL.IAM.001", got.ControlID)
	}
	if string(got.AssetID) != "role-x" {
		t.Errorf("AssetID = %q, want role-x", got.AssetID)
	}
}

func TestSelectFinding_FirstMatch(t *testing.T) {
	findings := []Finding{
		makeTestFinding("CTL.S3.001", "bucket-a"),
		makeTestFinding("CTL.S3.001", "bucket-b"),
	}
	got, err := SelectFinding(findings, "CTL.S3.001@bucket-a")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(got.AssetID) != "bucket-a" {
		t.Errorf("AssetID = %q, want bucket-a", got.AssetID)
	}
}

func TestSelectFinding_NotFound(t *testing.T) {
	findings := []Finding{
		makeTestFinding("CTL.S3.001", "bucket-a"),
		makeTestFinding("CTL.IAM.001", "role-x"),
	}
	_, err := SelectFinding(findings, "CTL.NOPE.001@unknown")
	if err == nil {
		t.Fatal("expected error for missing finding")
	}
	if !strings.Contains(err.Error(), "CTL.NOPE.001@unknown") {
		t.Errorf("error should mention the needle: %v", err)
	}
	// Error message should list available findings.
	if !strings.Contains(err.Error(), "CTL.S3.001@bucket-a") {
		t.Errorf("error should list available findings: %v", err)
	}
}

func TestSelectFinding_EmptyList(t *testing.T) {
	_, err := SelectFinding(nil, "CTL.S3.001@bucket-a")
	if err == nil {
		t.Fatal("expected error for empty findings list")
	}
}

func TestSelectFinding_AvailableListSorted(t *testing.T) {
	findings := []Finding{
		makeTestFinding("CTL.Z.001", "zz"),
		makeTestFinding("CTL.A.001", "aa"),
	}
	_, err := SelectFinding(findings, "CTL.NOPE@nope")
	if err == nil {
		t.Fatal("expected error")
	}
	msg := err.Error()
	// Available findings should be sorted: CTL.A before CTL.Z.
	aIdx := strings.Index(msg, "CTL.A.001@aa")
	zIdx := strings.Index(msg, "CTL.Z.001@zz")
	if aIdx < 0 || zIdx < 0 {
		t.Fatalf("error message missing expected findings: %v", msg)
	}
	if aIdx > zIdx {
		t.Error("available findings should be listed in sorted order")
	}
}
