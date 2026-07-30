package stave

import (
	"testing"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
)

func makeControl(id string, assetTypes ...string) policy.ControlDefinition {
	ctl := policy.ControlDefinition{ID: kernel.ControlID(id)}
	for _, at := range assetTypes {
		ctl.ApplicableAssetTypes = append(ctl.ApplicableAssetTypes, kernel.AssetType(at))
	}
	return ctl
}

func makeChain(id string, controlIDs ...string) policy.ChainDefinition {
	ids := make([]kernel.ControlID, len(controlIDs))
	for i, c := range controlIDs {
		ids[i] = kernel.ControlID(c)
	}
	return policy.ChainDefinition{
		ID:         kernel.ChainID(id),
		ControlIDs: ids,
	}
}

func TestBuildSiloReport_Basic(t *testing.T) {
	controls := []policy.ControlDefinition{
		makeControl("CTL.S3.PUBLIC.001"),
		makeControl("CTL.S3.ENCRYPT.001"),
		makeControl("CTL.S3.LOGGING.001"),
		makeControl("CTL.IAM.POLICY.001"),
		makeControl("CTL.IAM.ROLE.001"),
		makeControl("CTL.EC2.PUBLIC.001"),
	}

	chains := []policy.ChainDefinition{
		makeChain("cross_s3_iam", "CTL.S3.PUBLIC.001", "CTL.IAM.POLICY.001"),
		makeChain("s3_only", "CTL.S3.PUBLIC.001", "CTL.S3.ENCRYPT.001"),
	}

	report := buildSiloReport(controls, chains, 1)

	if report.TotalControls != 6 {
		t.Fatalf("TotalControls = %d, want 6", report.TotalControls)
	}
	if report.TotalChains != 2 {
		t.Fatalf("TotalChains = %d, want 2", report.TotalChains)
	}

	// EC2 has 1 control and 0 chains → silo
	if report.SiloCount != 1 {
		t.Fatalf("SiloCount = %d, want 1", report.SiloCount)
	}
	if report.Silos[0].Service != "ec2" {
		t.Fatalf("Silos[0].Service = %q, want %q", report.Silos[0].Service, "ec2")
	}
	if report.Silos[0].Question == "" {
		t.Fatal("silo should have a structural question")
	}

	// S3 has 2 chains (cross_s3_iam + s3_only), connected to IAM
	var s3 *ServiceConnectivity
	for i := range report.MostConnected {
		if report.MostConnected[i].Service == "s3" {
			s3 = &report.MostConnected[i]
			break
		}
	}
	if s3 == nil {
		t.Fatal("s3 should be in most_connected")
	}
	if s3.Chains != 2 {
		t.Fatalf("s3 chains = %d, want 2", s3.Chains)
	}

	// IAM has 1 chain (cross_s3_iam), connected to S3
	var iam *ServiceConnectivity
	for i := range report.MostConnected {
		if report.MostConnected[i].Service == "iam" {
			iam = &report.MostConnected[i]
			break
		}
	}
	if iam == nil {
		t.Fatal("iam should be in most_connected")
	}
	if iam.Chains != 1 {
		t.Fatalf("iam chains = %d, want 1", iam.Chains)
	}
}

func TestBuildSiloReport_MinControls(t *testing.T) {
	controls := []policy.ControlDefinition{
		makeControl("CTL.S3.PUBLIC.001"),
		makeControl("CTL.S3.ENCRYPT.001"),
		makeControl("CTL.EC2.PUBLIC.001"),
	}

	report := buildSiloReport(controls, nil, 2)

	// S3 has 2 controls, EC2 has 1. With minControls=2, only S3 qualifies as silo.
	if report.SiloCount != 1 {
		t.Fatalf("SiloCount = %d, want 1", report.SiloCount)
	}
	if report.Silos[0].Service != "s3" {
		t.Fatalf("Silos[0].Service = %q, want %q", report.Silos[0].Service, "s3")
	}
}

func TestBuildSiloReport_NoSilos(t *testing.T) {
	controls := []policy.ControlDefinition{
		makeControl("CTL.S3.PUBLIC.001"),
		makeControl("CTL.IAM.POLICY.001"),
	}
	chains := []policy.ChainDefinition{
		makeChain("chain1", "CTL.S3.PUBLIC.001", "CTL.IAM.POLICY.001"),
	}

	report := buildSiloReport(controls, chains, 1)

	if report.SiloCount != 0 {
		t.Fatalf("SiloCount = %d, want 0", report.SiloCount)
	}
}

func TestBuildSiloReport_UnevaluatedAssetTypes(t *testing.T) {
	report := buildSiloReport(nil, nil, 1)

	if report.SchemaAssetTypeCount == 0 {
		t.Fatal("SchemaAssetTypeCount should be >0 from contract schema")
	}
	if report.UnevaluatedCount != report.SchemaAssetTypeCount {
		t.Fatalf("with zero controls, all %d schema types should be unevaluated, got %d",
			report.SchemaAssetTypeCount, report.UnevaluatedCount)
	}
	if report.EvaluatedAssetTypeCount != 0 {
		t.Fatalf("EvaluatedAssetTypeCount = %d, want 0", report.EvaluatedAssetTypeCount)
	}
}

func TestIndexControlsByAssetType(t *testing.T) {
	controls := []policy.ControlDefinition{
		makeControl("CTL.S3.PUBLIC.001", "aws_s3_bucket"),
		makeControl("CTL.S3.ENCRYPT.001", "aws_s3_bucket"),
		makeControl("CTL.IAM.POLICY.001", "aws_iam_policy", "aws_iam_role"),
	}

	m := indexControlsByAssetType(controls)

	if m["aws_s3_bucket"] != 2 {
		t.Fatalf("aws_s3_bucket count = %d, want 2", m["aws_s3_bucket"])
	}
	if m["aws_iam_policy"] != 1 {
		t.Fatalf("aws_iam_policy count = %d, want 1", m["aws_iam_policy"])
	}
	if m["aws_iam_role"] != 1 {
		t.Fatalf("aws_iam_role count = %d, want 1", m["aws_iam_role"])
	}
}

func TestIndexControlsByService(t *testing.T) {
	controls := []policy.ControlDefinition{
		makeControl("CTL.S3.PUBLIC.001"),
		makeControl("CTL.S3.ENCRYPT.001"),
		makeControl("CTL.IAM.POLICY.001"),
	}

	m := indexControlsByService(controls)

	if m["s3"] != 2 {
		t.Fatalf("s3 count = %d, want 2", m["s3"])
	}
	if m["iam"] != 1 {
		t.Fatalf("iam count = %d, want 1", m["iam"])
	}
}

func TestChainServices(t *testing.T) {
	ids := []kernel.ControlID{
		"CTL.S3.PUBLIC.001",
		"CTL.IAM.POLICY.001",
		"CTL.S3.ENCRYPT.001",
	}

	svcs := chainServices(ids)

	if !svcs["s3"] {
		t.Fatal("expected s3 in chain services")
	}
	if !svcs["iam"] {
		t.Fatal("expected iam in chain services")
	}
	if len(svcs) != 2 {
		t.Fatalf("expected 2 services, got %d", len(svcs))
	}
}
